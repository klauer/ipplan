'''ipplan configuration scraper

No ipplanapi? No problem.
(but if you have it, use it -- seriously... It'll be a lot cleaner)

Requires: docopt, lxml, yaml, requests

Usage:
    ipplan.py download URL (BASE_INDEX ...) [--path=PATH] [--user=USER] [--pass=PASS] [--block=BLOCK ...] [-v]
    ipplan.py parse PATH (BASE_INDEX ...) [-v] [--file=FILE]
    ipplan.py dhcp PATH (BASE_INDEX ...) [-v] [--all] [--file=FILE] [--indent=INDENT] [--sort-ip]

Options:
    BASE_INDEX          The `base_index` from the URL
    --path=PATH         Temporary download path [Default: info].
    --block=BLOCK       Download specific block.
    --user=USER         Username (authentication not used if unspecified)
    --pass=PASSWORD     IPPlan password (prompted for if not set)
    --file=FILE         File to save to
    --indent=INDENT     Spaces to indent the output [Default: 0].
    --sort-ip           Sort by IP address instead of by hostname
    -v                  Verbose mode

Example:
    # Clean slate:
    > rm -rf info

    # Download relevant html files to info/ for base index 49 (found in ipplan URL)
    > python ipplan.py download https://controlsweb01.nsls2.bnl.gov/ipplan/user/ 49 --user=klauer --path=info -v

    # Generate a dhcpd configuration file from the saved files:
    > python ipplan.py dhcp info 49

    # Run an IPython session and play around with the parsed data
    > ipython -i ipplan.py -- dhcp info 49 -v
'''

from __future__ import print_function

import os
import sys
import getpass
import logging
import socket
import struct

from docopt import docopt
from collections import OrderedDict
import requests
import operator
import yaml

import lxml
import lxml.html


logger = logging.getLogger('ipplan')


class DownloadError(ValueError):
    pass

failed_messages = ['page was bookmarked and contains invalid information',
                   ]


def get_user_url(url):
    url = url.split('/')
    try:
        user_url = url[:url.index('user') + 1]
        return '/'.join(user_url)
    except IndexError:
        return url


def get_subnet_page(url, index, block):
    user_url = get_user_url(url)
    kw = locals()
    return '{user_url}/displaysubnet.php?baseindex={index}&block={block}'.format(**kw)


def get_long_ip(ip):
    packed = socket.inet_aton(ip)
    return struct.unpack("!L", packed)[0]


def get_ip_page(url, index, block, ip):
    user_url = get_user_url(url)
    ip = get_long_ip(ip)
    kw = locals()
    return '{user_url}/modifyipform.php?baseindex={index}&block={block}&ip={ip}'.format(**kw)


def get_block_html_fn(base_path, index, block):
    blocks_html_path = os.path.join(base_path, 'html', 'blocks')

    try:
        os.makedirs(blocks_html_path)
    except OSError:
        pass

    return os.path.join(blocks_html_path, '%.3d_%.3d.htm' % (index, block))


def get_ip_base_path(base_path, index):
    return os.path.join(base_path, 'html', 'ips', str(index))


def get_ip_html_fn(base_path, index, block, ip):
    ip_html_path = get_ip_base_path(base_path, index)

    try:
        os.makedirs(ip_html_path)
    except OSError:
        pass

    return os.path.join(ip_html_path, '%s.htm' % (ip, ))


def download(url, username=None, password=None):
    logger.debug('URL: %s' % url)

    auth = None

    if username is not None and password is not None:
        auth = (username, password)

    r = requests.get(url, auth=auth)
    logger.debug('Response status code: %s' % r.status_code)
    if r.status_code != 200:
        raise DownloadError('Bad URL or block/index?')

    for msg in failed_messages:
        if msg in r.text:
            raise DownloadError('Bad block/index number (failed text found: %s)' % msg)

    return r


def download_block(url, index, block, base_path, username=None, password=None):
    url = get_subnet_page(url, index, block)

    r = download(url, username=username, password=password)
    text = r.text

    block_fn = get_block_html_fn(base_path, index, block)
    logger.debug('Saving index %s block %s to %s' % (index, block, block_fn))

    with open(block_fn, 'wt') as f:
        print(text, file=f)

    return block_fn


def download_blocks(url, indices=None, blocks=None, username=None, password=None,
                    base_path='info'):

    if username is not None and password is None:
        logger.debug('Querying for password')
        password = getpass.getpass('Password for ipplan, user=%s?' % username)

    fns = []
    for index in indices:
        if blocks is None or len(blocks) == 0:
            block = 0
            while True:
                try:
                    fn = download_block(url, index, block, base_path,
                                        username=username, password=password)
                except DownloadError as ex:
                    if block == 0:
                        logger.error('Failed to download block %d of index %s' % (block, index),
                                     exc_info=ex)
                        print('Failed to download block %d of index %s' % (block, index), file=sys.stderr)
                        print('%s' % (ex, ), file=sys.stderr)
                    else:
                        logger.debug('Final block was %d' % (block - 1))

                    break
                else:
                    fns.append((index, block, fn))

                block += 1

        else:
            for block in blocks:
                fn = download_block(url, index, block, base_path,
                                    username=username, password=password)
                fns.append((index, block, fn))

    data = OrderedDict()

    for index, block, fn in fns:
        rows = parse_block(fn)
        # header, ips = rows[0], rows[1:]
        ips = rows[1:]

        if index not in data:
            data[index] = OrderedDict()

        for ip_info in ips:
            ip, user, location, desc, phone, poll, modified, changed = ip_info
            if 'Reserved' in user:
                continue

            if user or location or desc:
                full_info = download_ip(url, index, block, ip,
                                        username=username, password=password,
                                        base_path=base_path)

                data[index][str(ip)] = full_info

    return data


def download_ip(url, index, block, ip, username=None, password=None,
                base_path='info'):
    url = get_ip_page(url, index, block, ip)
    r = download(url, username=username, password=password)

    ip_fn = get_ip_html_fn(base_path, index, block, ip)
    logger.debug('Saving IP %s to %s (index=%s block=%s)' % (ip, ip_fn, index, block))

    with open(ip_fn, 'wt') as f:
        print(r.text, file=f)

    return parse_ip(ip_fn)


def parse_ip(fn):
    logger.debug('Parsing IP html file:  %s' % fn)
    with open(fn, 'rt') as f:
        tree = lxml.html.fromstring(f.read())

    return {input_.get('name'): input_.get('value')
            for input_ in tree.findall('.//input')
            if input_.get('type') in ('TEXT', )}


def parse_ips(base_path, indices=None, data=None):
    def split_ip(ip):
        return [int(byte_) for byte_ in ip.split('.')[:4]]

    for index in indices:
        ip_path = get_ip_base_path(base_path, index)
        logger.debug('Parsing IPs In %s' % ip_path)

        ip_fns = sorted(os.listdir(ip_path), key=split_ip)
        ip_fns = [os.path.join(ip_path, fn) for fn in ip_fns
                  if fn.endswith('.htm')]

        if data is None:
            data = OrderedDict()

        if index not in data:
            data[index] = OrderedDict()

        for fn in ip_fns:
            html_fn = os.path.split(fn)[1]
            ip = html_fn.rsplit('.', 1)[0]
            data[index][ip] = parse_ip(fn)

    return data


def parse_block(fn):
    logger.debug('Parsing %s' % fn)
    with open(fn, 'rt') as f:
        tree = lxml.html.fromstring(f.read())

    table = tree.find_class('outputtable')[0]

    def parse_row(row):
        ret = [td.text_content().strip() for td in row.getchildren()]
        ip, user, location, desc, phone, poll, modified, changed = ret
        ip = ip.split(' ')[0]
        return ip, user, location, desc, phone, poll, modified, changed

    rows = [parse_row(row) for row in table.getchildren()]
    rows[0] = [head.strip().strip('<') for head in rows[0]]
    return rows


def write_host(ip, info, f=None, indent=0):
    desc = info.get('descrip', '')
    host = info.get('hname', None)
    mac = info.get('macaddr', None)
    loc = info.get('location', None)
    user = info.get('user', None)
    telephone = info.get('telno', None)
    linked_addr = info.get('lnk', None)

    valid = (host and mac and ip)

    ret = ['host %s {' % host.split('.')[0]]
    if desc:
        ret.append('    # Description:' % desc)
    if loc:
        ret.append('    # Location: %s' % loc)
    if linked_addr:
        ret.append('    # Linked address: %s' % linked_addr)
    if user:
        if telephone:
            ret.append('    # User: %s (%s)' % (user, telephone))
        else:
            ret.append('    # User: %s' % user)
    if mac:
        ret.append('    hardware ethernet %s;' % mac)
    ret.append('    fixed-address %s;' % ip)
    ret.append('}')

    if not valid:
        ret = [' '.join(('#', line)) for line in ret]

    if indent > 0:
        ret = [''.join((' ' * indent, line)) for line in ret]

    if f is not None:
        for line in ret:
            print(line, file=f)

    return ret


def create_dhcpd_conf(path, f=sys.stdout, include_all=False,
                      sort_host=True, indent=0):
    data = parse_ips(path, indices)

    def get_ips():
        hosts = {}
        for index in indices:
            for ip, ip_info in data[index].items():
                if (ip_info['hname'] and ip_info['macaddr']) or include_all:
                    if sort_host:
                        hosts[ip_info['hname']] = (ip, ip_info)
                    else:
                        yield ip, ip_info

        if sort_host:
            for host, (ip, ip_info) in sorted(hosts.items(), key=operator.itemgetter(0)):
                yield ip, ip_info

    for ip, ip_info in get_ips():
        write_host(ip, ip_info, f=f, indent=indent)
        print('', file=f)


if __name__ == '__main__':
    args = docopt(__doc__, version='0.1')

    LOG_FORMAT = "%(asctime)-15s [%(name)5s:%(levelname)s] %(message)s"
    fmt = logging.Formatter(LOG_FORMAT)

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(fmt)
    logger.addHandler(handler)

    if args['-v']:
        logger.setLevel(logging.DEBUG)
        logger.debug('Verbose mode enabled')

    if args['download']:
        indices = [int(index) for index in args['BASE_INDEX']]
        blocks = [int(block) for block in args['--block']]
        data = download_blocks(args['URL'],
                               indices=indices,
                               base_path=args['--path'],
                               blocks=blocks,
                               username=args['--user'],
                               password=args['--pass'],
                               )

    elif args['parse']:
        indices = [int(index) for index in args['BASE_INDEX']]
        data = parse_ips(args['PATH'], indices)
        out_fn = args['--file']

        def dump(stream):
            yaml.dump(data, stream=stream,
                      default_flow_style=False)

        if out_fn:
            with open(out_fn, 'wt') as f:
                dump(f)
        else:
            dump(sys.stdout)

    elif args['dhcp']:
        indices = [int(index) for index in args['BASE_INDEX']]
        out_fn = args['--file']
        indent = int(args['--indent'])

        if out_fn:
            f = open(out_fn, 'wt')
        else:
            f = sys.stdout

        create_dhcpd_conf(args['PATH'], f=f, include_all=args['--all'],
                          indent=indent, sort_host=not args['--sort-ip'])

#!/usr/bin/env python3

#
# Copyright 2018 Palo Alto Networks, Inc.
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#

import asyncio
import getopt
import json
import logging
import os
import pprint
import sys

libpath = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [os.path.join(libpath, os.pardir)]

from gridmeld.minemeld.api import MinemeldApi
from gridmeld import DEBUG1, DEBUG2, DEBUG3, __version__

INDENT = 2


def main():
    options = parse_opts()

    if options['debug']:
        logger = logging.getLogger()
        if options['debug'] == 3:
            logger.setLevel(DEBUG3)
        elif options['debug'] == 2:
            logger.setLevel(DEBUG2)
        elif options['debug'] == 1:
            logger.setLevel(DEBUG1)

        log_format = '%(message)s'
        handler = logging.StreamHandler()
        formatter = logging.Formatter(log_format)
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    kwargs = {}
    for x in ['uri', 'username', 'password',
              'verify', 'timeout']:
        if options[x] is not None:
            kwargs[x] = options[x]

    loop = asyncio.get_event_loop()
    try:
        loop.run_until_complete(_loop(kwargs, options))
    finally:
        loop.close()


async def _loop(kwargs, options):
    try:
        async with MinemeldApi(**kwargs) as api:
            if options['info']:
                resp = await api.info()
                print_status('info', resp)
                await print_response(options, resp)
                resp.raise_for_status()

            if options['status']:
                resp = await api.status()
                print_status('status', resp)
                await print_response(options, resp)
                resp.raise_for_status()

            if options['get']:
                resp = await api.get_indicators(options['node'])
                print_status('get_indicators(%s)' % options['node'], resp)
                await print_response(options, resp)
                resp.raise_for_status()

            if options['delete-all']:
                resp = await api.delete_all_indicators(options['node'])
                print_status('delete_all_indicators(%s)' % options['node'],
                             resp)
                await print_response(options, resp)
                resp.raise_for_status()

            if options['append'] is not None:
                resp = await api.append_indicators(options['node'],
                                                   options['append'])
                print_status('append_indicators(%s)' % options['node'], resp)
                await print_response(options, resp)
                resp.raise_for_status()

    except Exception as e:
        print('%s: %s' % (e.__class__.__name__, e),
              file=sys.stderr)
        sys.exit(1)


def print_status(name, resp):
    print('%s:' % name, end='', file=sys.stderr)
    if resp.status is not None:
        print(' %s' % resp.status, end='', file=sys.stderr)
    if resp.reason is not None:
        print(' %s' % resp.reason, end='', file=sys.stderr)
    if resp.headers is not None:
        print(' %s' % resp.headers.get('content-length'),
              end='', file=sys.stderr)
    print(file=sys.stderr)


async def print_response(options, resp):
    if resp.content_type == 'application/json':
        x = await resp.json()
        print_json_response(options, x)
    else:
        print(await resp.text())


def print_json_response(options, x):
    if options['print_python']:
        print(pprint.pformat(x))

    if options['print_json']:
        print(json.dumps(x, sort_keys=True, indent=INDENT))


def parse_opts():
    def opt_verify(x):
        if x == 'yes':
            return True
        elif x == 'no':
            return False
        elif os.path.exists(x):
            return x
        else:
            print('Invalid --verify option:', x, file=sys.stderr)
            sys.exit(1)

    options = {
        'config': {},
        'uri': None,
        'username': None,
        'password': None,
        'node': None,
        'status': False,
        'info': False,
        'get': False,
        'append': None,
        'delete-all': False,
        'verify': None,
        'print_json': False,
        'print_python': False,
        'timeout': None,
        'debug': 0,
        }

    short_options = 'F:jp'
    long_options = [
        'help', 'version', 'debug=',
        'uri=', 'username=', 'password=', 'node=',
        'status', 'info', 'get', 'append=', 'delete-all',
        'verify=',
        'timeout=',
    ]

    try:
        opts, args = getopt.getopt(sys.argv[1:],
                                   short_options,
                                   long_options)
    except getopt.GetoptError as error:
        print(error, file=sys.stderr)
        sys.exit(1)

    for opt, arg in opts:
        if False:
            pass
        elif opt == '-F':
            try:
                with open(arg, 'r') as f:
                    x = json.load(f)
                    options['config'].update(x)
            except (IOError, ValueError) as e:
                print('%s: %s' % (arg, e), file=sys.stderr)
                sys.exit(1)
        elif opt == '--uri':
            options['uri'] = arg
        elif opt == '--username':
            options['username'] = arg
        elif opt == '--password':
            options['password'] = arg
        elif opt == '--node':
            options['node'] = arg
        elif opt == '--status':
            options['status'] = True
        elif opt == '--info':
            options['info'] = True
        elif opt == '--get':
            options['get'] = True
        elif opt == '--append':
            try:
                with open(arg, 'r') as f:
                    x = json.load(f)
                    options['append'] = x
            except (IOError, ValueError) as e:
                print('%s: %s' % (arg, e), file=sys.stderr)
                sys.exit(1)
        elif opt == '--delete-all':
            options['delete-all'] = True
        elif opt == '--verify':
            options['verify'] = opt_verify(arg)
        elif opt == '--timeout':
            try:
                options['timeout'] = tuple(float(x) for x in arg.split(','))
            except ValueError as e:
                print('Invalid timeout %s: %s' % (arg, e), file=sys.stderr)
                sys.exit(1)
            if len(options['timeout']) == 1:
                options['timeout'] = options['timeout'][0]
        elif opt == '-j':
            options['print_json'] = True
        elif opt == '-p':
            options['print_python'] = True
        elif opt == '--debug':
            try:
                options['debug'] = int(arg)
                if options['debug'] < 0:
                    raise ValueError
            except ValueError:
                print('Invalid debug:', arg, file=sys.stderr)
                sys.exit(1)
            if options['debug'] > 3:
                print('Maximum debug level is 3', file=sys.stderr)
                sys.exit(1)
        elif opt == '--version':
            print('gridmeld', __version__)
            sys.exit(0)
        elif opt == '--help':
            usage()
            sys.exit(0)
        else:
            assert False, 'unhandled option %s' % opt

    for x in ['uri', 'username', 'password', 'node']:
        if x in options['config'] and options[x] is None:
            options[x] = options['config'][x]
    if 'verify' in options['config'] and options['verify'] is None:
        options['verify'] = opt_verify(options['config']['verify'])
    if options['verify'] is None:
        options['verify'] = True

    if options['debug'] > 2:
        print(pprint.pformat(options), file=sys.stderr)

    return options


def usage():
    usage = '''%s [options]
    --uri uri                MineMeld URI
    --username username      API username
    --password password      API password
    --node name              Node name
    --status                 status API request
    --info                   info API request
    --get                    get indicators API request
    --delete-all             delete all indicators
    --append path            append indicators API request
    --verify opt             SSL server verify option: yes|no|path
    -j                       print JSON
    -p                       print Python
    --timeout timeout        connect, read timeout
    -F path                  JSON options (multiple -F's allowed)
    --debug level            debug level (0-3)
    --version                display version
    --help                   display usage
'''
    print(usage % os.path.basename(sys.argv[0]), end='')


if __name__ == '__main__':
    main()

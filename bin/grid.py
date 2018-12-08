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
import functools
import getopt
import json
import logging
import os
import pprint
import signal
import sys

libpath = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [os.path.join(libpath, os.pardir)]

from gridmeld.pxgrid.rest import PxgridRest
from gridmeld.pxgrid.wsstomp import PxgridWsStomp
from gridmeld import DEBUG1, DEBUG2, DEBUG3, __version__

debug = 0
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
    for x in ['hostname', 'nodename', 'password', 'secret',
              'cert', 'verify', 'timeout']:
        if options[x] is not None:
            kwargs[x] = options[x]

    loop = asyncio.get_event_loop()
    try:
        loop.run_until_complete(_loop(kwargs, options))
    finally:
        pass

    kwargs = {}
    for x in ['wsurl', 'subscribe', 'peernode',
              'nodename', 'secret',
              'cert', 'verify', 'timeout']:
        if options[x] is not None:
            if x == 'subscribe':
                kwargs['topic'] = options[x]
            else:
                kwargs[x] = options[x]
        pass

    loop = asyncio.get_event_loop()
    # Python 3.7: task = asyncio.create_task(coro())
    asyncio.ensure_future(_loop2(kwargs, options))
    try:
        loop.run_forever()
    finally:
        loop.run_until_complete(loop.shutdown_asyncgens())
        loop.close()


async def _loop(kwargs, options):
    try:
        async with PxgridRest(**kwargs) as api:
            if options['xversion']:
                resp = await api.version()
                print_status('version', resp)
                await print_response(options, resp)
                resp.raise_for_status()

            if options['create']:
                resp = await api.account_create()
                print_status('account_create', resp)
                await print_response(options, resp)
                resp.raise_for_status()

            if options['activate']:
                resp = await api.account_activate(
                    description=options['description'])
                print_status('account_activate', resp)
                await print_response(options, resp)
                resp.raise_for_status()

            if options['lookup']:
                resp = await api.service_lookup(name=options['name'])
                print_status('service_lookup', resp)
                await print_response(options, resp)
                resp.raise_for_status()

            if options['asecret']:
                resp = await api.access_secret(
                    peernode=options['peernode'])
                print_status('access_secret', resp)
                await print_response(options, resp)
                resp.raise_for_status()

            if options['sessions']:
                resp = await api.get_sessions(
                    restbaseurl=options['baseurl'],
                    starttime=options['start_time'])
                print_status('get_sessions', resp)
                await print_response(options, resp)
                resp.raise_for_status()

    except Exception as e:
        print('%s: %s' % (e.__class__.__name__, e),
              file=sys.stderr)
        sys.exit(1)


async def _loop2(kwargs, options):
    if options['subscribe'] is None:
        asyncio.get_event_loop().stop()
        return

    try:
        loop = asyncio.get_event_loop()
        for signame in ('SIGINT', 'SIGTERM'):
            loop.add_signal_handler(getattr(signal, signame),
                                    functools.partial(exit_, signame))

        async with PxgridWsStomp(**kwargs) as api:
            gen = api.subscribe()
            while True:
                x = await gen.__anext__()
                print_json_response(options, x)

    except asyncio.CancelledError:
        pass
    except Exception as e:
        print('%s: %s' % (e.__class__.__name__, e),
              file=sys.stderr)
    finally:
        loop.stop()


def exit_(signame):
    print('got %s, exiting' % signame, file=sys.stderr)
    for task in asyncio.Task.all_tasks():
        if debug > 0:
            print('cancel task:', task, file=sys.stderr)
        task.cancel()


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
    # XXX get_sessions returns no content-type

    data = await resp.text()
    try:
        x = json.loads(data)
        print_json_response(options, x)
    except ValueError:
        print(data)


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
        'xversion': False,
        'create': False,
        'activate': False,
        'description': None,
        'lookup': False,
        'name': None,
        'asecret': False,
        'peernode': None,
        'sessions': False,
        'baseurl': None,
        'start_time': None,
        'wsurl': None,
        'subscribe': None,
        'hostname': None,
        'nodename': None,
        'password': None,
        'secret': None,
        'cert': None,
        'verify': None,
        'print_json': False,
        'print_python': False,
        'timeout': None,
        'debug': 0,
        }

    short_options = 'F:jp'
    long_options = [
        'help', 'version', 'debug=',
        'xversion',
        'create',
        'activate', 'desc=',
        'lookup', 'name=',
        'asecret', 'peernode=',
        'sessions', 'start=', 'baseurl=',
        'wsurl=', 'subscribe=',
        'hostname=', 'nodename=', 'password=', 'secret=',
        'cert=', 'verify=',
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
        elif opt == '--hostname':
            if options['hostname'] is None:
                options['hostname'] = []
            options['hostname'].append(arg)
        elif opt == '--nodename':
            options['nodename'] = arg
        elif opt == '--password':
            options['password'] = arg
        elif opt == '--secret':
            options['secret'] = arg
        elif opt == '--xversion':
            options['xversion'] = True
        elif opt == '--create':
            options['create'] = True
        elif opt == '--activate':
            options['activate'] = True
        elif opt == '--desc':
            options['description'] = arg
        elif opt == '--lookup':
            options['lookup'] = True
        elif opt == '--name':
            options['name'] = arg
        elif opt == '--asecret':
            options['asecret'] = True
        elif opt == '--peernode':
            options['peernode'] = arg
        elif opt == '--sessions':
            options['sessions'] = True
        elif opt == '--baseurl':
            options['baseurl'] = arg
        elif opt == '--start':
            options['start_time'] = arg
        elif opt == '--wsurl':
            options['wsurl'] = arg
        elif opt == '--subscribe':
            options['subscribe'] = arg
        elif opt == '--cert':
            options['cert'] = arg
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
            global debug
            debug = options['debug']
        elif opt == '--version':
            print('gridmeld', __version__)
            sys.exit(0)
        elif opt == '--help':
            usage()
            sys.exit(0)
        else:
            assert False, 'unhandled option %s' % opt

    for x in ['hostname', 'nodename', 'password', 'secret', 'cert']:
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
    --xversion               pxGrid version API request
    --create                 AccountCreate API request (username/password auth)
    --activate               AccountActivate API request
    --desc description       client "description"
    --lookup                 ServiceLookup API request
    --name name              service "name"
    --asecret                AccessSecret API request (username/password auth)
    --peernode name          "peerNodeName"
    --sessions               getSessions API request
    --baseurl url            "restBaseUrl"
    --start time             start time in ISO 8601 format
    --wsurl url              WebSocket URL ("wsUrl")
    --subscribe topic        subscribe to topic
    --hostname hostname      ISE hostname (multiple --hostname's allowed)
    --nodename nodename      pxGrid client nodename (username)
    --password password      pxGrid client password
    --secret secret          pxGrid client secret
    --cert path              SSL client certificate file
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

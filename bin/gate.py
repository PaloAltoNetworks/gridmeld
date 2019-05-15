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

import aiohttp
import asyncio
import functools
import getopt
import inspect
import ipaddress
import json
import logging
from logging.handlers import SysLogHandler
import os
import pprint
import signal
import sys
import tenacity

libpath = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [os.path.join(libpath, os.pardir)]

import gridmeld.pxgrid.rest
import gridmeld.pxgrid.wsstomp
from gridmeld.pxgrid.wsstomp import EOS
import gridmeld.minemeld.api
from gridmeld.util.util_daemon import daemon
from gridmeld import DEBUG1, DEBUG2, DEBUG3, __version__

debug = 0
logger = None

SYSLOG_DEVICE = '/dev/log'
SYSLOG_FORMAT = '%(levelname)s %(name)s[%(process)d]: %(message)s'
STDERR_FORMAT = '%(levelname)s %(name)s %(message)s'


def main():
    loop = asyncio.get_event_loop()
    try:
        for signame in ('SIGINT', 'SIGTERM'):
            loop.add_signal_handler(getattr(signal, signame),
                                    functools.partial(exit_, signame))
        loop.run_until_complete(loop_main())
    finally:
        loop.run_until_complete(loop.shutdown_asyncgens())
        loop.close()


def exit_(signame):
    logger.info('got %s, exiting', signame)
    for task in asyncio.Task.all_tasks():
        logger.debug('cancel task: %s', task)
        task.cancel()


async def loop_main():
    options = parse_opts()

    if options['syslog'] is None:
        handler = logging.StreamHandler()  # default sys.stderr
        formatter = logging.Formatter(STDERR_FORMAT)
    else:
        facility = SysLogHandler.facility_names[options['syslog']]
        handler = SysLogHandler(address=SYSLOG_DEVICE,
                                facility=facility)
        formatter = logging.Formatter(SYSLOG_FORMAT)

    handler.setFormatter(formatter)
    global logger
    logger = logging.getLogger()
    logger.addHandler(handler)

    if options['debug'] == 3:
        logger.setLevel(DEBUG3)
    elif options['debug'] == 2:
        logger.setLevel(DEBUG2)
    elif options['debug'] == 1:
        logger.setLevel(DEBUG1)
    else:
        logger.setLevel(logging.INFO)

    if options['daemon']:
        try:
            daemon()
        except OSError as e:
            print('daemon: %s' % e, file=sys.stderr)
            sys.exit(1)

    logger = logging.getLogger(os.path.basename(sys.argv[0]))
    logger.info('starting (gridmeld %s)', __version__)

    m_kwargs = {}
    for x in ['uri', 'username', 'password',
              'verify', 'timeout']:
        if options['m'][x] is not None:
            m_kwargs[x] = options['m'][x]

    x_kwargs = {}
    for x in ['hostname', 'nodename', 'password',
              'cert', 'verify', 'timeout']:
        if options['x'][x] is not None:
            x_kwargs[x] = options['x'][x]

    try:
        node = options['m']['node']
        coros = [
            init_minemeld(node, m_kwargs),
        ]
        if not options['x']['replay']:
            coros.append(init_pxgrid(x_kwargs))

        x = await asyncio.gather(*coros)
        logger.debug('%s', x)

        if not all(x):
            raise RuntimeError

        queue = asyncio.Queue()
        coros = [
            loop_minemeld(node, m_kwargs, queue),
        ]

        if options['x']['replay']:
            coros.append(loop_replay(options['x']['replay'], queue))
        else:
            x_options = x[1]
            x_kwargs2 = {}
            for x in ['nodename', 'cert', 'verify', 'timeout']:
                if options['x'][x] is not None:
                    x_kwargs2[x] = options['x'][x]
            for x in ['secret', 'wsurl', 'peernode', 'topic', 'restbaseurl']:
                if x_options[x] is not None:
                    x_kwargs2[x] = x_options[x]
            coros.append(loop_pxgrid(x_kwargs2, x_options['rest_secret'],
                                     queue))

        tasks = map(asyncio.ensure_future, coros)
        done, pending = await asyncio.wait(
            tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in pending:
            logger.debug('cancel task: %s', task)
            task.cancel()

    except RuntimeError:
        pass
    except asyncio.CancelledError:
        logger.debug('%s: CancelledError', inspect.stack()[0][3])
    except Exception as e:
        logger.error('%s', e, exc_info=True)

    logger.info('exiting')


async def init_minemeld(node, m_kwargs):
    try:
        async with gridmeld.minemeld.api.MinemeldApi(**m_kwargs) as api:
            resp = await api.info()
            if resp.status == 200:
                result = await resp.json()
                try:
                    logger.info('MineMeld %s', result['result']['version'])
                except KeyError as e:
                    logger.error('MineMeld %s', e)
            resp = await api.status()
            resp.raise_for_status()
            result = await resp.json()
            class_ = 'minemeld.ft.localdb.Miner'
            found = False
            for x in result['result']:
                if x['name'] == node and x['class'] == class_:
                    found = True
                    break
            if not found:
                raise ValueError('node "%s" with class "%s" not found' %
                                 (node, class_))

    except asyncio.CancelledError:
        return
    except (gridmeld.minemeld.api.RequiredArgsError,
            gridmeld.minemeld.api.MinemeldApiError,
            aiohttp.ClientError,
            ValueError) as e:
        logger.error('%s: %s: %s', inspect.stack()[0][3],
                     e.__class__.__name__, e)
        return False
    except Exception as e:
        logger.error('%s', e, exc_info=True)
        return False
    else:
        return True


async def init_pxgrid(x_kwargs):
    try:
        async with gridmeld.pxgrid.rest.PxgridRest(**x_kwargs) as api:
            # session service
            # PxgridRest.service_lookup()
            name = 'com.cisco.ise.session'
            resp = await api.service_lookup(name=name)
            resp.raise_for_status()
            result = await resp.json()
            args = {}
            x = result['services'][0]
            # PxgridRest.access_secret()
            peernode = x['nodeName']
            # PxgridWsStomp.__init__()
            args['topic'] = x['properties']['sessionTopic']
            # PxgridRest.get_sessions()
            args['restbaseurl'] = x['properties']['restBaseUrl']
            # PxgridRest.service_lookup()
            name = x['properties']['wsPubsubService']

            if 'password' in x_kwargs:
                resp = await api.access_secret(peernode=peernode)
                resp.raise_for_status()
                result = await resp.json()
                args['rest_secret'] = result['secret']
            else:
                args['rest_secret'] = None

            # pubsub service
            resp = await api.service_lookup(name=name)
            resp.raise_for_status()
            result = await resp.json()
            x = result['services'][0]
            # PxgridWsStomp.__init__()
            args['peernode'] = x['nodeName']
            # PxgridWsStomp.__init__()
            args['wsurl'] = x['properties']['wsUrl']

            if 'password' in x_kwargs:
                resp = await api.access_secret(peernode=args['peernode'])
                resp.raise_for_status()
                result = await resp.json()
                args['secret'] = result['secret']
            else:
                args['secret'] = None

            resp = await api.version()
            if resp.status == 200:
                data = await resp.json()
                logger.info('pxGrid %s', data)

    except asyncio.CancelledError:
        return
    except (gridmeld.pxgrid.rest.RequiredArgsError,
            gridmeld.pxgrid.rest.PxgridRestError,
            aiohttp.ClientError) as e:
        logger.error('%s: %s: %s', inspect.stack()[0][3],
                     e.__class__.__name__, e)
        return
    except Exception as e:
        logger.error('%s', e, exc_info=True)
        return
    else:
        return args


# session object:
# https://github.com/cisco-pxgrid/pxgrid-rest-ws/wiki/Session-Directory#objects
async def loop_minemeld(node, kwargs, queue):
    sdb = {}  # Session DB

    retry = tenacity.AsyncRetrying(
        before=tenacity.before_log(logger, logging.DEBUG),
        after=tenacity.after_log(logger, logging.WARN),
        retry=(tenacity.retry_if_exception_type(aiohttp.ClientError) |
               tenacity.retry_if_result(lambda resp: resp.status != 200)),
        wait=tenacity.wait_fixed(10),
        stop=tenacity.stop_after_delay(60*10),
        reraise=True,
    )

    try:
        async with gridmeld.minemeld.api.MinemeldApi(**kwargs) as api:
            resp = await api.get_indicators(node)
            resp.raise_for_status()
            result = await resp.json()
            indicators = {}
            for x in result['result']:
                keys = [k for k in x.keys() if not k.startswith('_')]
                indicator = {k: x[k] for k in keys}
                indicator['ttl'] = 0
                indicators[indicator['indicator']] = indicator

            sessions_synced = False

            while True:
                x = await queue.get()

                if x is EOS:  # end of sessions download
                    sessions_synced = True
                    sdb = {k: indicators[k] for k in indicators
                           if not indicators[k]['ttl'] == 0}
                    data = [indicators[k] for k in indicators]
                    resp = await api.append_indicators(node=node,
                                                       json=data)
                    resp.raise_for_status()
                    logger.info('SDB size after session sync: %d', len(sdb))
                    continue

                logger.debug('%s', x)

                if 'state' not in x:
                    logger.error('no state: %s', x)
                    continue
                if 'ipAddresses' not in x:
                    logger.warning('no ipAddresses: %s', x)
                    continue
                if not x['ipAddresses']:
                    logger.warning('empty ipAddresses: %s', x)
                    continue

                if x['state'] == 'STARTED':
                    for addr in x['ipAddresses']:
                        try:
                            ip = ipaddress.ip_address(addr)
                        except ValueError as e:
                            logger.error('invalid IP: %s: %s', addr, e)
                            continue
                        sgt = user = None
                        if 'ctsSecurityGroup' in x:
                            sgt = x['ctsSecurityGroup']
                        if 'userName' in x:
                            user = x['userName']
                        if not (sgt or user):
                            logger.warning('%s: no SGT or user', ip)
                            continue
                        indicator = indicator_object(ip, sgt, user)
                        if not sessions_synced:
                            indicators[str(ip)] = indicator
                            continue
                        resp = await retry.call(
                            api.append_indicators,
                            node=node,
                            json=indicator
                        )
                        if resp.status != 200:
                            log_http_error('append_indicators',
                                           resp, indicator)
                            continue
                        sdb[str(ip)] = indicator
                        log_event(str(ip), x['state'], sgt, user)

                elif x['state'] == 'DISCONNECTED':
                    for addr in x['ipAddresses']:
                        try:
                            ip = ipaddress.ip_address(addr)
                        except ValueError as e:
                            logger.error('invalid IP: %s: %s', addr, e)
                            continue
                        if not sessions_synced:
                            logger.warning('%s DISCONNECTED in get_sessions():'
                                           ' %s', ip, x)
                            continue
                        if str(ip) not in sdb:
                            logger.warning('%s %s: not connected',
                                           ip, x['state'])
                            continue
                        resp = await retry.call(
                            api.delete_indicator,
                            node=node,
                            indicator=str(ip),
                            type=indicator_type(ip)
                        )
                        if resp.status != 200:
                            log_http_error('delete_indicator',
                                           resp, indicator)
                            continue
                        log_event(str(ip), x['state'], sdb[str(ip)]['sgt'],
                                  sdb[str(ip)]['user'])
                        del sdb[str(ip)]

                else:
                    for addr in x['ipAddresses']:
                        logger.info('%s %s: no action on event',
                                    addr, x['state'])
                    continue

                if not sessions_synced:
                    continue

                msg = 'SDB size: %d' % len(sdb)
                max = 5
                if len(sdb) and len(sdb) <= max:
                    msg += ': indicators (up to %d): %s' % \
                           (max, list(sdb.keys()))
                logger.info('%s', msg)

    except asyncio.CancelledError:
        logger.debug('%s: CancelledError', inspect.stack()[0][3])
    except (gridmeld.minemeld.api.MinemeldApiError,
            aiohttp.ClientError) as e:
        logger.error('%s: %s: %s', inspect.stack()[0][3],
                     e.__class__.__name__, e)
    except Exception as e:
        logger.error('%s', e, exc_info=True)
    finally:
        logger.info('%s exiting', inspect.stack()[0][3])


def log_http_error(name, resp, indicator):
    logger.error('%s: %d %s: %s', name, resp.status, resp.reason, indicator)


def log_event(indicator, state, sgt, user):
    logger.info('%s %s: sgt=%s user=%s', indicator, state,
                sgt, user)


def indicator_type(ip):
    if ip.version == 4:
        return 'IPv4'
    elif ip.version == 6:
        return 'IPv6'


def indicator_object(ip, sgt, user):
    x = {
        'indicator': str(ip),
        'type': indicator_type(ip),
        'share_level': 'red',
        'user': user,
        'sgt': sgt,
        'ttl': 'disabled',  # any non-int disables expiration
    }

    return x


async def loop_pxgrid(kwargs, rest_secret, queue):
    try:
        async with gridmeld.pxgrid.wsstomp.PxgridWsStomp(**kwargs) as api:
            async for x in api.subscribe(get_sessions=True,
                                         rest_secret=rest_secret):
                await queue.put(x)

    except asyncio.CancelledError:
        logger.debug('%s: CancelledError', inspect.stack()[0][3])
    except (gridmeld.pxgrid.wsstomp.PxgridWsStompError,
            aiohttp.ClientError) as e:
        logger.error('%s: %s: %s', inspect.stack()[0][3],
                     e.__class__.__name__, e)
    except Exception as e:
        logger.error('%s', e, exc_info=True)
    finally:
        logger.info('%s exiting', inspect.stack()[0][3])


async def loop_replay(sessions, queue):
    try:
        for x in sessions['sessions']:
            await queue.put(x)
        await queue.put(EOS)
        await asyncio.sleep(15)  # XXX

    except asyncio.CancelledError:
        logger.debug('%s: CancelledError', inspect.stack()[0][3])
    except Exception as e:
        logger.error('%s', e, exc_info=True)
    finally:
        logger.info('%s exiting', inspect.stack()[0][3])


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

    def opt_context_verify(context, option):
        if context is None:
            print('No context for option: %s' % opt, file=sys.stderr)
            sys.exit(1)
        if context == 'minemeld':
            x = options_m
        elif context == 'pxgrid':
            x = options_x
        if option not in x:
            print('No option %s in context %s' % (opt, context),
                  file=sys.stderr)
            sys.exit(1)

        return x

    def opt_set(context, option, val):
        x = opt_context_verify(context, option)
        x[option] = val

    def opt_update(context, option, val):
        x = opt_context_verify(context, option)
        x[option].update(val)

    def opt_append(context, option, val):
        x = opt_context_verify(context, option)
        if x[option] is None:
            x[option] = []
        x[option].append(val)

    options_m = {
        'config': {},
        'uri': None,
        'username': None,
        'password': None,
        'node': None,
        'verify': None,
        'timeout': None,
    }

    options_x = {
        'config': {},
        'replay': None,
        'hostname': None,
        'nodename': None,
        'password': None,
        'cert': None,
        'verify': None,
        'timeout': None,
    }

    options = {
        'm': options_m,
        'x': options_x,
        'syslog': None,
        'daemon': False,
        'debug': 0,
    }

    short_options = '-F:'
    long_options = [
        'help', 'version', 'debug=',
        'syslog=', 'daemon', 'timeout=',
        # shared
        'password=', 'verify=',
        # MineMeld
        'minemeld', 'uri=', 'username=', 'node=',
        # pxGrid
        'pxgrid', 'nodename=', 'cert=', 'replay=',
    ]

    try:
        opts, args = getopt.getopt(sys.argv[1:],
                                   short_options,
                                   long_options)
    except getopt.GetoptError as error:
        print(error, file=sys.stderr)
        sys.exit(1)

    context = None

    for opt, arg in opts:
        if False:
            pass
        elif opt == '--minemeld':
            context = opt[2:]
        elif opt == '--pxgrid':
            context = opt[2:]
        elif opt == '-F':
            try:
                with open(arg, 'r') as f:
                    x = json.load(f)
                    opt_update(context, 'config', x)
            except (IOError, ValueError) as e:
                print('%s: %s' % (arg, e), file=sys.stderr)
                sys.exit(1)
        elif opt == '--replay':
            try:
                with open(arg, 'r') as f:
                    x = json.load(f)
                    if 'sessions' not in x:
                        print('%s: no "sessions" key in session object' %
                              arg, file=sys.stderr)
                        sys.exit(1)
                    opt_set(context, opt[2:], x)
            except (IOError, ValueError) as e:
                print('%s: %s' % (arg, e), file=sys.stderr)
                sys.exit(1)
        elif opt == '--uri':
            opt_set(context, opt[2:], arg)
        elif opt == '--node':
            opt_set(context, opt[2:], arg)
        elif opt == '--hostname':
            opt_set(context, opt[2:], arg)
        elif opt == '--username':
            opt_set(context, opt[2:], arg)
        elif opt == '--nodename':
            opt_append(context, opt[2:], arg)
        elif opt == '--password':
            opt_set(context, opt[2:], arg)
        elif opt == '--cert':
            opt_set(context, opt[2:], arg)
        elif opt == '--verify':
            opt_set(context, opt[2:], opt_verify(arg))
        elif opt == '--timeout':
            try:
                x = tuple(float(x) for x in arg.split(','))
            except ValueError as e:
                print('Invalid timeout %s: %s' % (arg, e), file=sys.stderr)
                sys.exit(1)
            if len(x) == 1:
                x = x[0]
            opt_set(context, opt[2:], x)
        elif opt == '--syslog':
            options['syslog'] = arg
            if options['syslog'] not in SysLogHandler.facility_names:
                print('Invalid syslog facility:', options['syslog'],
                      file=sys.stderr)
                sys.exit(1)
        elif opt == '--daemon':
            options['daemon'] = True
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

    for x in ['hostname', 'nodename', 'password', 'cert', 'timeout']:
        if x in options_x['config'] and options_x[x] is None:
            options_x[x] = options_x['config'][x]
    if 'verify' in options_x['config'] and options_x['verify'] is None:
        options_x['verify'] = opt_verify(options_x['config']['verify'])
    if options_x['verify'] is None:
        options_x['verify'] = True

    for x in ['uri', 'username', 'password', 'node', 'timeout']:
        if x in options_m['config'] and options_m[x] is None:
            options_m[x] = options_m['config'][x]
    if 'verify' in options_m['config'] and options_m['verify'] is None:
        options_m['verify'] = opt_verify(options_m['config']['verify'])
    if options_m['verify'] is None:
        options_m['verify'] = True

    if options['debug'] > 2:
        print(pprint.pformat(options), file=sys.stderr)

    return options


def usage():
    usage = '''%s [options]
    --minemeld               MineMeld options follow
      --uri uri              MineMeld URI
      --username username    API username
      --password password    API password
      --node name            localDB miner node name
      --verify opt           SSL server verify option: yes|no|path
      --timeout timeout      connect, read timeout
      -F path                JSON options (multiple -F's allowed)
    --pxgrid                 pxGrid options follow
      --hostname hostname    ISE hostname (multiple --hostname's allowed)
      --nodename nodename    pxGrid client nodename (username)
      --password password    pxGrid client password
      --cert path            SSL client certificate file
      --verify opt           SSL server verify option: yes|no|path
      --timeout timeout      connect, read timeout
      --replay json          replay session objects
      -F path                JSON options (multiple -F's allowed)
    --syslog facility        log to syslog with facility
                             (default: log to stderr)
    --daemon                 run as a daemon
                             (default: run in foreground)
    --debug level            debug level (0-3)
    --version                display version
    --help                   display usage
'''
    print(usage % os.path.basename(sys.argv[0]), end='')


if __name__ == '__main__':
    main()

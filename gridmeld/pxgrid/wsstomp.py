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

# Portions derived from:
#   https://github.com/cisco-pxgrid/pxgrid-rest-ws/blob/master/python/ws_stomp.py
# Which has Apache License 2.0:
#   https://github.com/cisco-pxgrid/pxgrid-rest-ws/blob/master/LICENSE

'''\
Python interface to the Cisco ISE pxGrid 2.0 WebSocket API:

  https://github.com/cisco-pxgrid/pxgrid-rest-ws/wiki

The interface is specific to the requirements for integration with
MineMeld and PAN-OS.
'''

import aiohttp
from asyncio import CancelledError
from io import StringIO
import json
import logging

from gridmeld.pxgrid.stomp import StompFrame, StompCommand
from gridmeld.pxgrid.rest import PxgridRest
from gridmeld.util.mixin import UtilMixin
from gridmeld import DEBUG1, DEBUG2, DEBUG3

EOS = object  # End of sessions sentinel when subscribe(get_sessions=True)


class PxgridWsStompError(Exception):
    pass


class RequiredArgsError(PxgridWsStompError):
    pass


class PxgridWsStomp(UtilMixin):
    def __init__(self,
                 loop=None,
                 wsurl=None,
                 nodename=None,  # username
                 peernode=None,
                 topic=None,
                 restbaseurl=None,
                 cert=None,
                 secret=None,
                 verify=None,
                 timeout=None):
        self._log = logging.getLogger(__name__).log
        self._log(DEBUG2, 'aiohttp version: %s', aiohttp.__version__)

        timeout_ = self._timeout(timeout)
        self._log(DEBUG2, 'timeout: %s', timeout_)
        try:
            self.ssl = self._ssl_context(verify, cert)
        except ValueError as e:
            raise PxgridWsStompError(e)
        self._log(DEBUG2, 'ssl: %s %s', self.ssl.verify_mode,
                  self.ssl.check_hostname)
        auth = self._auth(nodename, secret, cert)
        self.session = self._session(loop=loop, auth=auth, timeout=timeout_)

        self.wsurl = wsurl
        self.nodename = nodename
        self.peernode = peernode
        self.topic = topic
        self.restbaseurl = restbaseurl
        self.cert = cert
        self.secret = secret
        self.verify = verify
        self.timeout = timeout

    async def __aenter__(self):
        self._log(DEBUG1, '%s', '__aenter__')
        return self

    async def __aexit__(self, *args):
        self._log(DEBUG1, '%s', '__aexit__')
        if not self.session.closed:
            self._log(DEBUG1, 'closing aiohttp session')
            await self.session.close()

    def _auth(self, nodename, secret, cert):
        if nodename is None:
            raise RequiredArgsError('nodename required')
        if cert is None:
            if secret is None:
                raise RequiredArgsError('cert or secret required')
            x = aiohttp.BasicAuth(nodename, secret)
        else:
            x = aiohttp.BasicAuth(nodename, '')

        return x

    # https://aiohttp.readthedocs.io/en/stable/client_reference.html#clientwebsocketresponse
    # https://aiohttp.readthedocs.io/en/stable/websocket_utilities.html#aiohttp.WSMessage
    async def subscribe(self, get_sessions=False, rest_secret=None):
        if self.wsurl is None:
            raise RequiredArgsError('wsurl required')
        if self.peernode is None:
            raise RequiredArgsError('peernode required')
        if self.topic is None:
            raise RequiredArgsError('topic required')
        if get_sessions and self.restbaseurl is None:
            raise RequiredArgsError('restbaseurl required')

        try:
            async with self.session.ws_connect(url=self.wsurl,
                                               ssl=self.ssl) as ws:
                self.ws = ws
                await self.stomp_connect(self.peernode)
                await self.stomp_subscribe(self.topic)

                if get_sessions:
                    kwargs = {
                        'nodename': self.nodename,
                        'cert': self.cert,
                        'secret': rest_secret,
                        'verify': self.verify,
                        'timeout': self.timeout,
                    }
                    async with PxgridRest(**kwargs) as api:
                        resp = await api.get_sessions(
                            restbaseurl=self.restbaseurl)
                        resp.raise_for_status()
                        # XXX response has no content-type
                        sessions = await resp.json(content_type=None)
                        self._log(logging.INFO, '%s: %d session objects',
                                  'get_sessions()', len(sessions['sessions']))
                        for x in sessions['sessions']:
                            yield x

                        yield EOS

                self._log(logging.INFO, 'processing events from %s %s',
                          self.wsurl, self.topic)
                while True:
                    try:
                        message = await self.stomp_read_message()
                        try:
                            sessions = json.loads(message)
                        except (TypeError,
                                json.decoder.JSONDecodeError) as e:
                            raise PxgridWsStompError('%s: Bad JSON: %s' %
                                                     (type(e).__name__, e))
                        for x in sessions['sessions']:
                            yield x
                    except RuntimeError as e:
                        raise PxgridWsStompError(e)

        except CancelledError:
            self._log(DEBUG1, 'CancelledError')
            raise
        except Exception as e:
            raise

    async def stomp_connect(self, hostname):
        # XXX CONNECT host header is ignored?
        command = StompCommand.CONNECT
        self._log(DEBUG1, 'STOMP %s host=%s', command.value, hostname)
        frame = StompFrame(command=command)
        frame.set_header('accept-version', '1.2')
        frame.set_header('host', hostname)
        s_out = StringIO()
        frame.write(s_out)
        await self.ws.send_bytes(s_out.getvalue().encode('utf-8'))

    async def stomp_subscribe(self, topic):
        command = StompCommand.SUBSCRIBE
        self._log(DEBUG1, 'STOMP %s topic=%s', command.value, topic)
        frame = StompFrame(command=command)
        frame.set_header('destination', topic)
        # XXX we subscribe to single topic and don't need unique id
        frame.set_header('id', '50414e57')  # PANW
        s_out = StringIO()
        frame.write(s_out)
        await self.ws.send_bytes(s_out.getvalue().encode('utf-8'))

    # XXX not used
    async def stomp_send(self, topic, message):
        command = StompCommand.SEND
        self._log(DEBUG1, 'STOMP %s topic=%s', command.value, topic)
        frame = StompFrame(command=command)
        frame.set_header('destination', topic)
        frame.set_content(message)
        s_out = StringIO()
        frame.write(s_out)
        await self.ws.send_bytes(s_out.getvalue().encode('utf-8'))

    # only returns for MESSAGE
    async def stomp_read_message(self):
        while True:
            msg = await self.ws.receive()
            if msg.type != aiohttp.http.WSMsgType.BINARY:
                if msg.type in (aiohttp.http.WSMsgType.CLOSE,
                                aiohttp.http.WSMsgType.CLOSING,
                                aiohttp.http.WSMsgType.CLOSED):
                    x = 'peer closed connection: {}:{!r}'.format(
                        msg.type, msg.data)
                    raise RuntimeError(x)
                else:
                    x = 'websocket error: {}:{!r}'.format(
                        msg.type, msg.data)
                    raise RuntimeError(x)

            s_in = StringIO(msg.data.decode('utf-8'))
            try:
                stomp = StompFrame.parse(s_in)
            except ValueError as e:
                raise PxgridWsStompError('StompFrame.parse: %s' % e)
            command = stomp.get_command()
            if command == StompCommand.MESSAGE:
                id = stomp.get_header('message-id')
                content_length = stomp.get_header('content-length')
                x = 'STOMP %s message-id=%s content-length=%s' % \
                    (command.value, id, content_length)
                self._log(DEBUG2, x)
                return stomp.get_content()
            elif command == StompCommand.CONNECTED:
                version = stomp.get_header('version')
                x = 'STOMP %s version=%s' % (command.value, version)
                heartbeat = stomp.get_header('heart-beat')
                if heartbeat:
                    x += ' heart-beat=%s' % heartbeat
                self._log(DEBUG1, x)
            elif command == StompCommand.ERROR:
                x = 'STOMP %s content=%s' % (command.value,
                                             stomp.get_content())
                raise RuntimeError(x)
            else:
                x = 'STOMP %s' % command.value
                raise RuntimeError(x)

    # XXX not used
    async def stomp_disconnect(self, receipt=None):
        command = StompCommand.DISCONNECT
        self._log(DEBUG1, 'STOMP %s receipt=%s', command.value, receipt)
        frame = StompFrame(command=command)
        if receipt is not None:
            frame.set_header('receipt', receipt)
        s_out = StringIO()
        frame.write(s_out)
        await self.ws.send_bytes(s_out.getvalue().encode('utf-8'))

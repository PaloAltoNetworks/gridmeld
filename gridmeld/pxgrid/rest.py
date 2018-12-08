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

'''\
Python interface to the Cisco ISE pxGrid 2.0 REST API:
  https://github.com/cisco-pxgrid/pxgrid-rest-ws/wiki

The interface is specific to the requirements for integration with
MineMeld and PAN-OS.
'''

import aiohttp
# http://docs.aiohttp.org/en/stable/client_reference.html#hierarchy-of-exceptions
from aiohttp import ClientError
from asyncio import TimeoutError
import logging
import ssl

from gridmeld.util.mixin import UtilMixin
from gridmeld import DEBUG1, DEBUG2, DEBUG3


class PxgridRestError(Exception):
    pass


class RequiredArgsError(PxgridRestError):
    pass


class PxgridRest(UtilMixin):
    def __init__(self,
                 loop=None,
                 hostname=None,
                 nodename=None,  # username
                 cert=None,
                 password=None,
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
            raise PxgridRestError(e)
        self._log(DEBUG2, 'ssl: %s %s', self.ssl.verify_mode,
                  self.ssl.check_hostname)
        self.session = self._session(loop=loop, timeout=timeout_)
        self.uri = None
        self.hostname = hostname
        self.nodename = nodename
        self.password = password
        self.secret = secret
        self.cert = cert

    async def __aenter__(self):
        self._log(DEBUG1, '%s', '__aenter__')
        return self

    async def __aexit__(self, *args):
        self._log(DEBUG1, '%s', '__aexit__')
        if not self.session.closed:
            self._log(DEBUG1, 'closing aiohttp session')
            await self.session.close()

    async def _uri(self):
        if self.hostname is None:
            raise RequiredArgsError('hostname required')

        while True:
            x = self.hostname.pop(0)
            self.uri = 'https://' + x + ':8910'
            try:
                resp = await self.version()
            except (ClientError, TimeoutError):
                if not self.hostname:
                    raise
            else:
                if resp.status == 200:
                    data = await resp.text()
                    self._log(DEBUG1, '%s', data)
                    break

    # https://developer.cisco.com/docs/pxgrid-api/#!overview/cisco-ise-implementation
    async def version(self):
        path = '/pxgrid/control/version'
        if self.uri is None:
            await self._uri()
        url = self.uri + path

        kwargs = {
            'url': url,
            'ssl': self.ssl,
        }

        resp = await self.session.get(**kwargs)
        return resp

    # https://github.com/cisco-pxgrid/pxgrid-rest-ws/wiki/pxGrid-Consumer#accountcreate
    async def account_create(self):
        path = '/pxgrid/control/AccountCreate'
        if self.uri is None:
            await self._uri()
        url = self.uri + path

        if self.nodename is None:
            raise RequiredArgsError('nodename required')

        json = {}
        json['nodeName'] = self.nodename

        kwargs = {
            'url': url,
            'ssl': self.ssl,
            'json': json,
        }

        resp = await self.session.post(**kwargs)
        return resp

    # https://github.com/cisco-pxgrid/pxgrid-rest-ws/wiki/pxGrid-Consumer#accountactivate
    async def account_activate(self,
                               description=None):
        path = '/pxgrid/control/AccountActivate'
        if self.uri is None:
            await self._uri()
        url = self.uri + path

        if self.nodename is None:
            raise RequiredArgsError('nodename required')

        if self.cert is None:
            if self.password is None:
                raise RequiredArgsError('cert or password required')
            auth = aiohttp.BasicAuth(self.nodename, self.password)
        else:
            auth = aiohttp.BasicAuth(self.nodename, '')

        json = {}
        if description is not None:
            json['description'] = description

        kwargs = {
            'url': url,
            'ssl': self.ssl,
            'auth': auth,
            'json': json,
        }

        resp = await self.session.post(**kwargs)
        return resp

    # https://github.com/cisco-pxgrid/pxgrid-rest-ws/wiki/pxGrid-Consumer#servicelookup
    async def service_lookup(self,
                             name=None):
        path = '/pxgrid/control/ServiceLookup'
        if self.uri is None:
            await self._uri()
        url = self.uri + path

        if self.nodename is None:
            raise RequiredArgsError('nodename required')

        if self.cert is None:
            if self.password is None:
                raise RequiredArgsError('cert or password required')
            auth = aiohttp.BasicAuth(self.nodename, self.password)
        else:
            auth = aiohttp.BasicAuth(self.nodename, '')

        json = {}
        if name is not None:
            json['name'] = name

        kwargs = {
            'url': url,
            'ssl': self.ssl,
            'auth': auth,
            'json': json,
        }

        resp = await self.session.post(**kwargs)
        return resp

    # https://github.com/cisco-pxgrid/pxgrid-rest-ws/wiki/pxGrid-Consumer#accesssecret
    async def access_secret(self,
                            peernode=None):
        path = '/pxgrid/control/AccessSecret'
        if self.uri is None:
            await self._uri()
        url = self.uri + path

        if self.nodename is None:
            raise RequiredArgsError('nodename required')
        if self.password is None:
            raise RequiredArgsError('password required')

        auth = aiohttp.BasicAuth(self.nodename, self.password)

        json = {}
        if peernode is not None:
            json['peerNodeName'] = peernode
        else:
            raise RequiredArgsError('peernode required')

        kwargs = {
            'url': url,
            'ssl': self.ssl,
            'auth': auth,
            'json': json,
        }

        resp = await self.session.post(**kwargs)
        return resp

    # https://github.com/cisco-pxgrid/pxgrid-rest-ws/wiki/Session-Directory#post-restbaseurlgetsessions
    async def get_sessions(self,
                           restbaseurl=None,
                           starttime=None):
        path = '/getSessions'
        if restbaseurl is not None:
            url = restbaseurl + path
        else:
            raise RequiredArgsError('restbaseurl required')

        if self.nodename is None:
            raise RequiredArgsError('nodename required')

        if self.cert is None:
            if self.secret is None:
                raise RequiredArgsError('cert or secret required')
            auth = aiohttp.BasicAuth(self.nodename, self.secret)
        else:
            auth = aiohttp.BasicAuth(self.nodename, '')

        json = {}
        if starttime is not None:
            json['startTimestamp'] = starttime

        kwargs = {
            'url': url,
            'ssl': self.ssl,
            'auth': auth,
            'json': json,
        }

        resp = await self.session.post(**kwargs)
        return resp

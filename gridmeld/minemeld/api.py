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
import logging

from gridmeld.util.mixin import UtilMixin
from gridmeld import DEBUG1, DEBUG2, DEBUG3


class MinemeldApiError(Exception):
    pass


class RequiredArgsError(MinemeldApiError):
    pass


class MinemeldApi(UtilMixin):
    def __init__(self,
                 loop=None,
                 uri=None,
                 username=None,
                 password=None,
                 verify=None,
                 timeout=None):
        self._log = logging.getLogger(__name__).log
        self._log(DEBUG2, 'aiohttp version: %s', aiohttp.__version__)

        self.uri = uri
        timeout_ = self._timeout(timeout)
        self._log(DEBUG2, 'timeout: %s', timeout_)
        try:
            self.ssl = self._ssl_context(verify)
        except ValueError as e:
            raise MinemeldApiError(e)
        self._log(DEBUG2, 'ssl: %s %s', self.ssl.verify_mode,
                  self.ssl.check_hostname)
        auth = self._auth(username, password)
        self.session = self._session(loop, auth=auth, timeout=timeout_)

    async def __aenter__(self):
        self._log(DEBUG1, '%s', '__aenter__')
        return self

    async def __aexit__(self, *args):
        self._log(DEBUG1, '%s', '__aexit__')
        if not self.session.closed:
            self._log(DEBUG1, 'closing aiohttp session')
            await self.session.close()

    def _auth(self, username, password):
        if username is None:
            raise RequiredArgsError('username required')
        if password is None:
            raise RequiredArgsError('password required')
        return aiohttp.BasicAuth(username, password)

    async def status(self):
        path = '/status/minemeld'
        url = self.uri + path

        kwargs = {
            'url': url,
            'ssl': self.ssl,
        }

        resp = await self.session.get(**kwargs)
        return resp

    async def info(self):
        path = '/status/info'
        url = self.uri + path

        kwargs = {
            'url': url,
            'ssl': self.ssl,
        }

        resp = await self.session.get(**kwargs)
        return resp

    async def get_indicators(self, node=None):
        if node is None:
            raise RequiredArgsError('node required')
        type = 'localdb'
        path = f'/config/data/{node}_indicators?h={node}&t={type}'
        url = self.uri + path

        kwargs = {
            'url': url,
            'ssl': self.ssl,
        }

        resp = await self.session.get(**kwargs)
        return resp

    async def append_indicators(self, node=None, json=None):
        if node is None:
            raise RequiredArgsError('node required')
        type = 'localdb'
        path = f'/config/data/{node}_indicators/append?h={node}&t={type}'
        url = self.uri + path

        kwargs = {
            'url': url,
            'ssl': self.ssl,
            'json': json,
        }

        resp = await self.session.post(**kwargs)
        return resp

    async def delete_indicator(self, node=None, indicator=None, type=None):
        if node is None:
            raise RequiredArgsError('node required')
        if indicator is None:
            raise RequiredArgsError('indicator required')
        if type is None:
            raise RequiredArgsError('type required')

        json = {
            'indicator': indicator,
            'type': type,
            'ttl': 0
        }

        resp = await self.append_indicators(node, json)
        return resp

    async def delete_all_indicators(self, node=None):
        resp = await self.get_indicators(node)
        if resp.status >= 400:
            return resp

        result = await resp.json()
        if not result['result']:
            return resp

        for x in result['result']:
            x['ttl'] = 0

        resp = await self.append_indicators(node=node,
                                            json=result['result'])
        return resp

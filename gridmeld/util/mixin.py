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
import ssl

from gridmeld import DEBUG1, DEBUG2, DEBUG3


class UtilMixin:
    def _timeout(self, timeout):
        if timeout is None:
            return

        if isinstance(timeout, tuple):
            x = aiohttp.ClientTimeout(sock_connect=timeout[0],
                                      sock_read=timeout[1])
        else:
            x = aiohttp.ClientTimeout(total=timeout)

        return x

    def _ssl_context(self, verify, cert=None):
        context = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
        if cert is not None:
            try:
                context.load_cert_chain(certfile=cert)
            except (FileNotFoundError, ssl.SSLError) as e:
                raise ValueError('%s: %s' % (cert, e))

        if isinstance(verify, bool):
            if not verify:
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
        elif verify is not None:
            try:
                context.load_verify_locations(cafile=verify)
            except (FileNotFoundError, ssl.SSLError) as e:
                raise ValueError('%s: %s' % (verify, e))

        return context

    def _session(self, loop=None, auth=None, timeout=None):
        async def on_request_start(session, trace_config_ctx, params):
            log = logging.getLogger(__name__).log
            log(DEBUG2, '%s %s', params.method, params.url)
            for k, v in params.headers.items():
                log(DEBUG3, '%s: %s', k, v)

        async def on_request_end(session, trace_config_ctx, params):
            log = logging.getLogger(__name__).log
            log(DEBUG1, '%s %s %s %s %s',
                params.method,
                params.url,
                params.response.status,
                params.response.reason,
                params.response.headers.get('content-length'))
            for k, v in params.response.headers.items():
                log(DEBUG3, '%s: %s', k, v)

        kwargs = {
            'loop': loop,
        }
        if auth is not None:
            kwargs['auth'] = auth
        if timeout is not None:
            kwargs['timeout'] = timeout

        if (logging.getLogger(__name__).getEffectiveLevel() in
           [DEBUG1, DEBUG2, DEBUG3]):
            trace_config = aiohttp.TraceConfig()
            trace_config.on_request_start.append(on_request_start)
            trace_config.on_request_end.append(on_request_end)
            kwargs['trace_configs'] = [trace_config]

        return aiohttp.ClientSession(**kwargs)

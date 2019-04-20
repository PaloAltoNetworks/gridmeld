``gridmeld`` Release History
============================

0.2.0 (2019-04-20)
------------------

- pxgrid/wsstomp.py: Log number of session objects from get_sessions()
  when PxgridWsStomp.subscribe(get_sessions=True).

- meld.py, minemeld/api.py: Add /status/info API request which
  contains MineMeld version.

- gate.py: Log gridmeld, MineMeld and pxGrid version at startup.

- pxgrid/wsstomp.py: Use aiohttp.ClientWebSocketResponse.receive()
  vs. receive_bytes() to capture websocket close types for logging
  peer closed message.

- gate.py: Discard session object if empty ipAddresses array and log
  at warning.  Change no ipAddresses to log at warning.

- gate.py: Add --replay option to replay pxGrid session objects;
  useful for testing.

- gate.py: Use "invalid IP" in log message consistently.

0.1.0 (2019-03-31)
------------------

- gate.py: Discard session object if no state key and log at level
  error.

- gate.py: ipAddresses key is optional in session object.  Fixes
  KeyError exception.  Log at level info.

- Documentation updates.

- gate.py: Fix exception usage, should be PxgridWsStompError.

0.0.0 (2018-12-08)
------------------

- First release.

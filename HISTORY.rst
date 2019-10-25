``gridmeld`` Release History
============================

0.6.0 (2019-10-25)
------------------

- gate.py: Add "include_networks" and "exclude_networks" to MineMeld
  session processing policy (--policy object).

- gate.py: Only log SDB size when updated by event.  Prevents log when
  event discarded by policy.

- gate.py: Apply session policy to event states not processed so 'no
  action on event' logged only when IP matches policy.

0.5.0 (2019-07-20)
------------------

- gate.py: Log Python version and operating system information at
  startup.

- gate.py: Fix command line --pxgrid --hostname and --nodename
  options: swapped logic and missing long option.

- setup.py, admin-guide.rst: Support Python 3.7.

- Documentation updates.

- gate.py: Log timestamp field from session for skipped events.

0.4.0 (2019-07-03)
------------------

- gate.py: Add "gate.py --minemeld --policy path" option to allow
  customization of MineMeld session processing policy.

- Documentation updates.

- gate.py: Add gate.py -T option to add time to default stderr log
  format.

- gate.py: In loop_main() when FIRST_COMPLETED or receive
  CancelledError, loop through other tasks and wait for them to
  re-raise CancelledError.  Addresses periodic "asyncio Task was
  destroyed but it is pending!" on exit.

- admin-guide.rst, README.rst: Update MineMeld configuration
  documentation to use dagPusherNg.  This is available in MineMeld
  0.9.62 and contains a number of functional and performance
  enhancements made to the legacy node.

0.3.0 (2019-06-15)
------------------

- gate.py: Append indicator to localDB if SGT or user in session.
  Previously only pushed if SGT in session.

- pxgrid/wsstomp.py: Log message prior to reading events from session
  topic.

- gate.py, pxgrid/wsstomp.py: Instead of deleting all indicators from
  the localdb node at startup, perform a simple sync of existing
  localdb indicators with bulk session download.

- Documentation updates.

- admin-guide.rst: Add section for recommended system configuration
  tasks on Ubuntu 18.04.

- pxgrid/stomp.py, pxgrid/wsstomp.py:

  In ISE 2.4.0.357 Cumulative Patch 8 some StompCommand.MESSAGE frames
  with content-length header can include the trailing NULL in the
  content-length, resulting in a message body with trailing NULL.
  Result is "json.decoder.JSONDecodeError: Extra data: xxx" exception
  from json.loads() with the object.  Detect this and strip the NULL.
  Add warning logging to detect this and other invalid conditions.

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

gridmeld - Cisco ISE pxGrid to Palo Alto Networks MineMeld Gateway
==================================================================

``gridmeld`` is a Python3 application which consumes session data from
the Cisco ISE pxGrid service, and publishes IP indicators to Palo Alto
Networks MineMeld for consumption by PAN-OS.

The pxGrid 2.0 REST and WebSocket APIs available in ISE 2.4 are used
to perform bulk session download, and subscribe to session directory
updates.  Sessions are synchronized to a MineMeld ``localDB`` miner
using the MineMeld config API as IPv4 or IPv6 indicators with a
TrustSec Security Group Tag (SGT).  The miner is connected to a
``dagPusherNg`` output node which will push IP-SGT mappings to PAN-OS as
``registered-ip`` objects, which can be used to configure Dynamic
Address Groups (DAGs) for security policy enforcement.

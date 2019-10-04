gridmeld Administrator's Guide
==============================

.. contents::

Overview
--------

``gridmeld`` is a
`Cisco ISE
<https://www.cisco.com/c/en/us/products/security/identity-services-engine/index.html>`_
pxGrid to Palo Alto Networks
`MineMeld
<https://www.paloaltonetworks.com/products/secure-the-network/subscriptions/minemeld>`_
gateway application.

MineMeld is an extensible Threat Intelligence processing framework and
the *multi-tool* of threat indicator feeds.

Cisco ISE 2.4 provides
`REST and WebSocket APIs
<https://developer.cisco.com/docs/pxgrid/#!introduction-to-pxgrid-2-0>`_
for pxGrid.
`Sample Python programs
<https://github.com/cisco-pxgrid/pxgrid-rest-ws/tree/master/python>`_
are provided which use the APIs,
and
`API documentation
<https://github.com/cisco-pxgrid/pxgrid-rest-ws/wiki>`_
is provided in a GitHub Wiki.

``gridmeld`` is a Python3 application which uses these APIs to consume
session data from the ISE pxGrid service, and publish IP indicators to
MineMeld for consumption by PAN-OS.  Sessions containing a TrustSec
Security Group Tag (SGT) can be pushed by MineMeld to PAN-OS as
``registered-ip`` objects representing an IP-SGT mapping. The objects
can then be used to configure Dynamic Address Groups (DAGs) for
security policy enforcement.  PAN-OS 9.0 has been enhanced to update
DAGs immediately, compared to a delay of up to 60 seconds in previous
versions, and ``registed-ip`` object capacity has been increased.

``gridmeld`` is non-blocking (using
`asyncio <https://docs.python.org/3/library/asyncio.html>`_)
and consuming session directory updates over WebSocket results
in near real-time correlation of ISE IP-SGT to PAN-OS security
policy.


gridmeld
--------

Install gridmeld
~~~~~~~~~~~~~~~~

The ``gridmeld`` source repository is hosted on GitHub at
`https://github.com/PaloAltoNetworks/gridmeld
<https://github.com/PaloAltoNetworks/gridmeld>`_.
It is available as a
`release <https://github.com/PaloAltoNetworks/gridmeld/releases>`_
on GitHub and as a
`package <https://pypi.org/project/gridmeld/>`_
on PyPi for installing with
`pip <https://pip.pypa.io/en/stable/installing/>`_.

``gridmeld`` should run on any Unix system with Python 3.6 or 3.7, and
has been tested on OpenBSD 6.5 and Ubuntu 18.04.  Its module
dependencies are ``aiohttp`` and ``tenacity``.

gridmeld Command Line Programs
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

``gridmeld`` provides 3 command line programs:

- ``grid.py``

  Command line client to the pxGrid API requests used by ``gridmeld``.
  This can be used for testing and troubleshooting, and to create and
  activate clients for username/password authentication, and activate
  clients for client certificate authentication.

- ``meld.py``

  Command line client to the MineMeld config API requests used by
  ``gridmeld`` to update ``localDB`` miner indicators.

- ``gate.py``

  Gateway application to consume session directory data from pxGrid
  and publish IP indicators to a MineMeld ``localDB`` miner node.

Command options can be displayed using ``--help`` (e.g.,
``gate.py --help``).

Cisco ISE pxGrid
----------------

ISE must be configured for pxGrid.  By default pxGrid is disabled and
can be enabled at Administration->Deployment->Deployment Nodes
List-> *your ISE node*.

The ``grid.py`` and ``gate.py`` pxGrid clients can use either SSL
client certificate authentication or username/password
authentication.

.. note:: ISE 2.4 or greater is required.  ``gridmeld`` has been
          tested with ISE 2.4.0.357.

          A pxGrid 2.0
	  `test-bed ISO image
	  <https://developer.cisco.com/fileMedia/download/36c70887-c7bd-46b0-93c6-c6778ca62bd7>`_
	  is available from the
	  `getting started
	  <https://developer.cisco.com/docs/pxgrid/#getting-started>`_
	  section of the documentation.

Export the ISE Certificate Services Root CA
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The ``grid.py`` and ``gate.py --verify`` option is used to specify a
trusted CA certificate, or to disable server certificate
verification::

  $ grid.py --hostname ise-2.santan.local --xversion
  ClientConnectorSSLError: Cannot connect to host ise-2.santan.local:8910 ssl:<ssl.SSLContext object at 0x66adb6d2898> [[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed (_ssl.c:781)]

.. note:: The pxGrid version API request does not require client
	  authentication.

Verification fails because we do not have the trusted CA certificate.
``--verify no`` can be used to disable verification::

  $ grid.py --verify no --hostname ise-2.santan.local --xversion -j
  version: 200 OK None
  "2.0.0.13"

To obtain the trusted CA certificate, export the *Certificate Services
Root CA* at Administration->System->Certificates->Certificate
Authority->CA Certificates.  With this CA certificate saved as
``ise-ca.pem`` we can verify the pxGrid SSL server certificate::

  $ grid.py --verify ise-ca.pem --hostname ise-2.santan.local --xversion -j
  version: 200 OK None
  "2.0.0.13"

Using pxGrid Client Certificate Authentication
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

`Client certificate authentication
<https://developer.cisco.com/docs/pxgrid/#!generating-certificates/generating-certificates>`_
can be used to authenticate the pxGrid client.
It is configured with the following steps:

#. Generate a key pair and public key certificate.

#. Convert the PKCS12 format file to PEM with no passphrase.

#. Activate the account using the ``AccountActivate`` API request;
   this places the account in the *PENDING* state.

#. The ISE administrator approves the account (unless automatic
   approval is enabled); this places the account in the *ENABLED*
   state.

.. note:: Existing certificates can be viewed at
          Administration->System->Certificates->Certificate
          Authority->Issued Certificates.

Example: Certificate Account Creation
.....................................

#. Generate client certificate.

   pxGrid certificates are generated at Administration->pxGrid
   Services->Certificates.  Here you should:

   - Generate a single certificate (without a certificate signing
     request).
   - Specify the username for the Common Name (CN).
   - Specify PKCS12 format.
   - Create the certificate.

   This exports a ZIP file containing a PKCS12 format file with the
   client public key certificate and private key::

     $ unzip 1544027591204_cert.zip
     Archive:  1544027591204_cert.zip
       inflating: paloalto04_.p12

#. Convert the PKCS12 format file to PEM.

   The PKCS12 key file is converted to PEM with no passphrase using the
   OpenSSL command line tool::

     $ openssl pkcs12 -in paloalto04_.p12 -out paloalto04-nopw.pem -nodes
     Enter Import Password:
     MAC verified OK

     $ ls -l paloalto04-nopw.pem
     -rw-r--r--  1 ksteves  ksteves  11301 Dec  5 09:47 paloalto04-nopw.pem

   .. note::  The openssl ``-nodes`` argument means *no DES*.

   This certificate file can be used for the ``grid.py`` and ``gate.py
   --cert`` argument.

#. Activate account.

   Use the ``grid.py`` program to activate the account using the
   ``AccountActivate`` API request with the client certificate file::

     $ grid.py --verify ise-ca.pem --hostname ise-2.santan.local --activate -j --nodename paloalto04 --cert paloalto04-nopw.pem --desc 'test certificate account'
     account_activate: 200 OK None
     {
       "accountState": "PENDING",
       "version": "2.0.0.13"
     }

#. Approve account.

   The ISE administrator approves the account at
   Administration->pxGrid Services->All Clients.

   The approval can be verified by performing another activate
   request; the state should now be *ENABLED*::

     $ grid.py --verify ise-ca.pem --hostname ise-2.santan.local --activate -j --nodename paloalto04 --cert paloalto04-nopw.pem
     account_activate: 200 OK None
     {
       "accountState": "ENABLED",
       "version": "2.0.0.13"
     }

Using pxGrid Username/Password Authentication
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

`Username/Password authentication
<https://developer.cisco.com/docs/pxgrid/#!using-pre-shared-keys>`_
is an alternative to client certificate authentication.

A pxGrid client account is configured with the following steps:

#. Create the account using the ``AccountCreate`` API request;
   this provides a *password*.

   .. note:: In order to allow a pxGrid client to register itself and
             create the account via the REST API, you must enable
             *Allow password based account creation* at
             Administration->pxGrid Services->Settings; by default
             this is disabled.  This can be disabled after the account
             is created.

#. Activate the account using the ``AccountActivate`` API request;
   this places the account in the *PENDING* state.

#. The ISE administrator approves the account (unless automatic
   approval is enabled); this places the account in the *ENABLED*
   state.

#. Obtain a shared secret for a peer node using the ``AccessSecret``
   API request; the shared secret is unique for the REST and WebSocket
   APIs.  ``gate.py`` will determine the secret using the nodename
   (username) and password provided when username/password
   authentication is specified.

Example: Username/Password Account Creation
...........................................

#. Create account.
   ::

     $ grid.py --verify ise-ca.pem --hostname ise-2.santan.local --create -j --nodename paloalto03
     account_create: 200 OK None
     {
       "nodeName": "paloalto03",
       "password": "jtKm2m3VNdd2xYiF",
       "userName": "paloalto03"
     }

#. Activate account.
   ::

     $ grid.py --verify ise-ca.pem --hostname ise-2.santan.local --activate -j --nodename paloalto03 --password jtKm2m3VNdd2xYiF --desc 'test account'
     account_activate: 200 OK None
     {
       "accountState": "PENDING",
       "version": "2.0.0.13"
     }

   You can now view the account with status *Pending* at
   Administration->pxGrid Services->All Clients.

#. Approve account.

   The ISE administrator approves the account at
   Administration->pxGrid Services->All Clients.

   The approval can be verified by performing another activate
   request; the state should now be *ENABLED*::

     $ grid.py --verify ise-ca.pem --hostname ise-2.santan.local --activate -j --nodename paloalto03 --password jtKm2m3VNdd2xYiF
     account_activate: 200 OK None
     {
       "accountState": "ENABLED",
       "version": "2.0.0.13"
     }

#. Get shared secret.

   .. note:: The shared secret is only needed when using ``grid.py``
	     with username/password authentication; ``gate.py`` will
	     automatically obtain the shared secrets using the
	     provided password.

   The password is used to obtain a shared secret for a peer node.
   The peer nodename depends on the service name, which is
   *com.cisco.ise.session* for the session directory service, and
   *com.cisco.ise.pubsub* for the session pubsub service.  A
   ``ServiceLookup`` API request is used to determine the peer node
   given the service name, followed by an ``AccessSecret`` API
   request to determine the shared secret::

     $ grid.py --verify ise-ca.pem --hostname ise-2.santan.local --lookup -j --nodename paloalto03 --password jtKm2m3VNdd2xYiF --name com.cisco.ise.session
     service_lookup: 200 OK None
     {
       "services": [
         {
           "name": "com.cisco.ise.session",
           "nodeName": "ise-mnt-ise-2",
           "properties": {
             "groupTopic": "/topic/com.cisco.ise.session.group",
             "restBaseURL": "https://ise-2.santan.local:8910/pxgrid/mnt/sd",
             "restBaseUrl": "https://ise-2.santan.local:8910/pxgrid/mnt/sd",
             "sessionTopic": "/topic/com.cisco.ise.session",
             "wsPubsubService": "com.cisco.ise.pubsub"
           }
         }
       ]
     }

     $ grid.py --verify ise-ca.pem --hostname ise-2.santan.local --lookup -j --nodename paloalto03 --password jtKm2m3VNdd2xYiF --name com.cisco.ise.pubsub
     service_lookup: 200 OK None
     {
       "services": [
         {
           "name": "com.cisco.ise.pubsub",
           "nodeName": "ise-pubsub-ise-2",
           "properties": {
             "wsUrl": "wss://ise-2.santan.local:8910/pxgrid/ise/pubsub"
           }
         }
       ]
     }

     $ grid.py --verify ise-ca.pem --hostname ise-2.santan.local --asecret -j --nodename paloalto03 --password jtKm2m3VNdd2xYiF --peernode ise-mnt-ise-2
     access_secret: 200 OK None
     {
       "secret": "4FhaXqreXpK1FeBW"
     }

     $ grid.py --verify ise-ca.pem --hostname ise-2.santan.local --asecret -j --nodename paloalto03 --password jtKm2m3VNdd2xYiF --peernode ise-pubsub-ise-2
     access_secret: 200 OK None
     {
       "secret": "Bx3HotDQuO7aZv36"
     }

   The secret can be verified by performing a ``getSessions`` API
   request::

     $ grid.py --verify ise-ca.pem --hostname ise-2.santan.local --nodename paloalto03 --sessions --baseurl 'https://ise-2.santan.local:8910/pxgrid/mnt/sd' --secret 4FhaXqreXpK1FeBW
     get_sessions: 200 OK None

   .. note:: You can use the ``-j`` option to display the JSON response.

Palo Alto Networks MineMeld
---------------------------

`MineMeld
<https://live.paloaltonetworks.com/t5/MineMeld/ct-p/MineMeld>`__
is an extensible Threat Intelligence processing framework and
the *multi-tool* of threat indicator feeds. Based on an extremely
flexible engine, MineMeld can be used to collect, aggregate and filter
indicators from a variety of sources and make them available for
consumption by the Palo Alto Networks security platform
and to multi-vendor peers.

.. note:: ``gridmeld`` functionality is not available as a miner
	  because MineMeld is currently implemented using Python 2.7,
	  which does not support ``asyncio``.

Install MineMeld
~~~~~~~~~~~~~~~~

You will need to install an
`on-premises MineMeld
<https://github.com/PaloAltoNetworks/minemeld/wiki/User%27s-Guide>`_
or you can use an
`AutoFocus-hosted MineMeld
<https://www.paloaltonetworks.com/documentation/autofocus/autofocus/autofocus_admin_guide/autofocus-apps/minemeld/use-autofocus-hosted-minemeld>`_
in the cloud.

.. note:: When using AutoFocus-hosted MineMeld you need to allow
          inbound API access from the cloud to your PAN-OS firewalls
          or Panoramas to allow ``registered-ip`` object updates from
	  the ``dagPusher`` output node.

MineMeld Nodes Configuration
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The configuration required is a ``localDB`` miner node connected to
a ``dagPusherNg`` output node.

``stdlib.localDB`` Miner
........................

The class ``minemeld.ft.localdb.Miner`` implements a miner with a
database containing indicators of various types (e.g., *IPv4* and
*IPv6*) and attributes for the indicators.  The ``stdlib.localDB``
prototype is used to create the miner node.

``gridmeld`` will populate the ``localDB`` node with IP indicators
from pxGrid sessions using the MineMeld config API.  The indicator
``sgt`` attribute will contain the SGT for each IP in the session.

``dagPusherNg`` Output Node
...........................

The class ``minemeld.ft.dag_ng.DagPusher`` implements an output node
which consumes indicators from an input node, in this case a
``localDB`` node, and uses the PAN-OS XML API to synchronize the
indicators as ``registered-ip`` objects on configured firewalls and
Panoramas.  The ``dagPusherNg`` prototype is used to create the output
node.

The prototype configuration specifies ``tag_attributes``, which are
the indicator attributes in ``localDB`` that will be used for the
``registered-ip`` object tags.  The configuration can also specify a
``tag_prefix`` which is used to identify tags owned by the node; the
default is ``mmld_``.  The tag name will be the concatenation of
*tag_prefix*, *tag_attribute* and *attribute*; for example:
``mmld_sgt_Employees``.

`Dynamic Address Group objects
<https://docs.paloaltonetworks.com/pan-os/9-0/pan-os-admin/policy/monitor-changes-in-the-virtual-environment/use-dynamic-address-groups-in-policy>`_
(DAGs) can be created by using the object tags in a match expression.
The DAGs can be used in a security policy as source and destination
for policy enforcement.

``dagPusher`` Implementations
.............................

There are two ``dagPusher`` implementations:

- class ``minemeld.ft.dag.DagPusher`` (prototype ``stdlib.dagPusher``)

  This is the legacy node and should only be used if you are using
  Autofocus-hosted MineMeld, or when the devices are using PAN-OS
  7.1.

- class ``minemeld.ft.dag_ng.DagPusher`` (prototype
  ``stdlib.dagPusherNg``)

  This is the next generation node and is the recommended
  implementation to use.  It contains a number of functional and
  performance enhancements made to the legacy node.  It requires
  PAN-OS 8.0 or greater.  ``dagPusherNg`` is available starting with
  MineMeld 0.9.62.

Nodes Configuration
...................

We first need to create a local prototype from the pre-defined
``stdlib.dagPusherNg`` prototype so we can add the ``sgt``
attribute to the ``tag_attributes`` config.

A ``minemeldlocal.stdlib_dagPusherNg-sgt`` prototype is created at
CONFIG->browse prototypes->Search "dagPusherNg"->select
"stdlib.dagPusherNg".  Then create a new local prototype from
``stdlib.dagPusherNg`` using **NEW** (create prototype from this) and
add a config of ``{ "tag_attributes": ["sgt"] }``.  This will result
in the following prototype in
``/opt/minemeld/local/minemeldlocal.yml`` (we named the new prototype
``stdlib_dagPusherNg-sgt``)::

  prototypes:
      stdlib_dagPusherNg-sgt:
          class: minemeld.ft.dag_ng.DagPusher
          config:
              tag_attributes:
              - sgt
          description: 'Push IP unicast indicators to PAN-OS 8.0 and greater devices
              via DAG.

              '
          development_status: EXPERIMENTAL
          indicator_types:
          - IPv4
          - IPv6
          node_type: output
          tags: []

Next we add a miner node using the ``stdlib.localDB`` prototype
at CONFIG->browse prototypes->Search "localDB"->select "stdlib.localDB",
then **CLONE** (new node from this prototype).

Then we add the output node at CONFIG->browse prototypes->Search
"stdlib_dagPusherNg-sgt"->select
"minemeldlocal.stdlib_dagPusherNg-sgt", then **CLONE** (new node from
this prototype), and specify the ``localDB`` node created above as
**INPUT** (this connects the output node to the input node).

Then **COMMIT** the configuration.

The nodes configuration, connecting the ``localDB`` miner to the
``dagPusherNg`` output node can be viewed in
``/opt/minemeld/local/config/running-config.yml``::

  nodes:
    localDB-1561848312020:
      inputs: []
      output: true
      prototype: stdlib.localDB
    stdlib_dagPusherNg-sgt-1561848485387:
      inputs:
      - localDB-1561848312020
      output: false
      prototype: minemeldlocal.stdlib_dagPusherNg-sgt

``stdlib_dagPusherNg-sgt`` Node Configuration
.............................................

The PAN-OS firewalls and Panoramas to be updated with
``registered-ip`` objects representing IP-SGT mappings are configured
in the node's **DEVICES** tab.  This updates a device list file
containing YAML.  The device list resides in the
``/opt/minemeld/local/config`` directory and is named *node*\
``_device_list.yml``, where *node* is the name of the output node::

  $ cat /opt/minemeld/local/config/stdlib_dagPusherNg-sgt-1561848485387_device_list.yml
  - {api_password: admin, api_username: admin, hostname: 192.168.1.102, name: vm-50-1}
  - {api_password: admin, api_username: admin, hostname: 192.168.1.110, name: pa-220-2}

The device list file can also be created and updated manually.
The device configuration variables are:

=========================  ========    ==============================     ==========
Variable Name              Type        Description                        Default
=========================  ========    ==============================     ==========
hostname                   string      PAN-OS hostname or IP address      null
api_username               string      user for type=keygen               null
api_password               string      password for type=keygen           null
api_key                    string      key for API requests               null
name                       string      optional friendly hostname         null
=========================  ========    ==============================     ==========

.. note::
   The device list file is a list of dictionaries.

   You must specify either ``api_key``, or ``api_username`` and
   ``api_password``.

   The **DEVICES** tab does not currently allow you to specify an ``api_key``.
   To use API keys you can update the device list file manually.

MineMeld Config API
~~~~~~~~~~~~~~~~~~~

The MineMeld config API is used to add and delete indicators in the
``localDB`` miner.  The ``meld.py`` and ``gate.py`` programs require the
URI of the MineMeld host and an admin username and password.

As a best practice it is recommended to add a ``gridmeld`` admin;
admin users are managed in the **ADMIN** tab in the MineMeld UI.

``meld.py`` and ``gate.py`` also have a ``--verify`` option to specify
the trusted CA certificate for server certificate verification.  If your
MineMeld has a self signed certificate, you can obtain it using the
OpenSSL command line tool::

  $ echo | openssl s_client -connect minemeld.santan.local:443 | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' > mm-cert.pem
  depth=0 CN = minemeld.santan.local
  verify error:num=18:self signed certificate
  verify return:1
  depth=0 CN = minemeld.santan.local
  verify return:1
  DONE

API access can be verified by performing a ``status`` API request::

  $ meld.py --verify mm-cert.pem --uri https://minemeld.santan.local --username gridmeld --password paloalto --status
  status: 200 OK 698

Running the ``gridmeld`` Gateway Application
--------------------------------------------

``gate.py`` is the ``gridmeld`` gateway application program::

  $ gate.py --help
  gate.py [options]
      --minemeld               MineMeld options follow
        --uri uri              MineMeld URI
        --username username    API username
        --password password    API password
        --node name            localDB miner node name
        --verify opt           SSL server verify option: yes|no|path
        --timeout timeout      connect, read timeout
	--policy path          JSON session processing policy object
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
      -T                       add time to default stderr log format
      --debug level            debug level (0-3)
      --version                display version
      --help                   display usage

``gate.py`` performs the following:

#. Set signal handler for **SIGINT** and **SIGTERM** for program
   termination.  ``gate.py`` will run until it receives a signal
   or encounters an unrecoverable error.

#. Parse command options.

#. Initialize MineMeld.

   * Verify ``localDB`` miner node specified using the config API.

#. Initialize pxGrid.

   * Obtain all required API parameters using the REST API (e.g.,
     obtain secret for session directory and pubsub service using
     password).

#. Invoke MineMeld and pxGrid loops, which run concurrently.

#. pxGrid loop:

   * Get existing indicators in MineMeld ``localDB`` miner node.
   * Perform bulk download of all existing sessions using the REST API.
   * Sync sessions with ``localDB`` indicators.
   * Subscribe to session directory updates using the WebSocket API.
   * Send session updates to MineMeld loop (using an asyncio queue).

#. MineMeld loop:

   * Read session events from the queue.
   * Process events according to the session policy by adding or
     deleting indicators in the ``localDB`` node.

By default ``gate.py`` logs to **stderr** and runs in the foreground.
It can run in the background by specifying the ``--daemon`` option,
and log to **syslog** using the ``--syslog`` option.  When
``--daemon`` is used certificate files must be a full path because the
current working directory is changed to root (/).

``gate.py`` requires no privilege and should not be run as root.  It
is recommended to add a new powerless no login account such as
``gridmeld`` and run ``gate.py`` as this user.

It is also recommended that ``gridmeld`` be run under a service
manager such as ``systemd`` for automatic start at system boot, and
re-start on program failure.

MineMeld and pxGrid JSON Options
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

MineMeld and pxGrid options can be specified in a JSON format file
using the ``--minemeld`` or ``--pxgrid`` option followed by the ``-F``
option; for example using the configuration discussed previously::

  $ cat gate-mm.json
  {
      "uri": "https://minemeld.santan.local",
      "username": "gridmeld",
      "password": "paloalto",
      "node": "localDB-1561848312020",
      "verify": "mm-cert.pem"
  }

  $ cat gate-ise-pw.json
  {
      "hostname": ["ise-2.santan.local"],
      "nodename": "paloalto03",
      "password": "jtKm2m3VNdd2xYiF",
      "verify": "ise-ca.pem"
  }

MineMeld Session Processing Policy
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

By default the MineMeld loop processes pxGrid session objects as
follows:

- *IPv4* and *IPv6* indicator types will be processed.

- Hosts in all IP networks are processed.

- `session object
  <https://github.com/cisco-pxgrid/pxgrid-rest-ws/wiki/Session-Directory#session-object>`_
  ``ctsSecurityGroup`` and ``userName`` fields are mapped to ``localDB``
  ``sgt`` and ``user`` attributes.

The default policy is represented by the JSON object::

  {
      "indicator_types": ["IPv4", "IPv6"],
      "include_networks": [],
      "exclude_networks": [],
      "attribute_map": {
          "ctsSecurityGroup": "sgt",
          "userName": "user"
      }
  }

The ``gate.py --minemeld --policy`` *path* option can be used to
change the default policy.  The JSON object specified will be merged
with the default policy using the Python ``dict.update()`` method
(top-level key/value pairs in the default object are overwritten
by keys in the ``--policy`` object specified).

Session Policy Examples
.......................

The following JSON object will update the default policy to include
the ``endpointOperatingSystem`` field using the ``localDB`` ``os``
attribute when it exists in a session.
::

  $ cat policy1.json
  {
      "attribute_map": {
          "ctsSecurityGroup": "sgt",
          "userName": "user",
	  "endpointOperatingSystem": "os"
      }
  }

.. note:: ``localDB`` attribute names must not begin with the
          underscore character (**_**).

The following JSON object will update the default policy to process
only *IPv4* indicator types.
::

  $ cat policy2.json
  {
      "indicator_types": ["IPv4"]
  }

The following JSON object will update the default policy to only
process (include) hosts in network 10.0.0.0/8 and not process
(exclude) hosts in networks 10.2.100.0/24 and 10.3.100.0/24.

Networks are specified as *prefix/length* and IPv4 and IPv6 networks
are allowed.  The policy match order is *include* then *exclude*, and
the empty list means *include all* and *exclude none* respectively.

.. note:: The Python `ipaddress
	  <https://docs.python.org/3/library/ipaddress.html>`_
	  module ``ip_network()`` function is used to create
	  the network object and test for hosts in the networks.

::

  $ cat policy3.json
  {
      "include_networks": ["10.0.0.0/8"],
      "exclude_networks": ["10.2.100.0/24", "10.3.100.0/24"]
  }

``gate.py`` Example
~~~~~~~~~~~~~~~~~~~
::

   $ gate.py --minemeld -F gate-mm.json --pxgrid -F gate-ise-pw.json
   INFO gate.py starting (gridmeld 0.4.0)
   INFO gate.py Python 3.7.3 OpenBSD 6.5 GENERIC.MP#1
   INFO gate.py MineMeld 0.9.60
   INFO gate.py pxGrid 2.0.0.13
   INFO gate.py MineMeld session policy {'indicator_types': ['IPv4', 'IPv6'], 'attribute_map': {'ctsSecurityGroup': 'sgt', 'userName': 'user'}}
   INFO gridmeld.pxgrid.wsstomp get_sessions(): 2 session objects
   INFO gridmeld.pxgrid.wsstomp processing events from wss://ise-3.santan.local:8910/pxgrid/ise/pubsub /topic/com.cisco.ise.session
   INFO gate.py SDB size after session sync: 2
   INFO gate.py 172.16.1.101 STARTED: {'sgt': 'Contractors', 'user': 'user101'}
   INFO gate.py SDB size: 3: indicators (up to 5): ['172.16.1.100', '172.16.1.102', '172.16.1.101']
   INFO gate.py 172.16.1.100 DISCONNECTED: {'sgt': 'Auditors', 'user': 'user100'}
   INFO gate.py SDB size: 2: indicators (up to 5): ['172.16.1.102', '172.16.1.101']
   INFO gate.py 172.16.1.101 DISCONNECTED: {'sgt': 'Contractors', 'user': 'user101'}
   INFO gate.py SDB size: 1: indicators (up to 5): ['172.16.1.102']
   INFO gate.py 172.16.1.102 DISCONNECTED: {'sgt': 'Employees', 'user': 'user102'}
   INFO gate.py SDB size: 0
   INFO gate.py 172.16.1.100 STARTED: {'sgt': 'Auditors', 'user': 'user100'}
   INFO gate.py SDB size: 1: indicators (up to 5): ['172.16.1.100']

Verify ``registered-ip`` objects are being pushed to a configured PAN-OS
system::

   admin@pa-220> show object registered-ip all

   registered IP                             Tags
   ----------------------------------------  -----------------

   172.16.1.100 #
                                            "mmld_pushed (never expire)"
                                            "mmld_sgt_Auditors (never expire)"

   172.16.1.101 #
                                            "mmld_pushed (never expire)"
                                            "mmld_sgt_Contractors (never expire)"

   ::
                                            "mmld_canary_for_resync (expire in 322 seconds)"

   172.16.1.102 #
                                            "mmld_pushed (never expire)"
                                            "mmld_sgt_Employees (never expire)"

   Total: 4 registered addresses
   *: received from user-id agent  #: persistent

When run in the foreground, ``gate.py`` is terminated with ^C (Control-C)::

   ^CINFO gate.py got SIGINT, exiting
   INFO gate.py loop_minemeld exiting
   INFO gate.py loop_pxgrid exiting
   INFO gate.py loop_main exiting
   INFO gate.py exiting

Ubuntu 18.04 Configuration
--------------------------

This section covers recommended system configuration tasks on Ubuntu
18.04.

rsyslogd
~~~~~~~~

The ``gate.py --syslog`` option is used to specify that syslog is used
for logging, and to specify the log facility to use.  On Ubuntu
`rsyslogd
<http://manpages.ubuntu.com/manpages/bionic/man8/rsyslogd.8.html>`_ is
used for system logging, and when using one of the ``local0`` through
``local7`` facilities the log file is ``/var/log/syslog``.  You can
configure ``rsyslogd`` to use another log file such as
``/var/log/gridmeld.log`` with the following steps::

  $ cat 20-gridmeld.conf
  local0.debug                    /var/log/gridmeld.log
  # Comment out the following line to allow further message processing.
  # This means you'll also get messages in /var/log/syslog.
  & stop

  $ sudo bash
  # >/var/log/gridmeld.log
  # chmod 640 /var/log/gridmeld.log
  # chown syslog:adm /var/log/gridmeld.log

  # cp 20-gridmeld.conf /etc/rsyslog.d/
  # systemctl restart rsyslog

logrotate
~~~~~~~~~

After configuring ``rsyslogd`` to log to a new log file, you should
configure it for log rotation.  Ubuntu uses
`logrotate
<http://manpages.ubuntu.com/manpages/bionic/man8/logrotate.8.html>`_
for log file rotation.  You can configure ``logrotate`` for rotation
of the new log file with the following steps::

  $ cat gridmeld
  /var/log/gridmeld.log
  {
          rotate 7
          daily
          missingok
          notifempty
          delaycompress
          compress
  }

  $ sudo cp gridmeld /etc/logrotate.d/

systemd
~~~~~~~

`systemd
<http://manpages.ubuntu.com/manpages/bionic/man1/systemd.1.html>`_ is
a system and service manager for Linux, and is the default init system
in Ubuntu since 16.04.  The following describes how to install and
enable a custom ``systemd`` service unit file on Ubuntu 18.04 for
``gate.py``.  This will start ``gate.py`` at system boot, and restart
it when it exits.

Access Control
..............

``gate.py`` will run as user ``gridmeld``, group ``gridmeld`` using
the service unit *User* and *Group* options.

Directories for configuration files will be owner root:gridmeld and
mode 750.  Configuration files will be owner root:root and mode 644.

gridmeld:gridmeld is a powerless user and group that can read the
configuration files but cannot modify them.

Create ``gridmeld`` user and group
..................................

::

  $ sudo bash
  # groupadd gridmeld
  # useradd -g gridmeld -s /usr/sbin/nologin gridmeld

Create ``/opt/gridmeld`` for Config
...................................

The following directory structure is created:

- ``/opt/gridmeld/etc/``

  Used for JSON -F config files.

- ``/opt/gridmeld/ssl/``

  Used for SSL server certificates.

- ``/opt/gridmeld/ssl/private/``

  Used for SSL private keys.

::

  # mkdir -p /opt/gridmeld/etc/
  # mkdir -p /opt/gridmeld/ssl/private/
  # find /opt/gridmeld -type d -exec chown root:gridmeld {} \;
  # find /opt/gridmeld -type d -exec chmod 750 {} \;

Sample JSON Config Files
........................

::

  $ cat gate-mm.json
  {
      "uri": "https://minemeld.santan.local",
      "username": "gridmeld",
      "password": "paloalto",
      "node": "localDB-1554312231193",
      "verify": "/opt/gridmeld/ssl/mm-cert.pem"
  }

  $ cat gate-ise.json
  {
      "hostname": ["ise-3.santan.local"],
      "nodename": "paloalto04",
      "verify": "/opt/gridmeld/ssl/ise3-ca.pem",
      "cert": "/opt/gridmeld/ssl/private/ise3-paloalto04-nopw.pem"
  }

Install JSON Config Files
.........................

Copy your JSON files for the ``--pxgrid`` and ``--minemeld -F``
options into ``/opt/gridmeld/etc/``, for example::

  $ sudo bash
  # cp gate-ise.json /opt/gridmeld/etc/
  # cp gate-mm.json /opt/gridmeld/etc/

Install SSL Certificates and Private Keys
.........................................

If you have certificate files for the ``--verify`` options, copy them
into ``/opt/gridmeld/ssl/``, for example::

  # cp ise-ca.pem /opt/gridmeld/ssl/
  # cp mm-ca.pem /opt/gridmeld/ssl/

If you are using client certificate authentication for pxGrid, copy
the SSL private key into ``/opt/gridmeld/ssl/private/``, for example::

  # cp ise-paloalto04-nopw.pem /opt/gridmeld/ssl/private/

Set File Owner and Mode
.......................

After populating the config directory you should set owner:group and
mode for the files using::

  # find /opt/gridmeld -type f -exec chown root:root {} \;
  # find /opt/gridmeld -type f -exec chmod 644 {} \;

Configure systemd gridmeld Service Unit File
............................................

Modify the ``gridmeld.service`` unit file *Environment* options as
needed for your environment::

  $ cat gridmeld.service
  [Unit]
  Description=Palo Alto Networks gridmeld Gateway
  Documentation=https://github.com/PaloAltoNetworks/gridmeld
  After=network.target

  [Service]
  Environment=PXGRID='--pxgrid -F /opt/gridmeld/etc/gate-ise.json'
  Environment=MINEMELD='--minemeld -F /opt/gridmeld/etc/gate-mm.json'
  Environment=ARGS='--syslog local0'
  Type=simple
  Restart=always
  RestartSec=10s
  User=gridmeld
  Group=gridmeld
  ExecStart=/usr/local/bin/gate.py $PXGRID $MINEMELD $ARGS

  [Install]
  WantedBy=multi-user.target

Copy the service unit file in place and verify::

  $ sudo cp gridmeld.service /lib/systemd/system

.. note:: The Polkit
	  `Local Authority
	  <http://manpages.ubuntu.com/manpages/bionic/man8/pklocalauthority.8.html>`_
	  will manage administrator authentication when required via a configuration
	  of ``AdminIdentities=unix-group:sudo``; sudo is not
	  used below for ``systemctl`` commands, although it can be used if desired.

::

  $ systemctl daemon-reload
  $ systemctl start gridmeld
  $ systemctl status gridmeld

Troubleshooting can be performed by querying the contents of
the systemd journal using
`journalctl
<http://manpages.ubuntu.com/manpages/bionic/man1/journalctl.1.html>`_::

  $ journalctl -n -u gridmeld
  $ journalctl -f -u gridmeld

Enable the service to start on boot and verify it is started after
a system reboot::

  $ systemctl stop gridmeld
  $ systemctl enable gridmeld
  $ systemctl reboot

Wait for boot, then check the service status::

  $ systemctl status gridmeld

References
----------

- `gridmeld GitHub Repository
  <https://github.com/PaloAltoNetworks/gridmeld>`_

- `Register IP Addresses and Tags Dynamically on PAN-OS
  <https://docs.paloaltonetworks.com/pan-os/9-0/pan-os-admin/policy/register-ip-addresses-and-tags-dynamically>`_

- `Use Dynamic Address Groups in Policy on PAN-OS (includes
  registered-ip object capacity for each model)
  <https://docs.paloaltonetworks.com/pan-os/9-0/pan-os-admin/policy/monitor-changes-in-the-virtual-environment/use-dynamic-address-groups-in-policy>`_

- `Palo Alto Networks MineMeld
  <https://www.paloaltonetworks.com/products/secure-the-network/subscriptions/minemeld>`_

- `MineMeld Community
  <https://live.paloaltonetworks.com/t5/MineMeld/ct-p/MineMeld>`_

- `MineMeld GitHub Repository
  <https://github.com/PaloAltoNetworks/minemeld>`_

- `pxGrid 2.0
  <https://developer.cisco.com/docs/pxgrid/#!introduction-to-pxgrid-2-0>`_

- `pxGrid 2.0 API Sample Code GitHub Repository
  <https://github.com/cisco-pxgrid/pxgrid-rest-ws>`_

- `pxGrid Whitepaper
  <https://developer.cisco.com/docs/pxgrid/#whitepaper>`_

- `ISE 2.4 test-bed ISO image
  <https://developer.cisco.com/fileMedia/download/36c70887-c7bd-46b0-93c6-c6778ca62bd7>`_

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
security policy enforcement.  PAN-OS 9.0 (currently in beta) has been
enhanced to update DAGs immediately, compared to a delay of up to 60
seconds in previous versions, and ``registed-ip`` object capacity has
been increased.

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

``gridmeld`` should run on any Unix system with Python 3.6, and has been
tested on OpenBSD 6.3 and Ubuntu 18.04.  Its module dependencies are
``aiohttp`` and ``tenacity``.

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

.. note:: ISE 2.4 or greater is required.  ``gridmeld`` has been
          tested with ISE 2.4.0.357.

ISE must be configured for pxGrid.  By default pxGrid is disabled and
can be enabled at Administration->Deployment->Deployment Nodes
List-> *your ISE node*.

The ``grid.py`` and ``gate.py`` pxGrid clients can use either SSL
client certificate authentication or username/password
authentication.

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
It is configured with the following steps:

#. Create the account using the ``AccountCreate`` API request;
   this provides a *password*.

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

.. note:: ``gridmeld`` functionality is not implemented as a miner
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

.. note:: When using AutoFocus-hosted MineMeld you will need to allow
          inbound API access from the cloud to your PAN-OS firewalls
          or Panorama to allow ``registered-ip`` object updates from
	  the ``dagPusher`` output node.

MineMeld Node Configuration
~~~~~~~~~~~~~~~~~~~~~~~~~~~

The configuration required is a ``stdlib.localDB`` miner node and a
``dagPusher`` output node as follows::

  nodes:
    localDB-1520449865122:
      inputs: []
      output: true
      prototype: stdlib.localDB
    stdlib_dagPusher-sgt-1520982676579:
      indicator_types:
      - IPv4
      - IPv6
      inputs:
      - localDB-1520449865122
      node_type: output
      output: false
      prototype: minemeldlocal.stdlib_dagPusher-sgt

The ``minemeldlocal.stdlib_dagPusher-sgt`` prototype is created by
creating a new local prototype from ``stdlib.dagPusher`` and adding a
config of ``{ "tag_attributes": ["sgt"] }``, as in the following::

  prototypes:
    stdlib_dagPusher-sgt:
        class: minemeld.ft.dag.DagPusher
        config:
            tag_attributes:
            - sgt
        description: 'Push IP unicast indicators to PAN-OS devices via DAG.

            '
        development_status: STABLE
        indicator_types:
        - IPv4
        - IPv6
        node_type: output
        tags: []

``stdlib_dagPusher-sgt`` Node Configuration
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The PAN-OS firewalls and Panoramas to be updated with
``registered-ip`` objects representing IP-SGT mappings are configured
in the node's **DEVICES** tab.  This updates a device list file
containing YAML.  The device list resides in the
``/opt/minemeld/local/config`` directory and is named *node*\
``_device_list.yml``, where *node* is the name of the output node::

  minemeld@minemeld:/opt/minemeld/local/config$ cat stdlib_dagPusher-sgt-1520982676579_device_list.yml
  - {api_password: admin, api_username: admin, hostname: 192.168.1.102, name: vm-50-1}
  - {api_password: admin, api_username: admin, hostname: 192.168.1.110, name: pa-220-2}

The device list file can also be created and updated manually.
The device configuration variables are:

=========================  ========    ==============================     ==========
Variable Name              Type        Description                        Default
=========================  ========    ==============================     ==========
hostname                   string      PAN-OS hostname                    null
api_username               string      user for type=keygen               null
api_password               string      password for type=keygen           null
api_key                    string      key for API requests               null
name                       string      optional friendly hostname         null
=========================  ========    ==============================     ==========

.. note::
   The device list file is a list of dictionaries.

   You must specify either ``api_key`` or ``api_username`` and ``api_password``.

MineMeld Config API
~~~~~~~~~~~~~~~~~~~

The MineMeld config API is used to add and delete indicators in the
``localDB`` miner.  The ``meld.py`` and ``gate.py`` programs require the
URI of the MineMeld host and an admin username and password.

As a best practice it is recommended to add a ``gridmeld`` admin;
admin users are managed in the *ADMIN* tab in the MineMeld UI.

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
        -F path                JSON options (multiple -F's allowed)
      --pxgrid                 pxGrid options follow
        --hostname hostname    ISE hostname (multiple --hostname's allowed)
        --nodename nodename    pxGrid client nodename (username)
        --password password    pxGrid client password
        --cert path            SSL client certificate file
        --verify opt           SSL server verify option: yes|no|path
        --timeout timeout      connect, read timeout
        -F path                JSON options (multiple -F's allowed)
      --syslog facility        log to syslog with facility
                               (default: log to stderr)
      --daemon                 run as a daemon
                               (default: run in foreground)
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
   * Delete all existing indicators in ``localDB`` miner node.

#. Initialize pxGrid.

   * Obtain all required API parameters using the REST API (e.g.,
     obtain secret for session directory and pubsub service using
     password).

#. Invoke MineMeld and pxGrid loops, which run concurrently.

#. pxGrid loop:

   * Perform bulk download of all existing sessions using the REST API.
   * Send existing session events to MineMeld loop (using a Queue).
   * Subscribe to session directory updates using the WebSocket API.
   * Send session updates to MineMeld loop.

#. MineMeld loop:

   * Read session events from queue.
   * Process *STARTED* and *DISCONNECTED* events by adding
     or deleting indicator in ``localDB`` node.

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

MineMeld and pxGrid options can be specified in a JSON format file
using the ``--minemeld`` or ``--pxgrid`` option followed by the ``-F``
option; for example using the configuration discussed previously::

  $ cat gate-mm.json
  {
      "uri": "https://minemeld.santan.local",
      "username": "gridmeld",
      "password": "paloalto",
      "node": "localDB-1520449865122",
      "verify": "mm-cert.pem"
  }

  $ cat gate-ise-pw.json
  {
      "hostname": ["ise-2.santan.local"],
      "nodename": "paloalto03",
      "password": "jtKm2m3VNdd2xYiF",
      "verify": "ise-ca.pem"
  }

``gate.py`` Example
~~~~~~~~~~~~~~~~~~~
::

   $ gate.py --minemeld -F gate-mm.json --pxgrid -F gate-ise-pw.json
   INFO gate.py starting
   INFO gate.py 172.16.1.100 STARTED: sgt=Auditors username=user100
   INFO gate.py SDB size: 1: indicators (up to 5): ['172.16.1.100']
   INFO gate.py 172.16.1.101 STARTED: sgt=Contractors username=user101
   INFO gate.py SDB size: 2: indicators (up to 5): ['172.16.1.100', '172.16.1.101']
   INFO gate.py 172.16.1.102 STARTED: sgt=Developers username=user102
   INFO gate.py SDB size: 3: indicators (up to 5): ['172.16.1.100', '172.16.1.101', '172.16.1.102']
   INFO gate.py 172.16.1.101 DISCONNECTED: sgt=Contractors username=user101
   INFO gate.py SDB size: 2: indicators (up to 5): ['172.16.1.100', '172.16.1.102']

Verify ``registered-ip`` objects are being pushed to a configured PAN-OS
system::

   admin@pa-220-2> show object registered-ip all

   registered IP                             Tags
   ----------------------------------------  -----------------

   172.16.1.100 #
                                            "mmld_pushed (never expire) "
                                            "mmld_sgt_Auditors (never expire) "

   172.16.1.102 #
                                            "mmld_pushed (never expire) "
                                            "mmld_sgt_Developers (never expire) "

   Total: 2 registered addresses
   *: received from user-id agent  #: persistent

When run in the foreground, ``gate.py`` is terminated with ^C (Control-C)::

   ^CINFO gate.py got SIGINT, exiting
   INFO gate.py exiting
   INFO gate.py loop_minemeld exiting
   INFO gate.py loop_pxgrid exiting

References
----------

- `gridmeld GitHub Repository
  <https://github.com/PaloAltoNetworks/gridmeld>`_

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
  <https://cisco.app.box.com/v/ISE-Eval>`_

  .. note:: The pxGrid 2.0 test-bed image at
	    `https://developer.cisco.com/docs/pxgrid/#getting-started
	    <https://developer.cisco.com/docs/pxgrid/#getting-started>`_
	    points to an ISE 2.2 ISO.

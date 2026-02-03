************
General APIs
************
Functions used by device module implementations and internally by PEAT.

Datastore
---------
.. automodule:: peat.data.store
   :members:
   :private-members:

High-level APIs
---------------

Scan API
^^^^^^^^
.. automodule:: peat.api.scan_api
   :members:
   :undoc-members:

Pull API
^^^^^^^^
.. automodule:: peat.api.pull_api
   :members:
   :undoc-members:

Push API
^^^^^^^^
.. automodule:: peat.api.push_api
   :members:
   :undoc-members:

Parse API
^^^^^^^^^
.. automodule:: peat.api.parse_api
   :members:
   :undoc-members:

Pillage API
^^^^^^^^^^^
.. automodule:: peat.api.pillage_api
   :members:
   :undoc-members:

Network Discovery
-----------------
.. automodule:: peat.protocols.discovery
   :members:

Address Parsing
---------------
.. automodule:: peat.protocols.addresses
   :members:

Common networking functions
---------------------------
.. automodule:: peat.protocols.common
   :members:

Communication Protocols
-----------------------

IP
^^
.. automodule:: peat.protocols.ip
   :members:

FTP
^^^
.. automodule:: peat.protocols.ftp
   :members:
   :private-members:

Telnet
^^^^^^
.. automodule:: peat.protocols.telnet
   :members:
   :private-members:

HTTP
^^^^
.. automodule:: peat.protocols.http
   :members:
   :private-members:

SNMP
^^^^
.. automodule:: peat.protocols.snmp
   :members:

Serial
^^^^^^
.. automodule:: peat.protocols.serial
   :members:

CIP
^^^
.. automodule:: peat.protocols.cip.cip_packets
   :members:
   :private-members:

ENIP
^^^^
.. automodule:: peat.protocols.enip.enip_driver
   :members:
   :private-members:

.. automodule:: peat.protocols.enip.enip_socket
   :members:
   :private-members:

.. automodule:: peat.protocols.enip.enip_packets
   :members:
   :private-members:

PCCC
^^^^
.. automodule:: peat.protocols.pccc.pccc_functions
   :members:

Utilities/common functionality
------------------------------
.. automodule:: peat.utils
   :members:

Data Utilities
--------------
.. automodule:: peat.data.data_utils
   :members:

Logging Utils
-------------
.. automodule:: peat.log_utils
   :members:

.. _settings-api:

Settings
--------
.. automodule:: peat.settings
   :no-undoc-members:

SettingsManager
^^^^^^^^^^^^^^^
.. automodule:: peat.settings_manager
   :members:
   :private-members:

Constants
---------
.. automodule:: peat.consts
   :members:

CLI internals
-------------
.. automodule:: peat.cli_main
   :members:

cli_args
^^^^^^^^
.. automodule:: peat.cli_args
   :members:

.. TODO: this is raising an exception when Sphinx tries to load it for some reason
.. Command Parsers
.. ---------------
.. .. automodule:: peat.parsing.command_parsers
..    :members:

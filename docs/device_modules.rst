*****************************
Device module implementations
*****************************
Code documentation for the :class:`~peat.device.DeviceModule` implementations included with PEAT.

.. note::
   The source code for documented classes and functions is available by clicking the ``source`` to the right of the documentation for the class or function.

Class diagram
=============
.. automod-diagram:: peat.modules

Rockwell Automation
===================

Allen-Bradley ControlLogix PLC
------------------------------
.. automodule:: peat.modules.rockwell.controllogix
   :members:
   :no-undoc-members:

Rockwell Scanning
^^^^^^^^^^^^^^^^^
.. automodule:: peat.modules.rockwell.ab_scan
   :members:

Rockwell Communications
^^^^^^^^^^^^^^^^^^^^^^^
.. automodule:: peat.modules.rockwell.clx_cip
   :members:

.. automodule:: peat.modules.rockwell.clx_http
   :members:

Rockwell Parsing
^^^^^^^^^^^^^^^^
.. automodule:: peat.modules.rockwell.ab_parse
   :members:

.. automodule:: peat.modules.rockwell.clx_relay_ladder_parser
   :members:

.. automodule:: peat.modules.rockwell.clx_string_logic_parser
   :members:

Studio5000/RSLogix 5000 L5X file parsing
----------------------------------------
.. automodule:: peat.modules.rockwell.logic_l5x
   :members:
   :no-undoc-members:

Parsing
^^^^^^^
.. automodule:: peat.modules.rockwell.l5x_parse
   :members:

Camlin
======

Totus DGA
---------
.. automodule:: peat.modules.camlin.totus
   :members:
   :no-undoc-members:

Totus HTTP
^^^^^^^^^^
.. automodule:: peat.modules.camlin.totus_http
   :members:

Fortinet
========

Fortigate Firewall
------------------
.. automodule:: peat.modules.fortinet.fortigate
   :members:
   :no-undoc-members:

General Electric
================

GE D25 RTU
----------
.. automodule:: peat.modules.ge.ge_rtu
   :members:
   :no-undoc-members:

GE Relays
---------
.. automodule:: peat.modules.ge.ge_relay
   :members:
   :no-undoc-members:

iDirect
=======

iDirect Modem
-------------
.. automodule:: peat.modules.idirect.idirect
   :members:
   :no-undoc-members:

Sandia
======

SCEPTRE Field Device
--------------------
.. automodule:: peat.modules.sandia.sceptre_fcd
   :members:
   :no-undoc-members:

Schneider Electric
==================

Modicon M340 PLC
----------------
.. automodule:: peat.modules.schneider.m340.m340
   :members:
   :no-undoc-members:

M340 parsing
^^^^^^^^^^^^
.. automodule:: peat.modules.schneider.m340.m340_parse
   :members:

M340 pulling
^^^^^^^^^^^^
.. automodule:: peat.modules.schneider.m340.m340_pull
   :members:

UMAS protocol
^^^^^^^^^^^^^
.. automodule:: peat.modules.schneider.m340.umas_packets
   :members:

.. automodule:: peat.modules.schneider.m340.umas_codes
   :members:

.. ION power meter
.. ---------------
.. .. automodule:: peat.modules.schneider.ion.ion
..    :members:
..    :no-undoc-members:

.. ION HTTP
.. ^^^^^^^^
.. .. automodule:: peat.modules.schneider.ion.ion_http
..    :members:

.. ION Telnet
.. ^^^^^^^^^^
.. .. automodule:: peat.modules.schneider.ion.ion_telnet
..    :members:

.. ION parsing
.. ^^^^^^^^^^^
.. .. automodule:: peat.modules.schneider.ion.ion_parse
..    :members:

Sage RTU
--------
.. automodule:: peat.modules.schneider.sage.sage
   :members:
   :no-undoc-members:

Sage parsing
^^^^^^^^^^^^
.. automodule:: peat.modules.schneider.sage.sage_parse
   :members:

Sage Telnet
^^^^^^^^^^^
.. automodule:: peat.modules.schneider.sage.sage_telnet
   :members:

Sage SSH
^^^^^^^^^^^^
.. automodule:: peat.modules.schneider.sage.sage_ssh
   :members:

Sage commands
^^^^^^^^^^^^^
.. automodule:: peat.modules.schneider.sage.sage_commands
   :members:

Schweitzer Engineering Laboratories (SEL)
=========================================

SEL Relays
----------
.. automodule:: peat.modules.sel.sel_relay
   :members:
   :no-undoc-members:

SEL RTAC
--------
.. automodule:: peat.modules.sel.sel_rtac
   :members:
   :no-undoc-members:

SEL 3620 Gateway
----------------
.. automodule:: peat.modules.sel.sel_3620
   :members:
   :no-undoc-members:

Internal APIs
-------------

SELHTTP
^^^^^^^
.. automodule:: peat.modules.sel.sel_http
   :members:

SELTelnet
^^^^^^^^^
.. automodule:: peat.modules.sel.sel_telnet
   :members:

SELSerial
^^^^^^^^^
.. automodule:: peat.modules.sel.sel_serial
   :members:

SELASCII
^^^^^^^^^
.. automodule:: peat.modules.sel.sel_ascii
   :members:

General comms functions
^^^^^^^^^^^^^^^^^^^^^^^
.. automodule:: peat.modules.sel.sel_comms
   :members:

Relay Parsing
^^^^^^^^^^^^^
.. automodule:: peat.modules.sel.relay_parse
   :members:

RTAC Parsing
^^^^^^^^^^^^
.. automodule:: peat.modules.sel.rtac_parse
   :members:

Siemens
=======

SIPROTEC 7SJ6x relays
---------------------
.. automodule:: peat.modules.siemens.siprotec
   :members:
   :no-undoc-members:

Woodward
========

MicroNet Plus
-------------
.. automodule:: peat.modules.woodward.micronet
   :members:
   :no-undoc-members:

2301E Generator Controller
--------------------------
.. automodule:: peat.modules.woodward.wdw_2301e
   :members:
   :no-undoc-members:

easYgen 3500XT Genset Controller
--------------------------------
.. automodule:: peat.modules.woodward.easygen_3500xt
   :members:
   :no-undoc-members:

Windows
=======

WindowsCE
---------
.. automodule:: peat.modules.windows.WindowsCE
   :members:
   :no-undoc-members:

Internal APIs
-------------

ServLink protocol
^^^^^^^^^^^^^^^^^
.. automodule:: peat.modules.woodward.wdw_svl
   :members:

MicroNet parsing
^^^^^^^^^^^^^^^^
.. automodule:: peat.modules.woodward.parse_micronet
   :members:

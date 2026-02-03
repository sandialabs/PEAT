*******
Siemens
*******

Siemens Siprotec 7SJ6x relays
-----------------------------
.. warning::
   The PEAT Siprotec module has been tested with 7SJ61 and 7SJ64 relays. It should also work against others in the 7SJ6x family, however this has not been tested and shouldn't be relied upon.

The SIPROTEC 4 7SJ61 protection relays can be used for line protection of high and medium voltage networks with earthed (grounded), low-resistance earthed, isolated or compensated neutral point. When protecting motors, the SIPROTEC 4 7SJ61 is suitable for asynchronous machines of all sizes. The relay performs all functions of backup protection supplementary to transformer differential protection.

The relay provides control of the circuit breaker, further switching devices and automation functions. The integrated programmable logic (CFC) allows the user to implement their own functions, e.g. for the automation of switchgear (interlocking). The user is also allowed to generate user-defined messages. The flexible communication interfaces are open for modern communication architectures with control systems.

Data collection
^^^^^^^^^^^^^^^
PEAT utilizes two protocols to interrogate the Siprotec: :term:`HTTP` ("Web") and :term:`SNMP`.

HTTP
++++
Data collected via :term:`HTTP`:

- Firmware version
- "BF" number (unique hardware identifier as listed on the physical device)
- Hardware capabilities (The Machine-Readable Product Designation as listed on the physical device)
- WebMonitor version and build timestamp

This data is collected by parsing two files pulled via HTTP GET requests: ``MLFB.txt`` and ``VER.txt``. ``MLFB.txt`` contains the device's firmware version, "BF" number, and Machine-Readable Product Designation ("MLFB"). The "BF" number is a sort of serial number that we believe can be used to uniquely identify a device. The MLFB contains information about the device's capabilities, such as the type of over-current protection, installed modules, and region. ``VER.txt`` contains the version of the integrated web interface on the Ethernet module, WebMonitor, as well as a timestamp of when that version of the software was compiled.

.. note::
  The German translation of "Machine-Readable Product Designation", "Maschinenlesbare Fabrikatebezeichnung", is the source of the acronym "MLFB"

SNMP
~~~~
Data collected via :term:`SNMP`:

- Firmware version of the Ethernet module
- Model number of the Ethernet module
- System uptime (in milliseconds)
- Network statistics (such as how many incorrect SNMP authentication attempts were made, which is indicative of a network scan)
- Network mask
- Interface status

This data was collected via standard "SNMP GET" requests. Due to time constraints, it is only a subset of the wealth of information that can be collected via SNMP, as we discovered by performing SNMP "walks" and investigating the SNMP MIB files published by Siemens.

.. note::
  The SNMP functionality currently does not work reliably on the 7SJ64, since the SNMP server and configuration varies significantly between the 7SJ61 and 7SJ64. Development was started on a 7SJ61, and due to time constraints we were not able to debug and modify the functionality to work reliably on the 7SJ64.

********
Woodward
********

There are several Woodward controls supported by PEAT, including the easYgen genset controllers, the 2301E speed controller, and the MicroNet Plus. These are implemented by the PEAT modules :class:`~peat.modules.woodward.easygen_3500xt.Easygen3500XT`, :class:`~peat.modules.woodward.wdw_2301e.WDW2301E`, and :class:`~peat.modules.woodward.micronet.MicroNet`, respectively. This page documents the configuration files PEAT can parse for these devices with ``peat parse``: the files of Woodward's *ToolKit* service tool (used for the easYgen and other controls) and the tunable files of Woodward's *Control Assistant* service tool.

.. seealso::

   `Woodward ToolKit manual B37917 <https://www.woodward.com/products/wp-content/uploads/sites/3/2024/08/B37917_B.pdf>`__
      File types (chapter 2), loading settings files, and converting easYgen-3000 settings files for easYgen-3000XT controls (chapter 8)

   `Woodward application note 37572 <https://wss.woodward.com/manuals/PGC/easYgen-3000XT_series/Application_Notes/37572_how-to-create-partial-settings-files.pdf>`__
      Creating complete and partial settings files offline from a SID

   `easYgen-3400XT/3500XT-P2 technical manual B37581 <https://wss.woodward.com/manuals/PGC/easYgen-3000XT_series/easYgen-3400XT-3500XT-P2/01_Technical_Manuals/B37581_TM_easYgen-3400-3500-XT-P2_N.pdf>`__, `3400XT/3500XT-P1 manual B37580 <https://wss.woodward.com/manuals/PGC/easYgen-3000XT_series/easYgen-3400XT-3500XT-P1/01_Technical_Manuals/B37580_TM_easYgen-3400-3500-XT-P1_P.pdf>`__, and `3100XT/3200XT-P1 manual B37574 <https://wss.woodward.com/manuals/PGC/easYgen-3000XT_series/easYgen-3100XT-3200XT-P1/01_Technical_Manuals/B37574_TM_easYgen-3100-3200-XT-P1_U.pdf>`__
      Parameter lists (parameter numbers, defaults, ranges, and security levels) of the easYgen-3000XT series

   `easYgen-3400/3500 manual 37528 <https://wss.woodward.com/manuals/Legacy/easYgen-3x00/manual_easygen3400-3500_EN37528J.pdf>`__ and `easYgen-2000 configuration manual 37427 <https://www.dsf-technologies.com/wp-content/uploads/2017/04/WOODWARD_EASYGEN-2000_CONFIGURATION-MANUAL_EN_2017.pdf>`__
      Parameter lists and ToolKit file naming for the first generation easYgen-3000 and the easYgen-2000 series

   `Woodward knowledge base: factory settings files for 2301E <https://support.woodward.com/kb/articles/factory-settings-files-for-2301e>`__
      Factory default ToolKit settings files of the 2301E (application ``5418-6350``, revisions NEW to G)

   `Control Assistant manual 26775 <https://www.woodward.com/products/publication-asset/26775>`__
      Control Assistant and the tunable (``.tc``) files it saves

   `MS-NRBF: .NET Remoting Binary Format <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nrbf/>`__
      The serialization format inside ToolKit settings and tool files

   :class:`~peat.modules.woodward.easygen_3500xt.Easygen3500XT`
      PEAT :class:`~peat.device.DeviceModule` implementation for the easYgen genset controllers (scan, pull, and parse)

   :class:`~peat.modules.woodward.wdw_2301e.WDW2301E`
      PEAT :class:`~peat.device.DeviceModule` implementation for the 2301E speed controller (scan, pull, and parse of ToolKit settings files and Control Assistant tunable files)

Terminology
-----------
- :term:`ToolKit`: Woodward's Windows service tool for configuring and monitoring the easYgen genset controllers, the LS-5 and LS-6 breaker controls, the DTSC-200 transfer switch controller, the DSLC-2 and MSLC-2 synchronizers, Woodward E3 gas engine controls, and others. ToolKit saves the settings of a control to a ``.wset`` file.
- Service Interface Definition (:term:`SID`): the description of every parameter, status value, and event of a control, shipped by Woodward as a ``.sid`` file for each product, firmware release, and language. ToolKit uses it to communicate with the control. ToolKit *applications* are identified by the SID's identifier, e.g. ``5418-6722-NEW`` (easYgen-3000 and older: a Woodward software part number and revision) or ``EG3500XTP2 2.17-0_54728`` (easYgen-3000XT: a product short name, release, hotfix, and build number).
- :term:`LogicsManager`: the easYgen's programmable logic. Each LogicsManager parameter is an equation of three command variables (inputs), per-input operators (pass-through, ``Not``, ``True``, ``False``), two binary operators (``And``, ``Or``, ...), and on and off delays.
- Control Assistant: Woodward's service tool for GAP-based controls (2301E, 505, Atlas, MicroNet, and others). Its "Tunable Maintenance" feature saves the tunable values of a control to a ``.tc`` file.
- :term:`ServLink`: Woodward's proprietary service protocol, used over RS-232 and TCP (port 666) by both ToolKit and Control Assistant. PEAT scans and pulls easYgen and 2301E controls with it.

File types
----------
.. csv-table::
   :header: "Extension", "Name", "Contents", "PEAT support"
   :widths: 10, 20, 45, 25
   :align: left

   "``.wset``", "ToolKit settings file", "The complete configuration of a control (every parameter and its value), saved from a device or created offline. Binary: a 10-byte ToolKit header followed by two .NET binary serialization (:term:`NRBF`) streams.", "Parsed by :func:`~peat.modules.woodward.parse_wset.parse_wset`. All parameters are extracted with their values, defaults, ranges, units, enumerations, security levels, and ServLink handles."
   "``.sid``", "Service Interface Definition", "All parameters, status values, LogicsManager equations, enumerations, and events of a firmware release, with their defaults, ranges, and security levels. XML, either compressed (ToolKit header plus gzip) or plain (the ``.CAN.sid`` variant).", "Parsed by :func:`~peat.modules.woodward.parse_sid.parse_sid`. A SID holds parameter *definitions* and defaults, not the values configured on a device."
   "``.wtool``", "ToolKit tool file", "The ToolKit screens for a control, associated with one or more SIDs. Binary, same container as ``.wset``.", "Parsed by :func:`~peat.modules.woodward.parse_wtool.parse_wtool`. Only the tool properties, device names, and SID references are extracted. Decoding a large tool file takes several seconds."
   "``.tc``", "Control Assistant tunable file", "The tunable values of a control: tab-separated text with ``Mode``, ``Category``, ``Block Name``, ``Field Name``, ``Type``, ``Current``, ``Initial``, ``Low``, and ``High`` columns.", "Parsed by :func:`~peat.modules.woodward.wdw_tc.parse_tc`."
   "``.htm``", "ToolKit settings export", "Hierarchical or tabular HTML export of a settings file (ToolKit *File > Export*).", "Not parsed. Export the ``.wset`` instead."
   "``.msi``, ``.CONVERT.txt``, ``.eds``, ``.map``, ``.scp``", "ToolKit application package, settings conversion map, CANopen EDS, Modbus mapper file, firmware", "Published by Woodward per product and firmware release. easYgen-3000XT controls also store the application package on their internal USB mass storage.", "Not parsed. The ``.sid`` and ``.wtool`` files inside the ``.msi`` package can be extracted and parsed."

Supported devices
-----------------
The ToolKit file formats are shared by every ToolKit-based Woodward control, so :class:`~peat.modules.woodward.easygen_3500xt.Easygen3500XT` parses files for all of them, except for the settings files of the 2301E, which are parsed by :class:`~peat.modules.woodward.wdw_2301e.WDW2301E` (refer to `Module selection`_). The device model is identified from the ToolKit application identifier in the file (refer to :data:`~peat.modules.woodward.toolkit.TOOLKIT_APPLICATIONS` and :func:`~peat.modules.woodward.toolkit.identify_application`), and is reported as ``unknown`` if the identifier isn't recognized.

.. csv-table::
   :header: "Device", "Software", "Notes"
   :widths: 30, 15, 55
   :align: left

   "easYgen-3100XT, 3200XT, 3400XT, 3500XT (P1, P2, LT, LITE, and RENTAL variants); LS-6XT, GC-3400XT, DSLC-2XT, MSLC-2XT, RP-3000XT", "ToolKit 6.x/7.x", "XT-style application identifiers (``EG3500XTP2 2.17-0_54728``) are decoded into the model, release, and build. Verified with a published easYgen-3500XT-P2 SID and tool file. No public XT settings file was available for testing, and Woodward documents that XT settings files aren't compatible with earlier ones. The container format is expected to be the same."
   "easYgen-3100, 3200, 3400, 3500 (first generation); RP-3000, DSLC-2, MSLC-2", "ToolKit 3.x-6.x", "Verified with two published easYgen-3500 settings files (application ``5418-6722-NEW``, firmware 1.2102). Only known application part numbers are mapped to a model."
   "easYgen-2200, 2300, 2500; LS-5; DTSC-200; MFR 300", "ToolKit 3.x+", "Same file formats. Not tested, as no public files were found."
   "2301E digital speed/load control (ToolKit settings files)", "ToolKit", "Settings files of application ``5418-6350`` are parsed by :class:`~peat.modules.woodward.wdw_2301e.WDW2301E`. Verified with the `factory default settings files <https://support.woodward.com/kb/articles/factory-settings-files-for-2301e>`__ Woodward publishes for revisions NEW to G of the application (365 to 376 parameters each, container format version 22). The parameters are mapped to ServLink registers only (refer to `Data model`_), and the files have no LogicsManager logic."
   "Woodward E3 gas engine controls (Full Authority, Fuel Blending, Lean Burn Trim)", "ToolKit 4.x", "Verified with the settings, SID, and tool files Woodward publishes in its E3 HMI packages. These files use additional parameter types (boolean and lookup table parameters), which are supported."
   "easYgen-1000, easYgen-300, LS-4, MFR 2/11/15", "LeoPC1", "Not supported. These devices don't use ToolKit."
   "easYgen-400, 600, 800, 1400, 1600, 1700, 1800", "ToolKit-SC", "Not supported. ToolKit-SC is a separate product, and its file formats haven't been researched."
   "2301E, 505, Atlas, 723PLUS, MicroNet (Control Assistant tunable files)", "Control Assistant", "``.tc`` files are parsed by :class:`~peat.modules.woodward.wdw_2301e.WDW2301E`, except those of recognized easYgen applications, which are parsed by the easYgen module (refer to `Module selection`_). The layout was taken from PEAT's original parser, as no public example files exist."

Usage
-----
.. code-block:: bash

   # Parse a ToolKit settings file saved from an easYgen
   peat parse -d easygen ./genset-1.wset

   # Parse the example settings file (stored compressed in the repository)
   gunzip -k ./examples/devices/woodward/easygen-3500/4_MVA_Diesel_20161116.wset.gz
   peat parse -d easygen ./examples/devices/woodward/easygen-3500/4_MVA_Diesel_20161116.wset

   # Parse a SID or tool file from a ToolKit application package
   peat parse -d easygen "./EG3500XTP2 2.17-0_54728.sid"
   peat parse -d easygen ./8440-2088_M_EG3500XTP2_2.17-0_54728.wtool

   # Parse a ToolKit settings file or a Control Assistant tunable file of a 2301E
   peat parse -d wdw2301e ./5418-6350_Rev_G_default.wset
   peat parse -d wdw2301e ./2301e-tunables.tc

   # Let PEAT select the module by file contents (refer to "Module selection" below)
   peat parse ./toolkit-files/

   # Parse piped input (the file type is detected from its contents)
   cat ./genset-1.wset | peat parse -d easygen -

The files can also be parsed with the Python API:

.. code-block:: python

   from pathlib import Path

   from peat.modules.woodward.parse_wset import parse_wset
   from peat.modules.woodward.parse_sid import parse_sid

   settings = parse_wset(Path("genset-1.wset"))
   print(settings["application"]["product"], settings["num_parameters"])
   for parameter in settings["parameters"]:
       if parameter["kind"] == "logics_manager":
           print(parameter["name"], parameter["expression"])
       else:
           print(parameter["name"], parameter["value"], parameter["units"])

   sid = parse_sid(Path("EG3500XTP2 2.17-0_54728.sid"))
   print(sid["security"]["servlink"]["command_security_levels"])

Module selection
----------------
When no module is specified (``peat parse <directory>``), each file is parsed by exactly one module, selected by its contents:

- ``.wset`` settings files are parsed by :class:`~peat.modules.woodward.wdw_2301e.WDW2301E` if the application identifier in the settings header (the start of the file, refer to :func:`~peat.modules.woodward.parse_wset.wset_head_application_info`) is a 2301E application (``5418-6350``, refer to :func:`~peat.modules.woodward.toolkit.is_2301e_application`), and by :class:`~peat.modules.woodward.easygen_3500xt.Easygen3500XT` otherwise (easYgen, E3, and unknown applications).
- ``.tc`` tunable files are parsed by :class:`~peat.modules.woodward.easygen_3500xt.Easygen3500XT` if the application identifier is a recognized easYgen application (:func:`~peat.modules.woodward.toolkit.identify_application` returns the brand ``easYgen``), and by :class:`~peat.modules.woodward.wdw_2301e.WDW2301E` otherwise.
- ``.sid`` and ``.wtool`` files are parsed by :class:`~peat.modules.woodward.easygen_3500xt.Easygen3500XT`.

``.wset`` and ``.tc`` files are only selected by their contents, not by their extension, so a damaged file with one of these extensions is skipped when parsing a directory (parse it with ``-d`` to see the error). Specifying the wrong module with ``-d`` (e.g. ``-d easygen`` with a 2301E settings file, or ``-d wdw2301e`` with an easYgen settings or tunable file) results in an error that names the correct module.

Parsed data
-----------
The parsed data is saved as ``parsed-wset.json``, ``parsed-sid.json``, ``parsed-wtool.json``, or ``parsed-tc.json`` in the device's output directory. The following data is added to the device data:

- A summary of the file in ``extra.wset``, ``extra.sid``, ``extra.wtool``, or ``extra.tc``
- The parameter values in ``extra.parameters`` (a :class:`dict` of ``{parameter name: value}``)
- The application identity in the device description (brand, model, product) and firmware identifier

Settings files also populate the rest of the data model and the device logic (refer to `Data model`_ and `LogicsManager logic`_). If the file has LogicsManager equations, the logic is saved as ``logic.st`` (Structured Text) and ``logic-tc6.xml`` (PLCopen TC6 XML).

Settings files (.wset)
^^^^^^^^^^^^^^^^^^^^^^
:func:`~peat.modules.woodward.parse_wset.parse_wset` returns the container ``header``, the ``nrbf`` stream information, the ``settings_header`` (SID specification, application identifier, notes, partial settings flags), the ``application`` identity, the ``parameters``, and the LogicsManager command variable list (``logics_manager_inputs``). Each parameter record has the following fields:

.. csv-table::
   :header: "Field", "Description"
   :widths: 25, 75
   :align: left

   "``name``, ``group``, ``id``, ``label``", "The full parameter name as stored in the file (e.g. ``Config_Monitoring.Generator.Overfrequency level 2.1910 Limit``), split into its group, parameter number, and label. Internal variables without a parameter number are in the ``(internal)`` group."
   "``kind``", "``basic`` (a stored value), ``computed`` (a scaled view of a basic parameter: ``value = source * multiplier + offset``), ``bit_field`` (one bit of a basic parameter), ``logics_manager`` (a LogicsManager equation), ``lookup_table``/``array``, or ``generic`` (unknown object layout)."
   "``type``", "``integer``, ``float``, ``boolean``, ``enumerated``, ``string``, ``bit_fields``, ``bit_field``, ``logics_manager``, or ``array``."
   "``value``, ``value_text``", "The configured value converted to a Python type, and the text as stored in the file. Enumerated parameters have the option name as value and the number in ``enum_value`` with all ``options``. LogicsManager parameters have the equation as a :class:`dict` and a readable ``expression``, e.g. ``[False 00.01 LM: Flag 1] And [True 00.01 LM: Flag 1] And [True 00.01 LM: Flag 1], delay on 0 s, delay off 0 s``."
   "``initial``, ``minimum``, ``maximum``, ``units``", "The default value, range, and units from the SID descriptor."
   "``read_security_level``, ``write_security_level``, ``access_type``", "The easYgen code (password) levels required to read and change the parameter, and the SID access type."
   "``servlink_handle``, ``canopen_multiplexor``", "The ServLink handle and CANopen multiplexor of the parameter, useful for correlating with live reads from the device."
   "``source``, ``multiplier``, ``offset`` / ``base_parameter``, ``bit_position`` / ``arrays``", "Details of computed, bit field, and lookup table parameters."

Data model
^^^^^^^^^^
The contents of a settings file are mapped onto the PEAT :doc:`data model <data_model>` by :mod:`~peat.modules.woodward.easygen_data`:

.. csv-table::
   :header: "Device data", "Source", "Notes"
   :widths: 20, 35, 45
   :align: left

   "``registers``", "Every parameter with a ServLink handle or CANopen object address", "One :class:`~peat.data.models.Register` per protocol: ``servlink`` (address is the ServLink handle) and ``canopen`` (address is the SDO object ``index:subindex``, e.g. ``0x26A6:01`` for parameter 1702, which matches the object in Woodward's CANopen EDS files). The configured value, default, units, kind, and security levels are in ``extra``. SIDs produce the same registers without values."
   "``tag``", "LogicsManager command variable list and AnalogManager data source list", "``binary`` tags for the ~680 command variables (``03.05 Horn``) and ``analog`` tags for the ~240 data sources (``01.01 Gen.volt.L-N [%]``), with the variable number as address."
   "``io``", "``Config_IO`` discrete and analog inputs and outputs, including external I/O", "One :class:`~peat.data.models.IO` per point (``DI 01``, ``DO 03``, ``AI 02``, ``AO 01``, ``External DO 21``) with all of its settings in ``extra``. Relay outputs are named after their LogicsManager parameter (``Relay 3``) and have the equation as description."
   "``interface``", "``Config_Serial1``/``2`` (baudrate, parity, stop bits), ``Config_CAN1``..``3`` (baudrate), Ethernet IP/subnet/gateway parameters (easYgen-3000XT)", "Serial 1 is reported as RS-232 and Serial 2 (which has a duplex setting) as RS-485, as on the easYgen-3000 series."
   "``service``", "Modbus on the serial interfaces (enable flag, slave ID, protocol number), CANopen (node ID) and J1939 on the CAN interfaces", "Services are attached to their interface, and are only added when they're configured: Modbus when it's enabled (or, without an enable parameter, when a slave ID is set), CANopen when the device has a node ID on the bus, and J1939 when it's enabled or an ECU device type is selected."
   "``users``", "``Password ...`` parameters (easYgen-3000XT: basic, commissioning, super commissioning, serial and CAN interface passwords)", "The configured password is in the user's ``extra``. First generation easYgen-3000 settings files don't hold passwords. Code level settings are in ``extra.code_levels``."
   "``name``, ``geo.timezone``, ``extra``", "``Device name``, ``Time zone``, ``Device number``, ``Language`` parameters", ""
   "``logic``", "LogicsManager equations", "Refer to `LogicsManager logic`_."

Settings files of 2301E applications only get the registers (from the ServLink handles of the parameters), since the rest of the mapping relies on the parameter names of the easYgen. The counts of the objects stored are in ``extra.wset.data_model`` (``extra.sid.data_model`` for SIDs). Objects that already exist on the device (e.g. when the same file is parsed twice) are merged, not duplicated, and are included in the counts.

LogicsManager logic
^^^^^^^^^^^^^^^^^^^
The LogicsManager is the programmable logic of the easYgen: every relay output, start/stop command, alarm inhibit, flag, and so on is an equation of three command variables (boolean values of the control), per-input signs (pass-through, ``NOT``, fixed ``TRUE``/``FALSE``), two operators (``AND``, ``NAND``, ``OR``, ``NOR``, ``XOR``, ``NXOR``), and on/off delays. The encoding is documented in the easYgen manuals (manual 37528, tables 102, 103, and 117).

PEAT converts the equations in a settings file to IEC 61131-3 Structured Text and PLCopen TC6 XML (:mod:`~peat.modules.woodward.easygen_logic`), using the same :class:`~peat.parsing.tc6.TC6` class and Structured Text generator as the Schneider M340 and Rockwell PLC logic. The results are stored like PLC logic:

- ``logic.original``: a readable listing of the equations, one per line.
- ``logic.parsed`` and ``logic.formats["structured_text"]``: the Structured Text program.
- ``logic.formats["tc6"]``: the TC6 XML.

Each equation becomes a ``BOOL`` output (``LM_12310`` for parameter 12310) computed from command variables (``CV_03_02`` for command variable 03.02), with ``TON``/``TOF`` function blocks for the delays. For example, relay 3 of the example settings file, which closes 50 seconds after command variable 03.02 (the starter) becomes true:

.. code-block:: text

   (* 12310 Relay 3 [Config_IO.Discrete_Out.03] *)
   LM_12310_IN := ((CV_03_02 AND TRUE) AND TRUE);
   LM_12310_TON(IN := LM_12310_IN, PT := T#50000ms);
   LM_12310 := LM_12310_TON.Q;

Equations are chained left to right ``((sign1(cv1) op1 sign2(cv2)) op2 sign3(cv3))``, matching the order of the LogicsManager command chain in the Modbus documentation. Command variables that are the output of another equation (e.g. ``00.01 LM: Flag 1``, the output of ``12230 Flag 1``) are assigned that output right after the equation (``CV_00_01 := LM_12230;``), like the cyclic evaluation of the device, so the equations stay linked. Constant command variables (e.g. ``02.02 LM TRUE`` on the easYgen-3000XT) are assigned their value at the start of the program. The command variable names are listed as comments at the top of the program. The counts of equations, command variables, and linked and constant command variables are in ``extra.wset.logic``.

The AnalogManager (data source selections and analog setpoints) isn't converted to logic. Its data sources are available as tags and the selections as parameters.

Service Interface Definitions (.sid)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
:func:`~peat.modules.woodward.parse_sid.parse_sid` returns the following:

- The SID ``identifier``, ``specification``, and ``schema``, and the ``application`` identity
- The ServLink ``security`` configuration (accounts and command security levels)
- The top-level ``namespaces`` (``PARAMETER``, ``STATUS MENU``, ``ALARM STATUS``, ...)
- The ``parameters``: every ``DataItem``, ``LogicManager``, and ``StructureItem`` with its namespace ``path``, type, default, range, units, security levels, and communication handles
- The ``enumerations``, ``events``, and ``structures``

Compressed SIDs are decompressed up to :data:`~peat.modules.woodward.parse_sid.SID_MAX_XML_SIZE` (256 MiB). Larger files are rejected.

Tool files (.wtool)
^^^^^^^^^^^^^^^^^^^
:func:`~peat.modules.woodward.parse_wtool.parse_wtool` returns the container ``header``, the ``nrbf`` stream information, the ``tool_properties``, the tool ``name``, the ``device_names``, the ``sid_specifications`` the tool is associated with, and the ``application`` identity, which is identified from the last SID specification.

The SID specifications are unique and sorted in natural order (numbers are compared numerically, so ``EG3200XTP1 2.9-0_1`` comes before ``EG3200XTP1 2.12-0_50976`` and the newest release of a product is last). The language prefix of part number style specifications is removed (``5418-6722-NEW``, not ``us_5418-6722-NEW``).

Tunable files (.tc)
^^^^^^^^^^^^^^^^^^^
:func:`~peat.modules.woodward.wdw_tc.parse_tc` returns the file metadata (``file_version``, ``firmware_prefix``, ``firmware_date``), the nested ``config`` tree (``Mode > Category > Block Name > Field Name``) with the raw text values, and a flat ``parameters`` list with the ``current``, ``initial``, ``low``, and ``high`` values converted to Python types. Each parameter has a ``path`` (``Category/Block Name/Field Name``).

On the device, ``extra.parameters`` holds the current values as a :class:`dict` of ``{path: value}`` (the path is prefixed with the mode if two modes have the same path), and the summary of the file is in ``extra.tc``. The application identifier line of the file (e.g. ``5418-6722 NEW``) is looked up with :func:`~peat.modules.woodward.toolkit.identify_application`. If the application is known, the brand, model, and product are set. Otherwise, the brand is ``Woodward`` and the model is left to the module.

Notes and limitations
---------------------
- The model of a device is only identified when the application identifier is recognized. XT-style identifiers are always decoded. Older part number identifiers are looked up in :data:`~peat.modules.woodward.toolkit.TOOLKIT_APPLICATIONS`, which only contains the applications that could be verified from public files and manuals. Add entries there for the applications of your devices (the part number is printed on the control's nameplate and in the ``.wtool``/``.sid`` file names Woodward publishes).
- The ``.wset`` format isn't documented by Woodward. PEAT's parser was reverse engineered from published files saved by ToolKit 4.x and 5.x. Unknown object layouts are still decoded and reported using a best-effort ``generic`` parameter extraction, and the full decoded object graph is available with ``parse_wset(..., include_raw=True)``.
- The meaning of the LogicsManager operator numbers was derived empirically: pass-through (``NoOperator``), ``Not``, ``True``, and ``False`` for the per-input operators and ``And`` and ``Or`` for the binary operators were observed in files. The remaining binary operators (``Nand``, ``Nor``, ``Xor``, ``Nxor``) follow the order in the easYgen manuals and are unverified.
- Only settings files of the 2301E are parsed by the 2301E module. 2301E ``.sid`` and ``.wtool`` files (none are public) would be parsed by the easYgen module, which takes the brand and model from the application identifier.
- In settings files, parameter numbers with 1 or 2 digits aren't split from the parameter name, so such parameters have no ``id``. easYgen-3000XT SIDs define a few of them (e.g. ``60 Data Protocol 1, Mux``), but none were found in the available settings files. The SID parser recognizes them.
- Pulling settings from a live easYgen (``peat pull``) uses ServLink/TCP and FTP and doesn't produce a ``.wset`` file. Save the settings with ToolKit to parse them with PEAT.

Example files
-------------
- ``examples/devices/woodward/easygen-3500/4_MVA_Diesel_20161116.wset.gz`` and ``3_5MVA_NGGenset20161116.wset.gz``: real easYgen-3500 settings files (gzip compressed) of a 4 MVA diesel genset and a 3.5 MVA natural gas genset, from the MIT Lincoln Laboratory `EPHCC <https://github.com/PowerSystemsHIL/EPHCC>`__ project (MIT license).
- Woodward publishes `factory default settings files for the 2301E <https://support.woodward.com/kb/articles/factory-settings-files-for-2301e>`__ (``5418-6350_Rev_*_default.wset``). They aren't included in PEAT, since they're published without a license.
- Woodward publishes ToolKit application packages (``.msi`` files containing the ``.wtool`` and ``.sid`` files) for the easYgen-3000XT series on its `easYgen-3000XT document site <https://wss.woodward.com/manuals/PGC/easYgen-3000XT_series/>`__, and ``.wset``, ``.sid``, and ``.wtool`` files for its E3 engine controls in the E3 HMI packages on `woodward.com <https://www.woodward.com/products/support/software-assets/service-tool/5418-4091-hmi_a/>`__.
- No public ``.tc`` file is known. The unit tests use a hand-written example (``tests/modules/woodward/data_files/tunables_synthetic.tc``).

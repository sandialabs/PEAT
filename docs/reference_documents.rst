*******************
Reference Documents
*******************

.. toctree::
   :maxdepth: 1
   :hidden:

   sel
   siemens

.. _peat-index-reference:

PEAT Elasticsearch indices reference
====================================
.. csv-table::
   :name: PEAT Elasticsearch indices
   :header: "Index name", "Description", "Index name :doc:`configuration option <configure>`"
   :widths: 20, 55, 25
   :align: left

   "``vedar-logs``", "PEAT logging events.", ":attr:`ELASTIC_LOG_INDEX <peat.settings.Configuration.ELASTIC_LOG_INDEX>`"
   "``peat-scan-summaries``", "Scan result summaries.", ":attr:`ELASTIC_SCAN_INDEX <peat.settings.Configuration.ELASTIC_SCAN_INDEX>`"
   "``peat-pull-summaries``", "Pull result summaries.", ":attr:`ELASTIC_PULL_INDEX <peat.settings.Configuration.ELASTIC_PULL_INDEX>`"
   "``peat-parse-summaries``", "Parse result summaries.", ":attr:`ELASTIC_PARSE_INDEX <peat.settings.Configuration.ELASTIC_PARSE_INDEX>`"
   "``peat-configs``", "PEAT configurations.", ":attr:`ELASTIC_CONFIG_INDEX <peat.settings.Configuration.ELASTIC_CONFIG_INDEX>`"
   "``peat-state``", "Dumps of PEAT's internal state during a run.", ":attr:`ELASTIC_STATE_INDEX <peat.settings.Configuration.ELASTIC_STATE_INDEX>`"
   "``ot-device-hosts-timeseries``", "Information collected by PEAT from field devices or parsed files. A new Elasticsearch document is created for every pull of data from a device (the data is 'timeseries', with differences visible between pulls over time).", ":attr:`ELASTIC_HOSTS_INDEX <peat.settings.Configuration.ELASTIC_HOSTS_INDEX>`"
   "``ot-device-files``", "Information about files present on the device, or that were present on the device at one point in time.", ":attr:`ELASTIC_FILES_INDEX <peat.settings.Configuration.ELASTIC_FILES_INDEX>`"
   "``ot-device-registers``", "Information about individual communication 'registers' (e.g. Modbus registers/coils, DNP3 data points, BACNet objects, etc.) that are configured on devices, as extracted from device configuration information.", ":attr:`ELASTIC_REGISTERS_INDEX <peat.settings.Configuration.ELASTIC_REGISTERS_INDEX>`"
   "``ot-device-tags``", "Information about tag variables that are configured on devices, as extracted from device configuration information.", ":attr:`ELASTIC_TAGS_INDEX <peat.settings.Configuration.ELASTIC_TAGS_INDEX>`"
   "``ot-device-io``", "Information about I/O (Input/Output) available and/or configured on a device, as extracted from device configuration information.", ":attr:`ELASTIC_IO_INDEX <peat.settings.Configuration.ELASTIC_IO_INDEX>`"
   "``ot-device-events``", "Logging and other event history as extracted from devices. Examples include access logs, system logs, or protection history.", ":attr:`ELASTIC_EVENTS_INDEX <peat.settings.Configuration.ELASTIC_EVENTS_INDEX>`"
   "``ot-device-memory``", "Memory reads from devices, including address in memory, the value read, and information about where it came from and when the read occurred.", ":attr:`ELASTIC_MEMORY_INDEX <peat.settings.Configuration.ELASTIC_MEMORY_INDEX>`"

Command Line Interface (CLI) usage reference
============================================
.. sphinx_argparse_cli::
   :module: peat.cli_args
   :func: build_argument_parser
   :prog: peat
   :title:

PEAT configuration reference
============================
.. literalinclude:: ../examples/peat-config.yaml
   :name: PEAT configuration reference
   :language: yaml

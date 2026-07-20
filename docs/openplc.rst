.. _openplc_peat_module:

==============================
OpenPLC Runtime v4 PEAT Module
==============================

:Author: Th3BanHamm3r
:Version: 1.0
:Date: 2026-07-10

.. contents::
   :local:

Overview
========

This document provides in-depth documentation for the PEAT (PLC Enumeration and Assessment Tool) module designed for **OpenPLC Runtime v4**. The module enables discovery, fingerprinting, data collection, and program deployment on OpenPLC v4 instances via its native REST API.

For initial setup of the runtime environment, please refer to the official Autonomy Logic documentation:

.. seealso::

   * `OpenPLC Runtime v4 GitHub <https://github.com/Autonomy-Logic/openplc-runtime>`__
   * `OpenPLC Editor GitHub <https://github.com/Autonomy-Logic/openplc-editor>`__
   * `Autonomy Edge OpenPLC Documentation <https://edge.autonomylogic.com/docs/>`__
   * `OpenPLC Runtime v4 Documentation <https://github.com/Autonomy-Logic/openplc-runtime/tree/main/docs>`__
   * `OpenPLC Editor Documentation <https://github.com/Autonomy-Logic/openplc-editor/tree/main/docs>`__

PEAT Module Configuration
=========================

The ``openplcv4.py`` module uses the following configuration options within a ``config.yaml`` file.

Default Options
---------------

.. code-block:: yaml

   default_options = {
       "openplcv4": {
           "username": "",
           "password": "",
           "pull_methods": ["https"],
           "clean_upload": true,
           "plugins_to_query": {}
       },
   }

* **username/password**: Credentials for the OpenPLC v4 API. A user must be created on the runtime first.
* **pull_methods**: The module currently only supports ``https`` for data pulling.
* **clean_upload**: If ``True``, the module will instruct the runtime to wipe compilation caches before building an uploaded program.
* **plugins_to_query**: A list of plugins to query for status during a data pull. For example: ``["ethercat"]``.

Module Capabilities
===================

The module defines several core functions to interact with the OpenPLC v4 API.

Device Identification
---------------------

The module identifies OpenPLC v4 instances by sending a GET request to the ``/api/version`` endpoint. A successful response confirms the device's identity.

.. code-block:: http

   GET https://{device_ip}:8443/api/version

Refer to this tool to control the OpenPLC Runtime v4 via Python scripts in order to automate deployment and C2; no Editor needed.

.. seealso::

   * `plc4.py - OpenPLC Runtime v4 CLI Utility <https://github.com/Th3BanHamm3r/OpenPLC-Runtime-v4-CLI-Utility>`__

Data Pulling (``peat pull``)
----------------------------

When ``peat pull`` is executed, the module authenticates and systematically pulls data from various API endpoints.

**Authentication:**

1. A ``POST`` request is made to ``/api/login`` with the provided username and password.
2. A successful login returns a JWT ``access_token``.
3. This token is used as a Bearer token in the ``Authorization`` header for all subsequent requests.

**Data Endpoints:**

The module collects data from the following endpoints:

* ``GET /api/status?include_stats=true``: Retrieves the main PLC status, including run mode (``RUNNING``, ``STOPPED``), loaded program name, and detailed timing statistics for each task.
* ``GET /api/get-users-info``: Retrieves a list of all registered users and their roles.
* ``GET /api/runtime-logs``: Extracts the latest runtime logs, which are then saved as events and a log file (``openplc_runtime.log``).
* ``GET /api/compilation-status``: Extracts the status and output of the last program compilation, saved to ``compilation_status.log``.
* ``GET /api/serial-ports``: Retrieves the serial ports available on the device.
* ``POST /api/plugin-command``: If ``plugins_to_query`` is configured, this endpoint is used to send commands to specific plugins (e.g., ``ethercat status``) and retrieves their output.

Program Pushing (``peat push``)
-------------------------------

The ``peat push`` command allows for deploying a compiled program to the runtime.

1. The module authenticates to the API.
2. It sends a ``POST`` request to ``/api/upload-file`` with the valid program ``.zip`` file.
3. The ``clean`` parameter can be set to force a clean build.

Output Data Structure
=====================

The data collected by the PEAT module is structured in a JSON format, as seen in the ``device-data-full.json`` file.

Key Fields:
-----------

* **description**: General device info, including vendor ("Autonomy Logic, Inc.") and product model.
* **run_mode**: Current PLC state, e.g., "RUNNING".
* **os**: Operating system details, specifically "OpenPLC Runtime v4" and its version.
* **files**: A list of files generated during the pull, such as logs and plugin status outputs.
* **interfaces**: A list of interfaces and that the device has made available.
* **event**: A detailed log of runtime events.
* **users**: List of user accounts.
* **extra.timing_stats**: Detailed performance metrics for PLC tasks (cycle times, latency, etc.).
* **extra.plugin_status**: Contains the output from queried plugins. For example, the ``ethercat`` key holds the status of the EtherCAT master.

Example Output:
===============

1. PLC Status & Run Mode
------------------------

Basic status information dictates the core operational state of the PLC.

.. code-block:: json

    "type": "PLC",
    "run_mode": "RUNNING",
    "status": "Online",
    "os": {
        "full": "Autonomy Logic, Inc. OpenPLC Runtime v4 v4.1.7",
        "name": "OpenPLC Runtime v4",
        "vendor": {
            "name": "Autonomy Logic, Inc."
        },
        "version": "v4.1.7"
    }

2. User Information
-------------------

The ``users`` array contains all registered accounts pulled from the runtime.

.. code-block:: json

    "users": [
        {
            "id": "1",
            "name": "admin"
        }
    ]

3. Timing Statistics
--------------------

When statistics are included in the status pull, PEAT nests this performance data under the ``extra`` object.

.. code-block:: json

    "extra": {
        "timing_stats": {
            "tasks": [
                {
                    "cycle_latency_avg": 0,
                    "cycle_latency_max": 0,
                    "cycle_latency_min": 9223372036854775807,
                    "cycle_time_avg": 0,
                    "cycle_time_max": 0,
                    "cycle_time_min": 9223372036854775807,
                    "name": "TASK0",
                    "overruns": 0,
                    "scan_count": 1,
                    "scan_time_avg": 0,
                    "scan_time_max": 0,
                    "scan_time_min": 9223372036854775807
                }
            ]
        }
    }

4. File Extraction (Runtime, Compilation, & Plugin Logs)
--------------------------------------------------------

The raw ``openplc_runtime.log``, ``compilation_status.log``, and ``plugin_command.json`` are also dumped independently.

.. code-block:: json

   "files": [
        {
            "description": "Last Compilation Status",
            "device": "192.168.10.20",
            "extension": "log",
            "name": "compilation_status.log"
        },
        {
            "description": "Output for ethercat plugin (status)",
            "device": "192.168.10.20",
            "extension": "json",
            "mime_type": "application/json",
            "name": "ethercat_status.json"
        },
        {
            "description": "Runtime Logs",
            "device": "192.168.10.20",
            "extension": "log",
            "name": "openplc_runtime.log"
        }
   ]

5. Runtime Events
-----------------

PEAT parses the raw text logs from the runtime endpoint, standardizing them into the ``event`` timeline.

.. code-block:: json

   "event": [
        {
            "created": "2026-07-02 19:11:08+00:00",
            "dataset": "runtime",
            "id": "29",
            "kind": [
                "event"
            ],
            "message": "Native plugin './build/plugins/libs7comm_plugin.so' symbols loaded successfully",
            "module": "OpenPLCv4",
            "provider": "192.168.10.20",
            "severity": "INFO",
            "timezone": "UTC"
        }

6. Plugin Status (e.g., ``ethercat``)
-------------------------------------

Outputs from specific queried plugins (like ``ethercat``) are captured in their native format and nested under ``extra.plugin_status``.

.. code-block:: json

   "extra": {
       "plugin_status": {
           "ethercat": {
                "masters": [
                    {
                        "expected_wkc": 0,
                        "metrics": {
                            "avg_cycle_us": 0,
                            "avg_latency_us": 0,
                            "avg_period_us": 0,
                            "consecutive_wkc_errors": 0,
                            "cycle_count": 0,
                            "exchange_skips": 0,
                            "max_cycle_us": 0,
                            "max_exchange_us": 0,
                            "max_latency_us": 0,
                            "max_period_us": 0,
                            "min_cycle_us": 0,
                            "min_exchange_us": 0,
                            "min_latency_us": 0,
                            "min_period_us": 0,
                            "noframe_count": 0,
                            "recovery_attempts": 0,
                            "wkc_error_count": 0
                        },
                        "name": "default",
                        "plugin_state": "IDLE",
                        "slave_count": 0
                    }
                ]
            }
        }
    }

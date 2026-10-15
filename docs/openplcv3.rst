.. _openplcv3-peat-module:

==============================
OpenPLC Runtime v3 PEAT Module
==============================

.. contents::
   :local:

Overview
========

The :class:`~peat.modules.openplc.openplcv3.OpenPLCv3` module supports `OpenPLC Runtime v3
<https://github.com/thiagoralves/OpenPLC_v3>`__, the version of OpenPLC used in many
training labs and testbeds, including `GRFICSv3 <https://github.com/Fortiphyd/GRFICSv3>`__
(see :doc:`grfics_tutorial`). For OpenPLC Runtime v4, refer to :ref:`openplc_peat_module`.

OpenPLC v3 has no REST API. Everything is exposed through its Flask web interface
(HTTP, port ``8080`` by default), so the module logs in with the same form a user
would and reads the HTML pages.

The module is **read-only**. After logging in it only issues ``GET`` requests for
informational pages, and it never starts or stops the PLC, uploads or compiles
programs, writes I/O points, or changes settings. ``peat push`` is not supported.

Tested with OpenPLC v3 release ``2025-03-31`` (GRFICSv3).

Configuration
=============

.. code-block:: python

   default_options = {
       "openplcv3": {
           "username": "",
           "password": "",
           "pull_methods": ["http"],
       },
       "http": {
           "port": 8080,
       },
   }

* **username/password**: Login for the OpenPLC web interface. The OpenPLC default
  (also used by GRFICSv3) is ``openplc`` / ``openplc``.
* **pull_methods**: Only ``http`` is supported.
* **http.port**: Port of the web interface.

Example (see ``examples/peat-config-grfics.yaml`` for a complete file):

.. code-block:: yaml

   device_options:
     openplcv3:
       username: "openplc"
       password: "openplc"

Identification (``peat scan``)
==============================

PEAT requests ``GET /login`` and checks for the OpenPLC login form. The
release date shown at the bottom of the login page (e.g. ``Release: 2025-03-31``)
is saved as the OS and firmware version. No credentials are needed to scan.

Data Pulling (``peat pull``)
============================

1. ``POST /login`` with the configured username and password. A redirect to the
   dashboard means success, anything else is reported as a login failure.
2. Read the following pages. Each raw page is saved to the device's results directory
   (e.g. ``dashboard.html``) and parsed into the PEAT data model:

.. list-table::
   :header-rows: 1

   * - Page
     - Data collected
   * - ``/dashboard``
     - Run mode (``run_mode``), current program name, description, and file (``logic``)
   * - ``/programs?list_all=1``
     - Uploaded program history (``extra.programs``, ``related.files``)
   * - ``/users``
     - Web interface users: name, full name, email (``users``). Passwords are not collected.
   * - ``/modbus`` and ``/modbus-edit-device``
     - Slave (field) devices the PLC polls: name, protocol, slave ID, IP, port, and I/O ranges
       (``extra.slave_devices``, ``slave_devices.json``, ``related.ip``)
   * - ``/settings``
     - Hostname, enabled protocol servers and their ports (Modbus/TCP, DNP3, EtherNet/IP, S7)
       (``service``, ``extra.settings``)
   * - ``/hardware``
     - Selected hardware layer (``hardware.id``, ``extra.hardware_layer``)
   * - ``/monitoring``
     - Located program variables: name, data type, and address such as ``%IW100`` (``tag``)
   * - ``/runtime_logs``
     - Runtime log (``openplc_runtime.log``)

3. ``GET /logout``.

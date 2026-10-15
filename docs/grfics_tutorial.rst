.. _grfics-tutorial:

***********************************
Tutorial: PEAT with the GRFICS lab
***********************************

This tutorial walks through trying out PEAT end-to-end using only free and
open-source components running on a laptop or desktop. You will:

1. Deploy `GRFICSv3 <https://github.com/Fortiphyd/GRFICSv3>`__, an open-source
   containerized industrial control system (ICS) lab that simulates a chemical plant.
2. Run ``peat scan`` to discover the lab's PLC.
3. Run ``peat pull`` to collect the PLC's configuration, program information,
   users, I/O variables, and logs, using a pre-built PEAT configuration file.
4. Look through the results.

The PLC in GRFICSv3 is an `OpenPLC Runtime v3 <https://github.com/thiagoralves/OpenPLC_v3>`__
instance, which PEAT supports with the
:class:`~peat.modules.openplc.openplcv3.OpenPLCv3` module (see :ref:`openplcv3-peat-module`).
PEAT only reads from the PLC: it logs in to the web interface and reads
pages, it does not start or stop the PLC, upload programs, or change settings.

.. warning::
   GRFICS is an intentionally insecure training lab. Run it on a machine you
   control, and don't expose its ports to an untrusted network. Only run PEAT
   against devices you own or are authorized to assess.

Requirements
============

- A Linux, macOS, or Windows (WSL2) machine. GRFICS recommends Linux (native,
  VM, or WSL2). At least 8 GB of RAM and 20 GB of free disk space is
  recommended, the GRFICS container images total several gigabytes.
- `Docker Engine <https://docs.docker.com/engine/install/>`__ (or Docker Desktop)
  with the Docker Compose plugin (``docker compose version`` should work).
- Python 3.11, 3.12, or 3.13, and ``git``.
- A web browser (optional, for viewing the lab).

Lab network layout
------------------

GRFICSv3 runs several containers on two isolated networks. The ones relevant to this tutorial:

.. list-table::
   :header-rows: 1

   * - Container
     - Address
     - Access from your machine
     - Credentials
   * - PLC (OpenPLC v3)
     - ``192.168.95.2`` (ICS network ``192.168.95.0/24``)
     - http://localhost:8080
     - ``openplc`` / ``openplc``
   * - 3D plant simulation (Modbus field devices)
     - ``192.168.95.10``-``192.168.95.15``, ``192.168.95.45``
     - http://localhost
     - none
   * - Engineering workstation
     - ``192.168.95.5``
     - http://localhost:6080
     - none
   * - HMI (ScadaLTS)
     - ``192.168.90.107`` (DMZ network ``192.168.90.0/24``)
     - http://localhost:6081
     - ``admin`` / ``admin``

The PLC polls the simulated field devices (feed valves, purge, product, tank, and
analyzer) over Modbus/TCP. PEAT will discover that relationship from the PLC's configuration.

Step 1: Deploy GRFICSv3
=======================

These steps follow the `GRFICSv3 README <https://github.com/Fortiphyd/GRFICSv3#readme>`__,
which has more detail and troubleshooting tips.

.. code-block:: bash

   mkdir grfics && cd grfics

   # Download the GRFICS compose file (uses prebuilt images from Docker Hub)
   curl -fLO https://raw.githubusercontent.com/Fortiphyd/GRFICSv3/main/docker-compose.yml

The ICS and DMZ networks use the Docker ``macvlan`` driver, which is attached to
a host network interface. The compose file assumes the interface is named
``eth0``. If your interface has a different name, edit the two ``parent: eth0``
lines near the bottom of ``docker-compose.yml``:

.. code-block:: bash

   # Linux: find the name of the interface with the default route (e.g. "enp0s3", "wlp2s0")
   ip route show default
   # Then replace "eth0" with it, for example:
   sed -i 's/parent: eth0/parent: enp0s3/' docker-compose.yml

Download the images and start the lab:

.. code-block:: bash

   docker compose pull
   docker compose up -d

   # Wait until the containers show as "healthy" (this can take a minute or two)
   docker compose ps

Verify the PLC is up by opening http://localhost:8080 in a browser and logging in
with ``openplc`` / ``openplc``. You should see the dashboard with the
"Chemical Reactor" program running. Optionally, open http://localhost to watch
the 3D chemical plant.

.. note::
   If you're running Docker as a non-root user and get ``permission denied``, either
   prefix the Docker commands with ``sudo`` or add your user to the ``docker`` group.

Step 2: Install PEAT
====================

Refer to :doc:`install` for all installation methods. OpenPLC v3 support requires a
PEAT version that includes the ``OpenPLCv3`` module. Until that is included in
a published release, install PEAT from source into a Python virtual environment:

.. code-block:: bash

   # In a new directory (not inside the grfics directory)
   git clone https://github.com/sandialabs/PEAT.git
   cd PEAT
   python3 -m venv .venv
   source .venv/bin/activate      # Windows PowerShell: .venv\Scripts\Activate.ps1
   pip install .

   # Verify PEAT works and the OpenPLC v3 module is available
   peat --version
   peat scan --list-modules       # The list should include "OpenPLCv3"

The rest of this tutorial assumes you run PEAT from the root of the PEAT
repository, so the configuration file is at ``examples/peat-config-grfics.yaml``.
If you installed PEAT another way, download the file from the repository
(``examples/peat-config-grfics.yaml``) and adjust the paths below.

The pre-built configuration file
--------------------------------

``examples/peat-config-grfics.yaml`` contains everything PEAT needs for the lab:

.. literalinclude:: ../examples/peat-config-grfics.yaml
   :language: yaml

- ``device_options.openplcv3`` holds the PLC's web login (the GRFICS defaults).
  It applies to any OpenPLC v3 device PEAT finds.
- ``hosts`` defines two labels for the same PLC: ``grfics-plc`` (its ICS network
  address) and ``grfics-plc-local`` (the port Docker publishes on your machine).
  You can use these labels with ``-i`` instead of IP addresses.

Which address should you use?
-----------------------------

Docker's ``macvlan`` networks are isolated from the host they run on, so your
machine usually *cannot* reach ``192.168.95.2`` directly. There are two ways to
reach the PLC:

- **Option A (any OS, simplest):** target ``127.0.0.1``/``grfics-plc-local``.
  Docker publishes the PLC's web interface on ``localhost:8080``.
- **Option B (Linux, more realistic):** run PEAT from a container attached to the
  GRFICS ICS network, so it can scan the ``192.168.95.0/24`` subnet like a tool
  plugged into the plant network would. See :ref:`grfics-option-b`.

Step 3: Run a PEAT scan
=======================

A scan carefully discovers supported devices and identifies what they are.
For OpenPLC v3, PEAT requests the web login page and checks that it's an OpenPLC
runtime, and reads the OpenPLC release shown on that page.

.. code-block:: bash

   peat scan -c examples/peat-config-grfics.yaml -i grfics-plc-local

   # Equivalent, without using the host label
   peat scan -c examples/peat-config-grfics.yaml -i 127.0.0.1

You should see output similar to::

   | Protocol | Port | Reliability | Method Name                       | PEAT Module |
   | http     | 8080 |           8 | OpenPLC Runtime v3 web login page | OpenPLCv3   |
   OpenPLCv3 | Verified OpenPLC Runtime v3 on 127.0.0.1 (release: 2025-03-31)
   Completed scan of 1 device in 0.02 seconds (1 result)
   Saved scan summary to peat_results/scan_grfics-peat-config_<date>_<run id>/summaries/scan-summary.json

.. tip::
   If PEAT reports that no hosts are responding, add ``--assume-online`` (or ``-Y``)
   to skip host discovery. This is common when ``tcpdump``/``libpcap`` isn't
   installed or PEAT isn't run as root.

Step 4: Run a PEAT pull
=======================

A pull logs in to the device and collects data from it. PEAT runs a scan first
to identify the device, then pulls using the matching module.

.. code-block:: bash

   peat pull -c examples/peat-config-grfics.yaml -i grfics-plc-local

Expected output (abbreviated)::

   OpenPLCv3 | Pulling from 127.0.0.1
   OpenPLCv3 | Logging in to 127.0.0.1 as 'openplc'
   OpenPLCv3 | Finished pulling from 127.0.0.1
   Finished pulling from 1 devices in 4.45 seconds
   Saved pull summary to peat_results/pull_grfics-peat-config_<date>_<run id>/summaries/pull-summary.json

If you see ``Login failed ... Check credentials``, the username or password in
the configuration file doesn't match the PLC (for example, if you changed it in
the OpenPLC web interface).

Step 5: Look at the results
===========================

Every PEAT run creates a directory under ``./peat_results/``. For the pull:

.. code-block:: text

   peat_results/pull_grfics-peat-config_<date>_<run id>/
   ├── devices/
   │   └── grfics-plc-local/
   │       ├── device-data-full.json      # Everything PEAT knows about the PLC
   │       ├── device-data-summary.json   # Condensed version
   │       ├── device-data-*.jsonl        # One file per data type (tags, users, services, ...)
   │       ├── slave_devices.json         # Modbus field devices the PLC polls
   │       ├── openplc_runtime.log        # PLC runtime log
   │       └── *.html                     # Raw web pages PEAT read (dashboard, settings, ...)
   ├── logs/                              # PEAT's own logs (peat.log, json-log.jsonl)
   ├── peat_metadata/                     # Config and state used for the run
   └── summaries/
       ├── scan-summary.json
       └── pull-summary.json

Open ``device-data-full.json`` in an editor or browser, or explore it with
`jq <https://jqlang.org/>`__ (or ``python3 -m json.tool``):

.. code-block:: bash

   cd peat_results/pull_grfics-peat-config_*/devices/grfics-plc-local/

   # What is it, what's it running, and is it running?
   jq '{os, firmware, run_mode, logic, hardware}' device-data-full.json

   # Network services enabled on the PLC (Modbus/TCP server, web interface)
   jq '.service' device-data-full.json

   # Web interface user accounts
   jq '.users' device-data-full.json

   # Programs uploaded to the PLC (current and previous)
   jq '.extra.programs' device-data-full.json

   # The field devices the PLC communicates with over Modbus/TCP
   jq . slave_devices.json

   # The PLC program's variables and their I/O addresses
   jq -r '.tag[] | "\(.address)\t\(.type)\t\(.name)"' device-data-full.json

Example of what you'll find in the GRFICS PLC:

.. code-block:: json

   {
     "os": {"name": "OpenPLC Runtime v3", "version": "2025-03-31"},
     "run_mode": "RUNNING",
     "logic": {"name": "Chemical Reactor", "file": {"name": "326339.st"}},
     "hardware": {"id": "Blank Linux"},
     "service": [
       {"protocol": "modbus_tcp", "port": 502, "enabled": true},
       {"protocol": "http", "port": 8080, "status": "verified"}
     ],
     "users": [{"name": "openplc", "full_name": "OpenPLC User", "email": "openplc@openplc.com"}],
     "related": {
       "ip": ["192.168.95.10", "192.168.95.11", "192.168.95.12",
              "192.168.95.13", "192.168.95.14", "192.168.95.15"]
     }
   }

Things worth noticing as a defender:

- **The PLC still uses its default credentials** (``openplc``/``openplc``), which is
  exactly how PEAT logged in.
- **Modbus/TCP is enabled on port 502**, and Modbus has no authentication.
- ``related.ip`` and ``slave_devices.json`` list the **six field devices** the PLC
  talks to, discovered from a single device's configuration.
- The ``tag`` list maps the program's variables (``pressure``, ``level``,
  ``f1_valve_sp``, ...) to their I/O addresses (``%IW108``, ``%QW100``, ...),
  which is the starting point for understanding what the process does.
- ``extra.programs`` shows the upload history of PLC programs, useful for
  spotting unexpected program changes. Run the pull again later and compare.

.. _grfics-option-b:

Option B: scan the ICS network from inside the lab (Linux)
==========================================================

To scan the ICS subnet the way a tool on the plant network would, run PEAT in a
container attached to the GRFICS ICS network. The network name is prefixed with
the compose project name (the directory name, ``grfics`` in this tutorial):

.. code-block:: bash

   docker network ls | grep ics-net          # e.g. "grfics_b-ics-net"

   # From the root of the PEAT repository
   # PDM_BUILD_SCM_VERSION lets "pip install" work without git in the container
   docker run --rm -it \
     --network grfics_b-ics-net --ip 192.168.95.250 \
     -e PDM_BUILD_SCM_VERSION=0.0.0 \
     -v "$PWD:/peat" -w /peat \
     python:3.12-slim bash

   # Inside the container
   apt-get update && apt-get install -y --no-install-recommends libpcap0.8 tcpdump
   pip install --root-user-action=ignore .
   peat scan -c examples/peat-config-grfics.yaml -i 192.168.95.0/24
   peat pull -c examples/peat-config-grfics.yaml -i grfics-plc
   exit

Results are written to ``./peat_results/`` in the PEAT repository on your machine.
They are owned by root since the container ran as root; to take ownership, run
``sudo chown -R "$USER" peat_results/``.

The scan checks every address in the subnet with every PEAT module, so it takes
a few minutes. It should identify the PLC at ``192.168.95.2``.

Cleaning up
===========

.. code-block:: bash

   # In the grfics directory: stop and remove the lab, including its saved state
   docker compose down --volumes

   # Remove PEAT results when you no longer need them
   rm -rf peat_results/

Next steps
==========

- Learn about the other commands, including ``parse`` and ``heat``, in :doc:`operate`.
- Build your own configuration with ``peat config-builder``, see :doc:`configure`.
- Read :ref:`openplcv3-peat-module` for what the OpenPLC v3 module collects.
- Try the other GRFICS components: compare what PEAT collected with what you see in the
  engineering workstation (http://localhost:6080) and the HMI (http://localhost:6081).

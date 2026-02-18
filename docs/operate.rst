*******
Operate
*******
PEAT's primary interface is a command-line program with sub-commands for each function.

- ``scan``: carefully discover supported devices on a network
- ``pull``: acquire artifacts from a device, such as process logic, configuration, or firmware
- ``parse``: parse artifacts to extract useful and human-readable logic or configuration
- ``push``: push firmware, logic, or configuration to a device
- ``pillage``: search for :term:`OT` device-specific configuration and project files on a host machine
- ``heat``: extract and parse device artifacts from network traffic captures (PCAPs)

Basics
======
.. note::
   Refer to the :doc:`system requirements <system_requirements>` and :doc:`installation documentation <install>` for details on setup and installation

.. note::
   Refer to :doc:`reference_documents` for documentation of the available command line arguments

.. code-block:: bash

   # Display the command line usage for PEAT and it's commands
   # --help and -h both work to display help, as well as no arguments
   peat --help
   peat scan --help
   peat pull -h
   peat parse -h
   peat push -h
   peat pillage -h

   # Examples
   peat scan --examples
   peat pull --examples
   peat parse --examples
   peat push --examples
   peat pillage --examples
   peat heat --examples

   # The standard PEAT Linux install has a man page available
   man peat

   # Scanning
   peat scan -i 192.0.2.0/24

   # Pulling
   peat pull -i 192.0.2.0/24

   # Parsing
   peat parse <path>
   peat parse <path1> <path2> ...
   peat parse *.ext
   # -- is required before any path arguments if arguments
   # like "-d" that have multiple values are used.
   peat parse -d <device-type> -- <path>

   # Run name is the name of the folder in ./peat_results with peat data
   # either "--run-name" or "-R" can be used
   peat scan -i 192.0.2.0/24 --run-name scan_example
   peat pull -i 192.0.2.0/24 -R pull_example
   peat parse -d selrtac --run-name parse_example -- ./examples/

   # Pushing
   peat push -d <device-type> -i <ip> -- <filename>
   peat push -d <device-type> -i <ip> -t <push-type> <filename>

   # Pillage
   # NOTE: currently (04/20/2023) a configuration file with a "pillage" section is required.
   # NOTE: pillage MUST be run as root, using sudo or by su'ing to root ("sudo su")
   peat pillage -c ./examples/peat-config.yaml -P <raw-image-file>
   peat pillage -c ./examples/peat-config.yaml -P <local-filesystem-path>

   # List available device modules
   # NOTE: currently this shows ALL modules, including ones not supported for the command (e.g. scan)
   #  A future version of PEAT will only show modules that support the command (e.g. scan)
   peat scan --list-modules
   peat pull --list-modules
   peat parse --list-modules
   peat push --list-modules
   peat pillage --list-modules

   # Dry run where no commands will be executed
   # Useful for understanding PEAT's behavior and experimenting with configuration
   # options before packets are sent to OT devices.
   peat scan --dry-run -c ./examples/peat-config.yaml -vV -i 192.0.2.0/24


.. _windows-usage:

Note about Windows usage
------------------------
We recommend running in an Administrator-level PowerShell terminal or script. Running as a standard user will reduce performance slightly, since certain Windows networking APIs are restricted. This will affect some network features, such as the ability to do :term:`ICMP` pings, :term:`ARP` pings, or network sniffing. PEAT will run fine in a CMD terminal but some terminal functionality may not work as well (e.g. terminal output colors and formatting).

.. _output-structure:

Output
======
PEAT will output a number of files, depending on the subcommand used (e.g. ``scan``). By default, these files will be saved to the directory ``./peat_results/`` in the current working directory. The directory files are saved to can be changed with the ``-o <dirname>`` command line argument, ``OUT_DIR`` in a configuration file, or by setting the ``PEAT_OUT_DIR`` environment variable.

Device-specific output will be in ``<out-dir>/<run-dir>/devices/<device-id>/``. For example, the output from running ``peat pull -R example_pull -i 192.0.2.20`` will be in the ``./peat_results/example_pull/devices/192.0.2.20/`` directory.

Run directory and run name
--------------------------

Every time PEAT is run, a new sub-directory of ``./peat_results/`` is created. This is the "run dir", and contains all of the data for a run. The name of the directory can be configured using ``-R`` (``--run-name``) argument. If the run name isn't specified, it will be auto-generated based on the following format: ``<peat-command>_<config-name>_<timestamp>_<run-id>``. The run directory can also be set directly with ``--run-dir``, which will bypass ``peat_results/``.

Examples:

- ``peat scan --run-name example_run -i 127.0.0.1`` results in ``./peat_results/example_run/``
- ``peat pull -c ./examples/peat-config-sceptre-testing.yaml -i 127.0.0.1`` results in ``./peat_results/pull_sceptre-test-config_2022-06-17_165532013980/``
- ``peat scan -i 127.0.0.1`` results in ``./peat_results/scan_default-config_2022-09-27_165532013980/``
- ``peat scan --rundir example_run_dir -i 127.0.0.1`` results in ``./example_run_dir/``


Directory structure
-------------------
The location and names of directories are configurable, refer to the :doc:`configure` section for details on how to do this.

- ``devices/`` : All output for devices, with subdirectories for each device by device ID. The device ID is typically the :term:`IP` address in the case of pulls, but can be other identifying information if the IP isn't known, such as name, serial port, name of source file, or other identifiers.
- ``elastic_data/`` : Copies of documents pushed to Elasticsearch. These can be used to rebuild the Elasticsearch data if you only have the files or don't have a Elasticsearch server available when running PEAT. This is only created if Elasticsearch is in use (the ``-e`` argument).
   - ``mappings/`` : Elasticsearch type mappings for the PEAT indices
- ``heat_artifacts/`` : Output from :term:`HEAT` (``peat heat <args>``)
- ``logs/`` : Records of PEAT's command output, protocol logs, and other information that's useful for debugging or knowing what PEAT did. These include protocol- and module-specific log files (e.g. Telnet logs, ENIP logs).
- ``peat_metadata/`` : files related to PEAT itself, including :term:`JSON` and :term:`YAML` formatted dumps of PEAT's configuration and internal state.
- ``summaries/`` : Summary results of a command as :term:`JSON` files, e.g. :ref:`scan-summary`, :ref:`pull-summary`, or :ref:`parse-summary`. These include metadata about the operation (e.g., how many files were parsed), as well as a combined set of device summaries (most of the data, but some fields are excluded, like events, memory, blobs, etc.). To view the complete results for devices, look in the ``devices/`` directory.
- ``temp/`` : Temporary files, used by PEAT during a run to put files temporarily before being moved elsewhere.


Typical output structure
^^^^^^^^^^^^^^^^^^^^^^^^
NOTE: the file structure below will differ if any of the ``*_DIR``
variables were configured, e.g. ``OUT_DIR``, ``ELASTIC_DIR`` or ``LOG_DIR``.

``...`` represents "miscellaneous files".

The output directory structure generally looks like this:

.. code-block::

   ./peat_results/
      README.md
      <command>_<config-name>_<timestamp>_<run_id>/
         devices/
               <device-id>/
                  device-data-summary.json
                  device-data-full.json
                  ...
         elastic_data/
               mappings/
                  ...
               ...
         heat_artifacts/
               ...
         logs/
               enip/
                  ...
               peat.log
               json-log.jsonl
               debug-info.txt
               elasticsearch.log
               telnet.log
               ...
         peat_metadata/
               peat_configuration.yaml
               peat_state.json
               peat_state.yaml
         summaries/
               scan-summary.json
               pull-summary.json
               parse-summary.json
         temp/
               ...


Viewing the results
-------------------
Examples and helpful commands for inspecting the file results.

.. code-block:: shell

   peat pull --run-name example_pull -i 192.0.2.0/24 10.0.0.5-10 172.16.17.18
   # … wait a while …

   # View scan results
   cat peat_results/example_pull/summaries/scan-summary.json

   # Use with the "jq" command for color-highlighted output (https://stedolan.github.io/jq/)
   cat peat_results/example_pull/summaries/scan-summary.json | jq .

   # View listing of all the files pulled (requires the "tree" command, install using "sudo apt install tree")
   tree -arv peat_results/example_pull/devices/

   # Filtering memory and event entries from device results for 192.168.3.200 using 'jq'
   cat peat_results/example_pull/devices/192.168.3.200/device-data-full.json | jq 'del(.memory,.event)'

Device-specific results
-----------------------
.. warning::
   These lists are not exhaustive

Schneider Modicon M340
^^^^^^^^^^^^^^^^^^^^^^
.. csv-table::
   :name: Schneider Modicon M340 PLCs
   :header: "Type of file", "File extension", "Description"
   :widths: auto
   :align: left

   project, apx, "Raw project file pulled from the device ('peat parse' can be run on this)"
   "parsed-config", txt, "Configuration and metadata extracted from device and/or project file"
   tc6, xml, "TC6 format usable by PLCOpen editor and compilable to Structured Text or executable C-code emulating the logic. Only written if logic and/or variables are successfully extracted."
   logic, st, "Structured Text extracted from project file. Only written if logic is successfully extracted."
   "text-dump", txt, "Debugging dump created if logic extraction fails"
   "blob-packets", txt, "Raw dump of the bytes transferred when downloading a project file"
   "umas-packets", json, "Metadata and contents of UMAS packets transferred when downloading a project file"

Allen-Bradley ControlLogix
^^^^^^^^^^^^^^^^^^^^^^^^^^
.. csv-table::
   :name: Allen-Bradley ControlLogix PLCs
   :header: "Type of file", "File extension", "Description"
   :widths: auto
   :align: left

   "parsed-logic", txt, "Decompiled ladder logic in a human-readable form"
   "parsed-logic", json, "Extracted values from the ladder logic in machine-readable form"
   "raw-logic", json, "The raw tags and values pulled from the device"

SEL Relays
^^^^^^^^^^
.. csv-table::
   :name: SEL Relays
   :header: "Type of file", "File extension", "Description"
   :widths: auto
   :align: left

   "SET_ALL", TXT, "Text file containing all relay settings in one file"
   "CFG", TXT, "Text file containing a list of all config files resident inside the relay"
   "SET_*", TXT, "Individual configuration files for SEL relay, varies by relay model"

Scanning for systems on a network
=================================
PEAT's scanning functionality is essentially a lightweight `Nmap <https://nmap.org/>`__ specialized for :term:`OT` devices, with a focus on minimizing or eliminating impacts to field devices and processes. It can discover :ref:`supported OT devices <supported-devices>` on a network, determine their type, and retrieve basic information about them.

IP subnets can be scanned by specifying the IP subnet using :term:`CIDR` prefix notation. For example, running ``peat scan -i 192.0.2.0/24`` will scan all 254 devices in the range ``192.0.2.1`` to ``192.0.2.254``.

The results will be written to a file named ``./peat_results/the_run_name/summaries/scan-summary.json``. Terminal output can additionally be enabled using the argument ``-E`` (``--print-results``). If Elasticsearch output is enabled, then scan results will also be saved to the ``peat-scan-summaries`` index in Elasticsearch.

Detailed information can be collected via a pull (``peat pull``). Note that ``peat pull`` will implicitly perform a scan, and only pull from the devices positively identified by the scan. If you know you want to collect detailed information in addition to device discovery, then just run a pull via ``peat pull`` instead of performing a scan followed by a pull.


.. _broadcast-scanning:

Broadcast scanning
------------------
Network broadcasts can be used to discover devices on a network in a more efficient and less intrusive manner. This method will send a single packet (or set of packets) to the broadcast address for a subnet (e.g., ``192.0.2.255`` for the subnet ``192.0.2.0/24``) and wait for devices to respond. Any devices that respond will then be interrogated further using the normal unicast IP methods available. Note that only IP (:term:`OSI` layer 3) broadcasts are currently supported. Layer 2 (MAC) broadcast support may be added at a later date.

Benefits
^^^^^^^^
- Reduced load on network (less packets sent/received)
- Only devices expecting the traffic respond
- Reduced risk of causing issues with unrelated devices
- Can efficiently discover and query devices in extremely large networks (e.g. a full class B subnet with 65,535 IPs)

Supported devices
^^^^^^^^^^^^^^^^^
- ControlLogix (using the :term:`CIP` protocol)

Running as container
^^^^^^^^^^^^^^^^^^^^
.. warning::
   The ``--network "host"`` argument to Docker/Podman is required. This is because PEAT must be in the same broadcast domain(s) as the network(s) being scanned, and container network isolation prevents that.

   TODO: walk through Docker arguments

.. code-block:: bash

   # Podman
   podman run --rm -v $(pwd)/peat_results:/peat_results --network "host" -i --privileged ghcr.io/sandialabs/peat scan -b 192.0.2.255

   # Docker
   docker run --rm -v $(pwd)/peat_results:/peat_results --network "host" -i --privileged ghcr.io/sandialabs/peat scan -b 192.0.2.255

Examples
^^^^^^^^
.. code-block:: python

   # Discover devices on a network using IP broadcasts
   peat scan -b 192.0.2.0/24

   # Broadcast using an interface
   peat scan -b eth1

   # Broadcast from a file
   peat scan -b examples/broadcast_targets.txt

   # Broadcast combinations
   peat scan -b 192.0.3.0/24 192.168.2.255 192.0.2.0/25 eth1 examples/broadcast_targets.txt

   # Pull all devices discovered using IP broadcasts
   peat pull -b 192.0.2.0/24


Usage examples
==============

Scan
----
.. literalinclude:: ../peat/cli_args.py
   :name: Scan examples
   :language: python
   :start-after: scan_examples = """
   :end-before: """  # End scan_examples

Pull
----
.. literalinclude:: ../peat/cli_args.py
   :name: Pull examples
   :language: python
   :start-after: pull_examples = """
   :end-before: """  # End pull examples

Parse
-----
.. literalinclude:: ../peat/cli_args.py
   :name: Parse examples
   :language: python
   :start-after: parse_examples = """
   :end-before: """  # End parse examples

Push
----
.. literalinclude:: ../peat/cli_args.py
   :name: Push examples
   :language: python
   :start-after: push_examples = """
   :end-before: """  # End push examples


Summaries
=========
The output of several commands is in a structure known as a "summary". This can be a :term:`JSON` file, an Elasticsearch document, or Python :class:`dict` representing the results of a given command (e.g. ``scan``).

.. _scan-summary:

Scan summary
------------
The scan summary represents the results of device discovery and verification, such as during a scan, pull, push, or other related network operations. Scan summaries are stored as :term:`JSON` in the directory configured in the :attr:`SUMMARIES_DIR <peat.settings.Configuration.SUMMARIES_DIR>` :doc:`configuration option <configure>` (defaults to ``peat_results/summaries/``), printed to the terminal (``stdout``) as :term:`JSON` when running a scan using ``peat scan``, or returned as a :class:`dict` when calling :func:`peat.api.scan_api.scan`.

.. csv-table:: Scan summary fields
   :escape: \
   :file: field_references/scan_summaries_fields.csv
   :header-rows: 1
   :widths: auto
   :align: left

Example
^^^^^^^
.. literalinclude:: ../examples/example-scan-summary.json
   :name: Example scan results summary JSON file
   :language: json


.. _pull-summary:

Pull summary
------------
The pull summary is a summary of device pulls. Pull summaries are stored as :term:`JSON` in the directory configured in the :attr:`SUMMARIES_DIR <peat.settings.Configuration.SUMMARIES_DIR>` :doc:`configuration option <configure>` (defaults to ``peat_results/summaries/``) or returned as a :class:`dict` when calling :func:`peat.api.pull_api.pull`. Only the results of the pull (list of device data) is printed to the terminal (``stdout``) as :term:`JSON` when running a scan using ``peat pull``.

.. csv-table:: Pull summary fields
   :escape: \
   :file: field_references/pull_summaries_fields.csv
   :header-rows: 1
   :widths: auto
   :align: left

Example
^^^^^^^
.. literalinclude:: ../examples/example-pull-summary.json
   :name: Example pull results summary from a JSON file
   :language: json


.. _parse-summary:

Parse summary
-------------
The parse summary represents the results of parsing device artifacts using ``peat parse``. Parse summaries are stored as :term:`JSON` in the directory configured in the :attr:`SUMMARIES_DIR <peat.settings.Configuration.SUMMARIES_DIR>` :doc:`configuration option <configure>` (defaults to ``peat_results/summaries/``), printed to the terminal (``stdout``) as :term:`JSON` when running a parse using ``peat parse``, or returned as a :class:`dict` when calling :func:`peat.api.parse_api.parse`.

.. csv-table:: Parse summary fields
   :escape: \
   :file: field_references/parse_summaries_fields.csv
   :header-rows: 1
   :widths: auto
   :align: left

Example
^^^^^^^
.. literalinclude:: ../examples/example-parse-summary.json
   :name: Example parse results summary from a JSON file
   :language: json


.. _containers:

Containers (Docker/Podman)
==========================
.. note::
   When using :term:`Podman` on Red Hat Enterprise Linux (:term:`RHEL`), replace ``docker`` with ``podman`` in commands. :term:`Podman` is similar to Docker and has a nearly identical interface, and therefore most aspects of this guide are still applicable. However, there may be slight differences in lesser-used arguments as well as differences in behavior. Refer to the `official Podman documentation <http://docs.podman.io/en/latest/>`__ for further details.

.. note::
   This document was written with the assumption that :term:`Docker` is running on Linux and is installed as directed by the `official Docker documentation <https://docs.docker.com/get-docker/>`__. Your environment will likely differ slightly and so there may be differences in output and commands (for example, filesystem paths or arguments used). Refer to the `Docker documentation <https://docs.docker.com/>`__ for your platform for further details.

.. warning::
   The ``sudo`` command is required before all ``docker ...`` commands unless you have configured the ``docker`` group as directed by the Docker Linux setup guide. It is omitted from the commands in this guide for brevity and because it's a common configuration.

.. seealso::

   `Docker documentation <https://docs.docker.com/>`__

   `Podman documentation <http://docs.podman.io/en/latest/>`__

Docker arguments
----------------
.. note::
   Take note of the arguments to ``docker run`` when reading the examples. All command line arguments after "docker run" and before the image name ("ghcr.io/sandialabs/peat") are arguments to Docker, and any after the image name are arguments to PEAT.

.. warning::
   Results will NOT be saved unless the output directory is mounted in the container! Ensure ``-v $(pwd)/peat_results:/peat_results`` is always included in the arguments to ``docker run``.

Docker arguments of note:

- ``--network "host"``: removes Docker's network isolation and provides PEAT access to the local network interfaces. If missing, scans will be less reliable, :term:`MAC` addresses of devices will not be resolved, broadcast scanning will not work, and PEAT will not be able to push results to a Elasticsearch server listening on ``localhost``.
- ``-i``: "interactive", which enables STDIN, and is necessary for :term:`CLI` PEAT
- ``-v /local/system/path:/path/in/container/``: makes a local filesystem directory available inside the container
- ``--privileged``: gives PEAT full root access to the local system, which can be helpful for certain scans

Container usage
---------------
This is the standard PEAT command line interface, bundled up as a container.

.. note::
   If peat is run as a container then the file path logged in the container will differ from that on host. This affects logging messages and anywhere else paths are noted or logged.

.. warning::
   Currently, PEAT Pillage **when used as a container** WILL NOT work with Windows disk images, and MAY NOT work reliably with Linux disk images. File systems WILL work if used with a volume mount, e.g. using ``-v`` with ``docker run`` (see the examples below for details). In the meantime, if you need Pillage functionality we recommend using the Linux or Windows executable version of PEAT instead of the container.

View the command line help
^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: bash

   # Podman
   podman run --rm -i ghcr.io/sandialabs/peat --help
   podman run --rm -i ghcr.io/sandialabs/peat scan --help

   # Docker
   docker run --rm -i ghcr.io/sandialabs/peat --help
   docker run --rm -i ghcr.io/sandialabs/peat scan --help


Parsing files and directories
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. warning::
   File paths on the host system (the system running docker) cannot be used directly due to Docker's filesystem isolation. Instead, pipe the file in and use the ``-i`` argument to Docker run (for a single file), or mount a volume into the container (for multiple files or a directory). Examples of both are below.

To parse a single file, use a pipe (``|``), or use redirection to STDIN (``<``)

.. code-block:: bash

   # Using cat
   cat examples/devices/sel/sel_351/set_all.txt | docker run --rm -i ghcr.io/sandialabs/peat parse -d selrelay

   # Using file redirection
   docker run --rm -i ghcr.io/sandialabs/peat parse -d selrelay < examples/devices/sel/sel_351/set_all.txt

To parse data from a directory, mount it as a volume

.. code-block:: console

   # General usage. "/dirname" is the name of the directory you want to parse.
   docker run --rm -v "$(pwd)/dirname":"/dirname" -v $(pwd)/peat_results:/peat_results -i ghcr.io/sandialabs/peat parse -v -d ion -- "/dirname"

   # Push the parse results to an Elasticsearch server listening on localhost
   docker run --rm -v $(pwd)/peat_results:/peat_results --network "host" -i ghcr.io/sandialabs/peat parse -e -v -d selrelay -- "/peat_results/*/devices/"

   # Another concrete example of parsing a directory. Note the absolute path to /examples.
   docker run --rm -v "$(pwd)/examples":"/examples" -v $(pwd)/peat_results:/peat_results --network "host" -i --privileged ghcr.io/sandialabs/peat -VV -e http://localhost:9200 -d selrelay /examples/devices/sel/*/*.rdb

Pulling data from devices
^^^^^^^^^^^^^^^^^^^^^^^^^
Running a basic pull

.. code-block:: shell

   docker run --rm -v $(pwd)/peat_results:/peat_results --network "host" -i ghcr.io/sandialabs/peat pull -i 192.0.2.0/24

To improve scanning abilities, run as root using "privileged". This requires ``root`` privileges on the host system running Docker.

.. code-block:: bash

   docker run --rm --privileged -v $(pwd)/peat_results:/peat_results --network "host" -i ghcr.io/sandialabs/peat pull -i 192.0.2.0/24

Pull from a SEL relay, and export the results to Elasticsearch

.. code-block:: bash

   docker run --rm -v $(pwd)/peat_results:/peat_results --network "host" -i ghcr.io/sandialabs/peat pull -vV -e -d selrelay -i 192.0.2.22

Pull from three relays on two independent networks, and export the results to Elasticsearch

.. code-block:: bash

   docker run --rm -v $(pwd)/peat_results:/peat_results --network "host" -i ghcr.io/sandialabs/peat pull -vV -e -d selrelay -i 192.0.3.44-55 192.0.2.22-33

Pushing data to devices
^^^^^^^^^^^^^^^^^^^^^^^
Pushing a set of configuration files to a SEL relay

.. code-block:: bash

   docker run --rm -v $(pwd)/peat_results:/peat_results --network "host" -i ghcr.io/sandialabs/peat push -vV -d selrelay -i 192.0.2.22 -- "/relay_configs/"

Development and Debugging
^^^^^^^^^^^^^^^^^^^^^^^^^
Testing inside of the container and saving the changes

.. code-block:: bash

   docker run --name "peat_dev" -v $(pwd)/peat_results:/peat_results -i -t --entrypoint "/bin/sh" ghcr.io/sandialabs/peat
   docker commit peat_dev

Attach to an existing container (including a running one)

.. code-block:: bash

   docker ps -a
   docker exec --network "host" -it <container-name> "/bin/sh"

General Docker usage and reference
----------------------------------
.. note::
   Images and Containers are distinct terms that are easy to confuse. Images refer to the "image" that is built (e.g. PEAT) and used to create containers, created using ``docker build``. Containers are instances, created when using ``docker run``.

Images
^^^^^^
.. code-block:: bash

   # Load a image
   docker load -i image.tar

   # List installed images
   docker images
   docker images -a

   # Delete an image
   docker rmi <image-id>

   # Cleanup residual images and layers (e.g. leftover from builds)
   docker image prune

Logs
^^^^
.. code-block:: bash

   docker logs -f <container>
   docker logs --since 4h <container>
   docker logs <container> 2>&1 | head -n 10  # Container that writes to stderr

   # Monitor status of containers and view images using "lazydocker"
   # ("q" to quit, bottom of screen has usage)
   # Install from: https://github.com/jesseduffield/lazydocker
   lazydocker

Containers
^^^^^^^^^^
.. code-block:: bash

   # View RUNNING containers
   docker ps

   # View RUNNING and STOPPED containers
   docker ps -a

   # Delete a container
   docker rm -f <container>

   # Delete all STOPPED containers
   docker container prune

   # Cleanup images, containers, networks, and volumes
   docker system prune

Further reading
^^^^^^^^^^^^^^^
- `Docker vs. a VM <https://stackoverflow.com/a/16048358/2214380>`__
- `Docker Compose file reference <https://docs.docker.com/compose/compose-file/>`__
- `lazydocker <https://github.com/jesseduffield/lazydocker>`__
- `Start containers automatically <https://docs.docker.com/config/containers/start-containers-automatically/>`__
- `Container best practices <http://docs.projectatomic.io/container-best-practices/>`__
- `Docker Volume documentation <https://docs.docker.com/storage/volumes/>`__
- `Stack Overflow post explaining volumes and how to use them <https://stackoverflow.com/questions/42848279/how-to-mount-volume-from-container-to-host-in-docker?rq=1>`__

.. _pillage:

Pillage
=======

Description
-----------
Pillage is a sub-command of PEAT that searches for relevant :term:`ICS`/:term:`OT` project files to import into PEAT for further analysis and comparison to project files retrieved elsewhere.  It can search through a specific directory on the host system, a directory that is connected/mounted to the host system, or a raw disk image for possible files.

The search criteria defined in the configuration file is used to validate if a file should be considered a a valid file for copying.

When a valid file is found it will be copied into a ``./pillage_results/`` directory located in the current working directory of PEAT.  The valid files are sorted into sub-directories based on the brands (plus ``DEFAULT``) defined in the pillage configuration file.  If a file is found to fit multiple brands then it will be copied into a ``MULTIPLE`` sub-directory for the user to determine which specific brand it belongs too.  For more details regarding which brands apply to a file and why it was copied review the PEAT logs after the run.

Before a file is copied into a results sub-directory Pillage checks to see if a file with the same name already exists.  If it does then the new file is copied to the results sub-directory and renamed with an integer added.  For example if ``set_all.txt`` is found but a file with that same name already exists in ``./pillage_results/SEL/``, then the new file will be renamed to ``set_all.1.txt``

Refer to :ref:`pillage-config` for the available options and examples.

Requirements
------------
- Must be run on a Linux host system (Currently only tested on Ubuntu 18+)
- Must be run as ``root``.  This is specifically needed if mounting an image.
- ``qemu-nbd``, a part of the ``qemu-utils`` package. Installation: ``sudo apt install qemu-utils``
- ``kmodpy`` Python package. This should be automatically installed with PEAT.
- If pillaging a raw disk image, the host system must support the filesystem. The filesystems supported by the host can be found through the following commands:
  .. code-block::

     - Opening the file `/proc/filesystems` on the host system
     - Running `ls -1 /lib/modules/$(uname -r)/kernel/fs` on the host system

Running Pillage
---------------

Example commands
^^^^^^^^^^^^^^^^
Pillage files from a raw disk image

.. code-block:: bash

   peat pillage -c examples/peat-config.yaml -P raw_disk.img


Pillage files from VM images

.. code-block:: bash

   peat pillage -c examples/peat-config.yaml -P eng_vm.qcow2
   peat pillage -c examples/peat-config.yaml -P SomeVM.vmdk


Pillage files from a mounted drive or local directory

.. code-block:: bash

   peat pillage -c examples/peat-config.yaml -P /home/peat/pillage_this


Results can also be pushed to Elasticsearch

.. code-block:: bash

   peat pillage -e http://192.0.2.21:9200 -c examples/peat-config.yaml -P /home/peat/pillage_this

Command line arguments
^^^^^^^^^^^^^^^^^^^^^^
- ``-c`` The PEAT configuration file to use. Refer to :ref:`pillage-config`.
- ``-P`` The source image or directory to search

Examples
^^^^^^^^
.. literalinclude:: ../peat/cli_args.py
   :name: Pillage examples
   :language: python
   :start-after: pillage_examples = """
   :end-before: """  # End pillage examples

When things go wrong
--------------------
If there is a critical failure and PEAT is unable to cleanup, run the following commands to cleanup ``pillage_temp``:

.. code-block:: bash

   sudo umount pillage_temp
   sudo rm -rf pillage_temp
   sudo qemu-nbd -d /dev/nbd1
   sudo rmmod nbd

Notes
-----
- If a disk image is used as the source it must be a raw disk image.  Pillage does not support any other image formats.  To use unsupported images with pillage either convert it to a raw disk image or mount it to the host filesystem manually and provide the mount point as the input source to Pillage.
- If a disk image is used as a source Pillager will mount it (read only) to a directory prior to searching called ``pillage_temp``.  It will be located in the current working directory when Pillage is ran.  Once Pillager is complete the image will be unmounted and this directory will be removed.
- There have been times during development and testing when the host OS would not mount the image, but if the same Pillage command was tried again after waiting a few seconds it would mount just fine.
- If running in a VMware Workstation VM, pillage can run on a disk image or file system loaded in a shared folder. See the VMware documentation for details on how to set this up. If you run into issues, this askubuntu answer may be helpful: `How do I mount shared folders in Ubuntu using VMware tools? <https://askubuntu.com/a/1051620>`__
- To manually mount an image in the same manner as pillage:

.. code-block:: shell

   sudo modprobe nbd
   sudo mkdir /mnt/myimage
   qemu-nbd -r -c /dev/nbd1 /path/to/disk/image.vmdk
   mount -o ro /dev/nbd1p1 /mnt/myimage

   # Cleanup
   sudo umount /mnt/myimage
   sudo qemu-nbd -d /dev/nbd1
   sudo rmmod nbd

.. _heat-usage:

HEAT: High-fidelity Extraction of Artifacts from Traffic
========================================================

HEAT reconstructs *artifacts* (device files, e.g. configuration, logic, firmware, logs, etc.) from data in a network traffic capture and parses those artifacts using PEAT. Examples of data extracted include process logic, register mappings, protocol and network service configurations, I/O points, device types and roles, vendor and model, and more.

Protocols supported
-------------------
These can be listed by running ``peat heat --list-heat-protocols``.

- Telnet
   - SEL relays
   - Uses data in Elastic from ``ingest-tshark`` (:term:`SNL`-developed tool)
- :term:`FTP`
   - SEL relays
   - Uses Zeek to process PCAP files (``.pcap`` / ``.pcapng``)
- :term:`UMAS`
   - Schneider-proprietary protocol that is wrapped by Modbus/TCP (modbus function code 90). See :term:`UMAS` in the glossary for details.
   - Schneider Electric Modicon M340 PLCs (and other Modicon PLCs)
   - Uses data in Elastic from ``ingest-tshark`` (:term:`SNL`-developed tool)

Usage
-----
Network traffic either must be parsed by ``ingest-tshark`` and available in Elasticsearch, or in a PCAP file  (``.pcap`` / ``.pcapng``), depending on the HEAT protocol plugin. For example the FTP Extractor uses Zeek to process PCAP files directly.

HEAT FTP Extractor
^^^^^^^^^^^^^^^^^^
The ``FTPExtractor`` plug-in for HEAT uses the Zeek network monitoring tool to parse pcap files. A ``.pcap`` file must be present locally to use this plugin. The location of the pcap file can be specified using the ``--pcap`` argument when calling HEAT.

It's **strongly** recommended to use the Docker container version of PEAT, as it bundles the correct version of Zeek (6.0) and it's dependencies. If you are unable to use the container, then ensure you have Zeek 6.0 installed on your host and in the system PATH variable (or in ``/opt/zeek/``).

.. code-block:: shell

   # This example will process all PCAP files in "./pcaps", and save the results to "./peat_results"
   docker run --rm -i --network host -v "$(pwd)/pcaps":/pcaps -v $(pwd)/peat_results:/peat_results ghcr.io/sandialabs/peat:latest heat -vVV -e http://heat-elastic:9200 --pcaps /pcaps --heat-file-only --heat-protocols FTPExtractor

Examples
^^^^^^^^
.. literalinclude:: ../peat/cli_args.py
   :name: HEAT examples
   :language: python
   :start-after: heat_examples = """
   :end-before: """  # End HEAT examples


.. _peat-elastic-operate:

Elasticsearch
=============
.. note::
   Refer to :ref:`peat-index-reference` for a table of the Elasticsearch indices used by PEAT

Introduction
------------
PEAT has the ability to push artifacts from runs to an Elasticsearch server, such as scan results, logs, and device configurations. It uses multiple Elasticsearch indices to store data. Indices are described in detail here: :ref:`database-schema`

PEAT data is not saved to Elasticsearch by default. To do so, use the ``-e`` command line argument or the :attr:`ELASTIC_SERVER <peat.settings.Configuration.ELASTIC_SERVER>` :doc:`configuration option <configure>` and specify the server to export data to. Examples of usage can be found in the command line examples earlier in this chapter.

Configuration and notes
-----------------------
- **Binary blobs or large data fields (e.g. firmware images or raw configuration files) are NOT saved to Elasticsearch by default!**.
   - To enable saving of large data, use the ``--elastic-save-blobs`` command line argument or the :attr:`ELASTIC_SAVE_BLOBS <peat.settings.Configuration.ELASTIC_SAVE_BLOBS>` :doc:`configuration option <configure>`.
- Indices are "split" split by date, so a new index is created for each day.
   - Format: ``<index-name>-<year>.<month>.<day>``
   - Timestamps are in the :term:`UTC` timezone, not the host's timezone.
   - Example: ``ot-device-hosts-timeseries-2023.04.21`` for all host data collected on April 20th, 2023.
   - This behavior can be disabled by setting :attr:`ELASTIC_DISABLE_DATED_INDICES <peat.settings.Configuration.ELASTIC_DISABLE_DATED_INDICES>` to true or setting ``PEAT_ELASTIC_DISABLE_DATED_INDICES`` environment variable to true. This will result in only the base names of indices being used and no timestamped indices being created, e.g. all host data will be written to the index named ``ot-device-hosts-timeseries`` instead of ``ot-device-hosts-timeseries-2022.04.29`` and so on.
- PEAT's logging events and dumps of it's configuration and state are stored in Elasticsearch by default.
   - This behavior can be disabled via the following :doc:`configuration options <configure>`: :attr:`ELASTIC_SAVE_LOGS <peat.settings.Configuration.ELASTIC_SAVE_LOGS>`, :attr:`ELASTIC_SAVE_CONFIG <peat.settings.Configuration.ELASTIC_SAVE_CONFIG>`, and :attr:`ELASTIC_SAVE_STATE <peat.settings.Configuration.ELASTIC_SAVE_STATE>`.
- The timeout for PEAT to connect to the Elasticsearch server can be configured via the :attr:`ELASTIC_TIMEOUT <peat.settings.Configuration.ELASTIC_TIMEOUT>` :doc:`configuration option <configure>` or the ``--elastic-timeout`` command line argument.

JSON file copies of Elasticsearch exports
-----------------------------------------
Most data sent to Elasticsearch by PEAT is saved locally as :term:`JSON` files. These files can be used to rebuild the indices in case of a issue with the server, or if you want to import the data to another server and have lost access to the server the data was originally exported to. By default, these files are saved to ``peat_results/the_run_name/elastic_data/``. This location can be configured via the :attr:`ELASTIC_DIR <peat.settings.Configuration.ELASTIC_DIR>` :doc:`configuration option <configure>` in a config file or the ``PEAT_ELASTIC_DIR`` environment variable.

.. _peat-device-modules:

Third-party device modules
==========================
PEAT uses a modular architecture for implementing the functionality of devices supported by PEAT, with the functionality for a particular device (for example, a SEL Relay) bundled up as a semi-standalone "PEAT device module" (in this case,  :class:`peat.modules.sel.sel_relay.SELRelay`). While PEAT includes a large selection of modules, additional modules can be imported and used at runtime, with no changes to PEAT's code. These modules are generally referred to as "PEAT device modules", "PEAT modules", "third-party modules", or "runtime modules". Use cases for runtime loaded modules are modules that aren't able to be open-sourced due to sensitivities or modules implemented by a user (like you!).

Implementing a module to support a new device is simple and only requires a text editor and ability to write Python code. Refer to the :doc:`module_developer_guide` for details on implementing a module.

Usage example
-------------
Simple example performing a ``peat parse`` using the AwesomeTool PEAT device module, which parses the output of the fictional ``awesome-tool``:

.. code-block:: bash

   # "-d AwesomeTool" : specify what PEAT module to use, in this case the "AwesomeTool" module you created
   # "-I awesome_module.py" : import the middleware module so it's usable by PEAT
   # "-- awesome_output.json" : the file to parse, in this case the output of running "awesome-tool"
   peat parse -d AwesomeTool -I ./examples/example_peat_module/awesome_module.py -- ./examples/example_peat_module/awesome_output.json

Troubleshooting
===============

Getting troubleshooting data (logs)
-----------------------------------
Run PEAT with "verbose" flag (``-v``) to see more events on the terminal. These events are always written to the log file in ``peat_results/the_run_name/logs/``, as well as Elasticsearch if it's configured.

Additional information can be generated by enabling "Debugging" mode. There are multiple debugging levels ranging from 1 to 4. These can be set via command line arguments, e.g. ``-V`` for level 1 or ``-VVV`` for level 3, or by setting the :attr:`DEBUG <peat.settings.Configuration.DEBUG>` :doc:`configuration option <configure>` to the desired debugging level.

.. code-block:: bash
   :caption: Example troubleshooting a pull from SEL devices on a subnet

   peat pull -VVV -R example_tshoot -d selrelay -i 192.0.2.0/24

   # View the log files generated
   ls -lAht peat_results/example_tshoot/logs/

   # View the log file with the "less" command
   less peat_results/example_tshoot/logs/peat.log

Log files
---------
.. note::
   Much of the data listed below is also stored in Elasticsearch, if configured. Refer to :ref:`peat-index-reference`.

.. csv-table::
   :name: PEAT troubleshooting files
   :header: "Name", "Description", "Default file path"
   :widths: 20, 55, 25
   :align: left

   "Logs", "Primary log file for PEAT. Human-readable text file that contains most logging events generated by PEAT, as well as some metadata generated at startup.", "``peat_results/run_name/logs/peat.log``"
   "Configs", "Configuration dump, in :term:`YAML` format. This contains the configuration PEAT used for the run.", "``peat_results/run_name/peat_metadata/peat_configuration.yaml``"
   "State", "State dump, in :term:`JSON` format. This contains the internal state of PEAT as of the end of the run.", "``peat_results/run_name/peat_metadata/peat_state.json``"
   "JSON logs", "PEAT logs, in :term:`JSON` format. Each line in the log file is a JSON-formatted log record, following the ``.jsonl`` (JSON Lines) file format. Useful for ingesting into automated tools, e.g. a :term:`SIEM` or log processor.", "``peat_results/run_name/logs/json-log.jsonl``"
   "Elasticsearch logs", "Logging events generated by PEAT's Elasticsearch module, in a human-readable text format. Useful if you're troubleshooting issues with Elasticsearch.", "``peat_results/run_name/logs/elasticsearch.log``"
   "Telnet logs", "Raw Telnet protocol events, in a human-readable text format. Useful for troubleshooting issues with PEAT modules that use Telnet.", "``peat_results/run_name/logs/telnet.log``"

Troubleshooting issues with Elasticsearch
-----------------------------------------
Logging events from PEAT's Elasticsearch internals are NOT written to the normal places PEAT logs are saved. Instead, they're written to a special log file named ``elasticsearch.log``, which by default is located in ``peat_results/run_name/logs/``.

Common issues with Elasticsearch include bad type mappings. If this occurs, delete the index, then re-attempt the push. Ensure any important data is saved BEFORE deleting the index! Data can be exported using `elasticsearch-dump <https://github.com/elasticsearch-dump/elasticsearch-dump>`__. To delete an index, use `curl <https://manpages.debian.org/bullseye/curl/curl.1.en.html>`__ with the ``-XDELETE`` option: ``curl -XDELETE localhost:9200/ot-device-hosts-*``.

Limitations
===========
General limitations of PEAT that aren't bugs. Refer to :ref:`known-issues` for a list of known issues with PEAT (bugs).

- MAC addresses of devices will not be resolved during a scan or pull if the device is behind a router or gateway (e.g. in another subnet than the device performing the scanning).
- The ability to check host online status using ARP or ICMP requests requires root (Linux) or Administrator (Windows) permissions on the host running PEAT. If PEAT is unable to use these protocols, it falls back to using TCP SYN requests. These requests are less reliable and may be blocked by firewalls.

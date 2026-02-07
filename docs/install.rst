*******
Install
*******
This section documents how to setup PEAT for optimal use on each supported platform. Refer to :doc:`operate` for next steps after completing installation.

PEAT is distributed in multiple formats customized to each supported platform. All formats are included in the :ref:`release-archive`. If you need to build the executables manually or know more about the various distribution methods, refer to the :ref:`distribution`.

Installation
------------
The recommended method of installation for most users is to use the latest pre-built executable release (``peat`` on Linux and ``peat.exe`` on Windows). Additionally, a :term:`Container` image is available for use with :term:`Docker` or :term:`Podman`.

Linux
^^^^^
The recommended method of installation for most users is to run the Bash script, however other methods of installation are documented here in case the installation script doesn't work for your use case.

.. note::
   This guide assumes your current working directory is inside the decompressed :ref:`release-archive`.

Scripted installation
+++++++++++++++++++++
.. code-block:: bash

   cd linux
   sudo bash linux-install-script.sh
   # Verify installation
   peat --version
   man peat

Manual Installation
+++++++++++++++++++
.. code-block:: bash

   cd linux
   sudo cp ./peat /usr/local/bin/peat
   sudo chmod +rx /usr/local/bin/peat

   # Install the manual page ("manpage")
   mkdir -p /usr/local/share/man/man1/
   sudo cp ./peat.1 /usr/local/share/man/man1/
   sudo mandb

   # Verify installation
   peat --version
   man peat

Usage without installation
++++++++++++++++++++++++++
.. code-block:: bash

   cd linux
   chmod u+x ./peat
   ./peat --version
   man ./peat.1

Windows
^^^^^^^
The Windows distribution currently does not require any special installation steps. We recommend verifying that the executable works before using it in a deployed environment. There are some special considorations regarding usage, refer to :ref:`windows-usage` for further details.

.. note::
   This guide assumes your current working directory is inside the decompressed :ref:`release-archive`.

.. code-block:: powershell

   cd windows
   .\peat.exe --version
   .\peat.exe --help

Container
^^^^^^^^^
The :term:`Container` image provides a isolated and reliable method of executing PEAT on any platform with a container runtime. It is usable with both :term:`Docker` and :term:`Podman`. Refer to the :ref:`containers` documentation for further details on the Container distribution and it's usage.

.. note::
   This guide assumes your current working directory is inside the decompressed :ref:`release-archive`.

Docker
++++++
.. code-block:: bash

   cd docker
   docker load -i peat_docker_image.tar

   # Verify the image is present in the list of images
   docker ps

   # Verify the container is able to run
   docker run -i ghcr.io/sandialabs/peat:latest --version
   docker run -i ghcr.io/sandialabs/peat:latest --help

Podman
++++++
.. code-block:: bash

   cd docker
   podman load -i peat_docker_image.tar

   # Verify the image is present in the list of images
   podman ps

   # Verify the container is able to run
   podman run -i ghcr.io/sandialabs/peat:latest --version
   podman run -i ghcr.io/sandialabs/peat:latest --help

.. _release-archive:

PEAT Release Archive
--------------------
The standard distribution method for PEAT is a compressed archive (zip format), referred to as the "PEAT Release Archive". This archive includes:

- The :term:`Container` image (tarball format)
- The Linux executable (``peat``)
- The Windows executable (``peat.exe``)
- The Python source distribution (``.tar.gz``) and binary wheel (``.whl``)
- The Linux man page (``peat.1`` file)
- Some example files

See the earlier sections for details on setting up PEAT for your particular platform and use case.

Archive directory structure
^^^^^^^^^^^^^^^^^^^^^^^^^^^
- ``docker/``
    - ``peat_v<version>_cli_docker_image.tar``: The containerized distribution of PEAT, usable with :term:`Docker` or :term:`Podman`
- ``examples/``: Examples of using PEAT (scripts, etc.), as well as examples of output from running PEAT.
- ``linux/``
    - ``linux-install-script.sh``: Installs the PEAT executable in ``/usr/local/bin``, the man page in ``/usr/local/share/man/man1/``, and updates the ``mandb``. Usage: ``sudo linux/linux-install-script.sh``
    - ``peat``: The PEAT Linux executable. Run with ``./linux/peat``, or ``peat`` after running the install script.
    - ``peat.1``: Man page documentation. View with ``man peat.1``, or ``man peat`` after running the install script.
- ``python_package/``
    - ``PEAT-<version>-py3-none-any.whl``: Python binary "Wheel" distribution of PEAT ("bdist"). Use as a dependency if you are calling the PEAT Python APIs, e.g. any Python code that contains ``import peat`` (excluding custom DeviceModule implementations). Usage: ``pip install PEAT-<version>-py3-none-any.whl``
    - ``PEAT-<version>.tar.gz``: Python source distribution of PEAT ("sdist"). This is the easiest way to view the source code if that's relevant to your use case.
- ``windows/``
    - ``peat.exe``: The PEAT Windows executable. Run with ``.\windows\peat.exe``. We recommend running in an Administrator-level PowerShell terminal or script. Running as a standard user will reduce performance slightly, since certain Windows networking APIs are restricted. This will affect some network features, such as the ability to do ICMP pings, ARP pings, or network sniffing. PEAT will run fine in a CMD terminal but some terminal functionality may not work as well (e.g. terminal output colors and formatting).

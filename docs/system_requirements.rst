*******************
System requirements
*******************
Requirements for deploying and running PEAT, including platforms it can run on, hardware requirements, and other requirements such as network connectivity.

.. _platforms-section:

Supported platforms
===================
.. note::
   The PEAT "executable" (``peat`` on Linux, ``peat.exe`` on Windows) is the standard method of using PEAT. The executable is distribution-agnostic and should work on most distributions of Linux or releases of Windows. The supported platforms for PEAT development or using the PEAT Python API is far more restricted and is generally recent releases of Ubuntu or Windows.

- Linux
   - Ubuntu
      - Ubuntu 14.04+ : ``peat`` executable
      - Ubuntu 20.04+ is required for PEAT development or using the Python API
   - Red Hat Enterprise Linux (:term:`RHEL`)
      - RHEL 6: Works with the pre-built executable or ``podman`` and the PEAT container image
   - `Kali Linux <https://www.kali.org/>`__
      - 2018+ : ``peat`` executable
   - Other distributions: Debian, Debian-based distributions, and RHEL-based distributions (e.g. Fedora and CentOS) should work with the ``peat`` executable, but are not regularly tested. It has been known to work under Debian 9.
- Windows
   - Windows 7 SP2+: While Windows 7 has been tested with the pre-built executable, it's not regularly tested and support is not maintained. Your Mileage May Vary.
   - Windows 10 1809+/Windows Server 2019+ (build 17763): ``peat.exe`` executable, development, and Python API are fully supported and regularly tested on Windows desktop and server build 17763 and newer. 1703+ may work, but hasn't been tested in a while.
   - Windows 11: Windows 11 is not currently tested or formally supported. It may not work with the executable, but it may work with a direct Python install.
- `Windows Subsystem for Linux (WSL) <https://docs.microsoft.com/en-us/windows/wsl/>`__
   - PEAT will work in any WSL Linux distro that's supported by PEAT (e.g. Ubuntu, Kali), listed above.
   - Certain network-related features will not work in WSL, notably MAC address lookups, and a few other functions may not work fully.
- :term:`Docker`
   - Docker 18.03+, Linux host: PEAT is fully supported on Linux-based Docker hosts. PEAT is regularly tested on Docker 20+.
   - Windows and OSX Docker hosts should work but are untested.
   - Versions of Docker older than 18.03 may work, but are unsupported and may not work in recent releases of PEAT.
- :term:`Podman`
   - Podman 1.0+: Tested on :term:`RHEL` 6 and RHEL 7. Non-RHEL hosts are untested for Podman.
- MacOS/OSX
   - OSX is supported on a best-effort basis. There are known issues with some networking components when running on OSX and issues with system dependencies.

Hardware
========
The system hardware requirements for running PEAT are minimal. The limits vary slightly by system.

- Minimum 64-bit x86 CPU (Linux) or 32-bit x86 CPU (Windows); Dual-core 2.4Ghz 64-bit x86 CPU is recommended. Additional cores will not noticeably improve performance.
- Minimum of 64MB available memory (RAM); 256MB is recommended for scanning very large networks or when running PEAT as a container.
- Minimum of 50MB disk space in the platform's temporary directory (``/tmp`` on Linux or ``AppData`` on Windows). This is needed to extract and execute the Python code.
- Minimum of ~100MB disk space in the configured output directory; 1Gb is recommended for storing multiple runs and increased output verbosity, 5-10GB is recommended if pulling from 100+ devices, especially if those devices have significant amounts of logic or configuration.

Network
-------
PEAT requires network connectivity to carryout any active operations (``scan``, ``pull``, and ``push``). Specific considerations are listed below:

- Local subnet - Connection to same subnet as devices (:term:`OSI Model` Layer 2 broadcast domain) is required for broadcast scanning and using :term:`ARP` requests to check if hosts are online.
- Non-local subnets - Routes to connectivity are required if the devices being queried are not on the local subnet. The router(s) must allow :term:`TCP` and :term:`UDP` traffic, and :term:`ICMP` traffic if efficient online checks of hosts in non-local subnets is desired.
- Firewall configuration - The firewall on the system executing PEAT, as well as any firewalls on the network (e.g. a gateway firewall), must be configured to allow outbound :term:`TCP` and :term:`UDP` requests to either all hosts or the specific hosts and subnets being queried. Outbound :term:`ICMP` should also be allowed if efficient online checks of hosts in non-local subnets is desired.
- IDS configuration - The network Intrusion Detection System (:term:`IDS`) exceptions for the host performing the scanning. PEAT's network operations are inherently suspicious to an IDS, especially one tuned for :term:`OT` networks, and it will likely generate numerous false positive alerts during the course of a operation.

System configuration
--------------------
- Access to a terminal is recommended for running PEAT.
- (Windows-only) PowerShell is the preferred terminal on Windows. PEAT will run fine in a legacy Windows cmd terminal, but some terminal-related functionality may be degraded (e.g. text formatting and colors).
- **Administrator (Windows) or root (Linux) permissions are required for some network features**. Note that these permissions are *NOT* required for the offline functions of PEAT (parsing, pillage, etc.).
   - Permissions are required to use of lightweight :term:`ARP` and :term:`ICMP` requests for host status checking. These methods have less impact on the devices being scanned and are significantly faster than using TCP SYNs.
   - Lack of permissions potentially affects PEAT's ability to do broadcast scanning
   - Lack of permissions potentially affects PEAT's ability to use serial devices
- Ability to write output directory is required unless file output is disabled using the appropriate configuration options. Refer to :doc:`configure` for details on configuration options.
- Ability to run executables is required for all distributions other than the container.
- Ability to write and execute temporary files is required if using the executable distribution of PEAT (``peat`` or ``peat.exe``). This is necessary for the executable to unpack and run.
- Host endpoint protection (anti-malware/anti-virus) software may interfere with PEAT's operations. If this occurs, we recommend whitelisting PEAT and it's output directories, or as a last resort temporarily disabling the software. Note that this is highly unlikely and we have yet to witness it in the wild.

Optional software
-----------------
- PEAT documentation: A modern web browser is required to view the HTML version of the PEAT documentation. Most Chromium-based browsers should work, including the Microsoft Edge, Opera, and others. Firefox will also work just fine.
   - Chrome: version 63 or newer
   - Firefox: version 60 or newer
   - Edge
- Containerization: :term:`Docker` or :term:`Podman` are required to run the containerized distribution of PEAT. See :ref:`platforms-section` above for details on specific versions required.

Virtual Machine (VM) requirements and limitations
=================================================
Requirements and limitations for using PEAT inside of a Virtual Machine (VM).

- The use of hardware passthrough to a physical adapter connected to the network being scanned is recommended. If not possible, a bridged network adapter will also work as a fallback, though there are some potential issues with using a bridged adapter, such as the host :term:`OS` interfering with the adapter's configuration or applying firewall rules.
- VM hypervisors: PEAT has been tested with VMWare Workstation Pro (14+), VirtualBox (6+), and QEMU+KVM as class 2 hypervisors with a Linux guest OS (Ubuntu, :term:`RHEL`, Kali, and others). PEAT also fully supports being run inside a :term:`SCEPTRE` experiment, which is hosted with minimega and QEMU. PEAT has not been tested with class 1 hypervisors, e.g. Microsoft Hyper-V or Xen, but it should work in those environments with minimal or no issues.

Containers
----------
Refer to :ref:`containers` for details on requirements and limitations when using the container distribution of PEAT.

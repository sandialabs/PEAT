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
      - Ubuntu 22.04+ is required for PEAT development or using the Python API (PEAT requires Python 3.11 - 3.13)
   - Red Hat Enterprise Linux (:term:`RHEL`)
      - RHEL 6: Works with the pre-built executable or ``podman`` and the PEAT container image
   - `Kali Linux <https://www.kali.org/>`__
      - 2018+ : ``peat`` executable
   - Other distributions: Debian, Debian-based distributions, and RHEL-based distributions (e.g. Fedora and CentOS) should work with the ``peat`` executable, but are not regularly tested. It has been known to work under Debian 9.
- Windows
   - Windows 10 and Windows 11 (x64): ``peat.exe`` executable, development, and Python API are fully supported. Windows Server 2022 and 2025 are also fully supported. See :ref:`windows-ci-section` for the exact versions tested.
   - Windows 11 on ARM (e.g. Snapdragon PCs): ``peat.exe`` and the x64 build of Python run under Windows' built-in x64 emulation, and are tested in CI. Native ARM64 Python is not supported, since several of PEAT's dependencies don't publish ARM64 Windows packages.
   - Windows 10 1809+/Windows Server 2019 (build 17763) and newer should work, but older builds are no longer tested.
   - Windows 8.1 and older: not supported or tested. Microsoft no longer supports them, and Python 3.9 and newer don't run on Windows 7.
   - 32-bit (x86) Windows is not supported.
   - Refer to :ref:`windows-limitations-section` for features that work differently or aren't available on Windows.
- `Windows Subsystem for Linux (WSL) <https://docs.microsoft.com/en-us/windows/wsl/>`__
   - PEAT will work in any WSL Linux distro that's supported by PEAT (e.g. Ubuntu, Kali), listed above, in both WSL 1 and WSL 2.
   - Certain network-related features will not work fully in WSL. MAC address lookups use the Windows host's ``arp.exe`` (or the Linux ARP cache if Windows interop is disabled), and mounting disk images with ``peat pillage`` isn't supported.
   - WSL 2 uses a virtual NAT network by default, so broadcast scans and ARP-based host checks won't reach the Windows host's local network. Use `mirrored networking mode <https://learn.microsoft.com/en-us/windows/wsl/networking#mirrored-mode-networking>`__ or run ``peat.exe`` directly on Windows if you need those.
- :term:`Docker`
   - Docker 18.03+, Linux host: PEAT is fully supported on Linux-based Docker hosts. PEAT is regularly tested on Docker 20+.
   - Windows and OSX Docker hosts should work but are untested.
   - Versions of Docker older than 18.03 may work, but are unsupported and may not work in recent releases of PEAT.
- :term:`Podman`
   - Podman 1.0+: Tested on :term:`RHEL` 6 and RHEL 7. Non-RHEL hosts are untested for Podman.
- MacOS/OSX
   - OSX is supported on a best-effort basis. There are known issues with some networking components when running on OSX and issues with system dependencies.

.. _windows-ci-section:

Windows versions tested in CI
-----------------------------
Every pull request and push runs the full unit test suite with Python 3.11, 3.12, and 3.13, and runs the built ``peat.exe`` and ``sneakypeat.exe``, on the following GitHub-hosted runners. The unit tests are part of the ``All Tests Passed`` check, which pull requests must pass before they are merged.

.. list-table::
   :header-rows: 1

   * - Runner
     - Windows version
     - Corresponding desktop release
   * - ``windows-2022``
     - Windows Server 2022 (build 20348), x64
     - Windows 10 and 11 21H2 era (between Windows 10 21H2, build 19044, and Windows 11 21H2, build 22000)
   * - ``windows-2025``
     - Windows Server 2025 (build 26100), x64
     - Windows 11 24H2 (same build and code base)
   * - ``windows-11-arm``
     - Windows 11 (build 26100), ARM64, running x64 Python and ``peat.exe`` under emulation
     - Windows 11 24H2

.. note::
   GitHub doesn't provide x64 runners with the Windows 10 or Windows 11 desktop editions, so those exact editions are not tested in CI. Windows Server 2025 shares its kernel and networking stack with Windows 11 24H2, Windows Server 2022 is the closest available release to Windows 10, and the ``windows-11-arm`` runner is a Windows 11 desktop image. Windows 10 22H2 itself is supported but only tested manually.

.. _windows-limitations-section:

Windows limitations
-------------------
Most of PEAT works the same on Windows as on Linux. These are the known differences, most of which are inherent to Windows.

- **Administrator recommended for active scanning**: :term:`ICMP` pings, :term:`ARP` requests, and other raw socket features require running PEAT from an Administrator terminal. Without it, PEAT falls back to TCP SYN checks, which are slower. Passive commands (``parse``, and ``pillage`` of a directory) don't need Administrator.
- **Npcap is required for Layer 2 features**: ARP requests, broadcast discovery, and packet sniffing use Scapy, which requires `Npcap <https://npcap.com/>`__ on Windows. Install Npcap (or Wireshark or Nmap, which include it) to use these. Everything else works without it.
- **MAC address lookups**: Linux reads MAC addresses from the local ARP cache. On Windows, if the ``RESOLVE_MAC`` configuration option is enabled, PEAT sends an ARP request (which requires Npcap), and otherwise reads the ARP cache with ``arp.exe``.
- **Disk images in pillage**: ``peat pillage`` mounts VHD, VHDX, and ISO images natively, but other formats (raw, VMDK, qcow2) must be converted with ``qemu-img`` first, which PEAT does automatically if it's installed. Mounting VHD and VHDX images requires Administrator, and only filesystems Windows can read (NTFS, FAT, exFAT, ReFS) are searched. Refer to :ref:`pillage` for details.
- **No YMODEM serial transfers**: SEL relay serial pulls with ``sel.force_ymodem`` require the ``rz``/``sz`` commands, which aren't available on Windows. Regular serial pulls work. Serial ports are named ``COM1``, ``COM2``, and so on.
- **No promiscuous mode check**: PEAT doesn't warn if the network interface is in promiscuous mode on Windows.
- **Output encoding**: when PEAT's console output is redirected to a file or pipe, Windows uses the legacy code page (usually cp1252). Characters it can't represent are escaped (e.g. ``\u2013``) instead of causing an error. Output files PEAT writes (results, logs, JSON) are UTF-8.

Hardware
========
The system hardware requirements for running PEAT are minimal. The limits vary slightly by system.

- Minimum 64-bit x86 CPU, or a 64-bit ARM CPU running Windows 11; Dual-core 2.4Ghz 64-bit x86 CPU is recommended. Additional cores will not noticeably improve performance.
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

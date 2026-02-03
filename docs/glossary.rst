********
Glossary
********

.. glossary::
   :sorted:

   ACL
      Access Control List. Common form of firewalling. Is often used in a network context to refer to firewalls in general.

   API
      Application Programming Interface. Generic term that can refer to programming libraries (e.g a Python package), :term:`HTTP` server endpoints, and other sorts of interfaces to a program or library.

   ARP
      Address Resolution Protocol. :term:`OSI Model` Layer 2 protocol used to resolve an :term:`IP` address to a :term:`MAC` address.

   Artifact
      Chunk of data of interest collected by :term:`PEAT`, such as a device configuration file, firmware binary image, process logic, or log file. Commonly used in the Forensics field to refer to potentially useful data extracted from collected evidence.

   ASCII
      American Standard Code for Information Interchange. Character encoding standard for electronic communication. ASCII codes represent text in computers, telecommunications equipment, and other devices.

   BAC
      Building Automation Control

   BACnet
      Building Automation Control network communications protocol

   BAS
      Building Automation System

   CASCII
      :term:`SEL` Compressed :term:`ASCII` protocol. :term:`SEL` proprietary protocol for communicating to devices.

   CI/CD
      Continuous Integration/Continuous Deployment, a modern software development and testing methodology.

   CID
      Configured :term:`IED` Description. Used to configure communications for a :term:`SEL` device.

   CIDR
      Classless Inter-Domain Routing. CIDR notation is a compact representation of an IP address and its associated routing prefix. The notation is constructed from an IP address, a slash ('/') character, and a decimal number. The trailing number is the count of leading 1 bits in the routing mask, traditionally called the network mask. (Source: `Wikipedia - Classless Inter-Domain Routing <https://en.wikipedia.org/wiki/Classless_Inter-Domain_Routing#CIDR_notation>`__)

   CIP
      Common Industrial Protocol

   CLI
      Command Line Interface

   clx
      Shorthand referring to a Rockwell Automation/Allen-Bradley ControlLogix :term:`PLC`

   CPU
      Central Processing Unit. In a desktop computer, this is the primary processor, e.g. a Intel Core 2 Duo CPU. In a Master :term:`PLC`, this is usually the first module in a rack on the far left. Slave PLCs usually do not have CPUs.

   CSV
      Comma Separated Values. Commonly used table-structured data format.

   Container
      Containers are a form of operating system virtualization. A single container might be used to run anything from a small microservice or software process to a larger application. Inside a container are all the necessary executables, binary code, libraries, and configuration files.

   db
      Database, used generally (though often referring to :term:`Elasticsearch`)

   DCS
      Distributed Control System

   DGA
      Dissolved Gas Analyzer

   dict
      :term:`Python` dictionary

   dir
      Filesystem directory

   DNP3
      Distributed Network Protocol 3.0. :term:`SCADA` communication protocol commonly seen in the electric power industry in the U.S.

   DNS
      Domain Name System

   DPI
      Deep Packet Inspection

   Docker
      Docker is a system for building and running containers. Docker is a set of platform as a service products that use OS-level virtualization to deliver software in packages called containers. Containers are isolated from one another and bundle their own software, libraries and configuration files. Similar to :term:`Podman`. Further reading: `Docker documentation <https://docs.docker.com/>`__

   ECS
      Elastic Common Schema. ECS defines a common set of fields to be used when storing event data in :term:`Elasticsearch`. Refer to the `ECS documentation <https://www.elastic.co/guide/en/ecs/current/index.html>`__ for further details.

   ES
      Elasticsearch

   Elasticsearch
      NoSQL schemaless database that stores data in a :term:`JSON`-like structure. Used for integration of PEAT with other tools.

   elastic
      Refers to an :term:`Elasticsearch` database

   ethip
      EtherNet/IP industrial communications protocol (Not to be confused with Ethernet and TCP/IP)

   FCD
      Field Control Device

   FD
      Field Device. :term:`SCEPTRE` terminology for :term:`OT` devices.

   FQDN
      Fully Qualified Domain Name

   FTP
      File Transfer Protocol

   GE
      General Electric

   GUI
      Graphical User Interface

   GUID
      Globally Unique Identifier

   Golden Image
      General term for a known-good ("golden") device configuration or firmware image. Derives from the :term:`IT` term for a :term:`VM` base-image that is used to create many instances of the same virtual machine.

   HEAT
      High-fidelity Extraction of Artifacts from Traffic. Name of the PEAT capability for extracting and parsing artifacts from network captures (e.g. PCAP file). Refer to :ref:`heat-usage` for more details.

   HMI
      Human-Machine Interface

   HTML
      Hyper-Text Markup Language. Format used to render data in a browser.

   HTTP
      Hyper-Text Transfer Protocol. Plaintext protocol commonly used for transferring web information or making requests to a :term:`REST` :term:`API`.

   ICMP
      Internet Control Message Protocol. :term:`OSI Model` Layer 3 protocol commonly used to determine if a host is alive and responding.

   ICS
      Industrial Control System(s)

   IDS
      Intrusion Detection System. In the context of PEAT this usually refers to a network-based IDS.

   IED
      Intelligent Electronic Device

   INI
      File format, often used for software configurations

   ION
      The Schneider PowerLogic ION family of smart power meters

   I/O
      Input/Output

   IP
      Internet Protocol. The network address of a device, e.g. "IP address". In PEAT, references to "IP" without a version can be assumed to refer to version 4 of the protocol, IPv4. References to version 6 will be explicitly called out, e.g. "IPv6". Example IPv4 address: ``192.168.0.1``

   IT
      Information Technology. In the context of PEAT, this refers to systems and technologies that are not :term:`OT`-specific, such as Windows, anti-malware, firewalls, etc.

   JSON
      JavaScript Object Notation. Commonly used standard for structuring and formatting data.

   "layer <x>"
      Layer in the :term:`OSI Model` commonly used by network engineers (ex: "Layer 3" is the "network" or IP layer).

   LDRD
      Laboratory-Directed Research and Development

   MAC
      Media Access Control. :term:`OSI Model` Layer 2 communication between devices on the same local network (e.g. the same switch). Example MAC address: ``01:02:03:FA:FB:FC``

   MBAP
      Modbus Application. Often seen in Nmap or Wireshark as "mbap" or sometimes as "mbam".

   MIB
      Management Information Base. :term:`SNMP` flat-file, nonrelational database that describes devices being monitored.

   MTU
      Maximum Transfer Unit

   NIC
      Network Interface Card. Often used to refer generally to network interfaces on a host, both physical and virtual.

   NTP
      Network Time Protocol

   Nmap
      The Network Mapper. Open-source tool for active mapping of IP networks. Further reading: `Nmap website <https://nmap.org/>`__

   OS
      Operating System. Examples are Windows, Linux, and MacOS.

   OSI
      Open Systems Interconnection. Generally used to reference the :term:`OSI Model`.

   OSI Model
      Open Systems Interconnection Model. The Open Systems Interconnection model is a conceptual model that characterises and standardises the communication functions of a telecommunication or computing system without regard to its underlying internal structure and technology.

   OT
      Operational Technology. Umbrella term for technology that run critical operations, including :term:`ICS`/:term:`SCADA` and Building Automation Systems.

   OUI
      Organizationally Unique Identifier. 24-bit number that uniquely identifies a vendor, manufacturer, or other organization.

   out_dir
      Output directory

   OpenPLC
      Open-source software ("virtual") :term:`PLC` implemented in C++

   PCAP
      Packet Capture. Used interchangeably as a general term for capturing network traffic or to refer to the ``.pcap`` file format used by ``tcpdump``, ``libpcap``, and many other tools.

   PCCC
      Programmable Controller Communication Command. In the context of PEAT, this is usually referring to the Rockwell PCCC protocol.

   PEAT
      Process Extraction and Analysis Tool. PEAT is a multifunction utility and library for interrogating and mapping :term:`ICS` and :term:`OT` devices, including network discovery, acquiring and parsing artifacts (firmware, logic, etc.), uploading artifacts, and sending commands.

   PLC
      Programmable Logic Controller

   PLCOpen
      Graphical editor for process logic and a standards body

   Pillager
      :term:`PEAT` capability to collect artifacts (e.g. device configs or project files) from engineering workstation disk images or live machines. Refer to :ref:`pillage` for details.

   Podman
      Red Hat's container solution. Similar to :term:`Docker`. Further reading: `Podman documentation <http://docs.podman.io/en/latest/>`__

   pickle
      Python's Pickle protocol, which serializes arbitrary :term:`Python` objects into a stream of bytes. Further reading: :mod:`pickle`

   Port
      Commonly used to refer to network ports. It is an integer used by :term:`TCP` and :term:`UDP` to address applications on a host over a :term:`IP` network.

   Python
      The Python programming language. This is the language :term:`PEAT` is implemented in.

   py
      Shorthand for "Python", e.g. "py3" for "Python 3", "py36" for "Python 3.6", or "py2" for "Python 2"

   RAM
      Random-access Memory

   REPEAT
      Term used to refer to the device recovery (aka "push") capabilities of :term:`PEAT`. May also be written as "rePEAT".

   REPL
      Read Eval Print Loop. Often used to refer to the :term:`Python` command line interpreter interface. Further reading: `Wikipedia - Read-eval-print loop <https://en.wikipedia.org/wiki/Read%E2%80%93eval%E2%80%93print_loop>`__ and the `Python interpreter documentation <https://docs.python.org/3/tutorial/interpreter.html>`__

   REST
      Representational State Transfer. Type of :term:`HTTP` :term:`API` architecture that is stateless and well-defined.

   RHEL
      Red Hat Enterprise Linux. Enterprise-focused distribution of Linux developed by Red Hat, Inc. Widely used in Government and industry and the defacto distribution for critical servers or core infrastructure. Well-known for it's long term support and robust security.

   RTAC
      Real-Time Automation Controller

   RTU
      Remote Terminal Unit

   SCADA
      Supervisory Control and Data Acquisition

   SCEPTRE
      SCEPTRE is a comprehensive :term:`OT` modeling and simulation platform developed by :term:`SNL`. Further reading: `phenix documentation <https://phenix.sceptre.dev/>`__

   SEL
      Schweitzer Engineering Laboratories

   SER
      Sequential Event Recorder

   SIS
      Safety Instrumented System

   SLC
      Small, chassis-based, modular programmable controller by Rockwell Automation and part of the Allen-Bradley product line.

   SNL
      Sandia National Laboratories

   SNMP
      Simple Network Management Protocol

   SNTP
      Simple Network Time Protocol

   SSH
      Secure Shell protocol

   SFTP
      SSH File Transfer Protocol. Basically :term:`FTP` over a SSH connection.

   SOE
      Sequence of Events log. Refers to the system log from SEL RTAC devices aka ``soe.csv``.

   SIEM
      Security Information and Event Management. A cybersecurity solution that enables real-time visibility, detection, and threat hunting by aggregating log and event data from across :term:`IT` infrastructure. Examples of SIEMs include Splunk Enterprise Security and Elastic Security.

   str
      :term:`Python` string

   TC6
      TC6 XML. :term:`XML`-based standard for storing graphical representations of process logic in a portable and implementation-independent manner

   TCP
      Transmission Control Protocol

   TRL
      Technology Readiness Level

   TXT
      Text file or text data (e.g. ".txt")

   UDP
      User Datagram Protocol

   UMAS
      UMAS is a Schneider Electric proprietary protocol that rides on top of Modbus/TCP. It uses the reserved proprietary Modbus/TCP function code 90 (0x5A), and is sometimes referred to as "Function Code 90" or "Func90".

   USB
      Universal Serial Bus

   UTC
      Coordinated Universal Time

   UUID
      Universally Unique Identifier

   VFD
      Variable Frequency Drive

   VM
      Virtual Machine

   VPN
      Virtual Private Network

   Wireshark
      Open-source network traffic analysis tool. Further reading: `Wireshark website <https://www.wireshark.org/>`__, `Wireshark User Guide <https://www.wireshark.org/docs/wsug_html_chunked/>`__, `Wireshark Wiki <https://gitlab.com/wireshark/wireshark/-/wikis/home>`__

   WSL
      Windows Subsystem for Linux. Also known as Bash for Windows. Further reading: `About WSL <https://docs.microsoft.com/en-us/windows/wsl/about>`__ and `WSL installation guide <https://docs.microsoft.com/en-us/windows/wsl/install-win10>`__

   XML
      Extensible Markup Language. Commonly used hierarchical data format, similar to HTML.

   YAML
      Yet Another Markup Language. Format commonly used for software configuration files (".yml" or ".yaml"). Further reading: `YAML 1.2 specification <https://yaml.org/spec/1.2/spec.html>`__

   yml
      File extension commonly used for :term:`YAML` files

   MR
      Merge Request, used when talking about GitLab

   PR
      Pull Request, used when talking about GitHub

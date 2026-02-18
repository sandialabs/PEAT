from __future__ import annotations

import typing
from collections import defaultdict
from ipaddress import IPv4Interface, IPv4Network
from pathlib import Path

from .consts import RUN_ID, START_TIME, AllowedCommTypes, EntrypointType
from .settings_manager import SettingsManager

if typing.TYPE_CHECKING:
    try:
        import peat
    except Exception:
        pass


class Configuration(SettingsManager):
    """
    Global configuration settings used throughout PEAT.
    """

    METADATA: dict = {
        "name": "",
        "description": "",
        "author": "",
        "created": "",
        "updated": "",
    }
    """
    Metadata for the PEAT YAML configuration file.
    """

    ADDITIONAL_MODULES: list[str | Path] = []
    """
    File paths to external/third-party PEAT device modules to import.

    These can be the path to a ``.py`` file with a :class:`~peat.device.DeviceModule`
    subclass or a path to a folder with an ``__init__.py`` file and any number
    of ``.py`` files containing :class:`~peat.device.DeviceModule` subclasses
    to import.
    """

    DEBUG: int = 0
    """
    DEBUG level (higher = more output, 0 = disabled).
    """

    VERBOSE: bool = False
    """
    Include DEBUG messages in the :term:`CLI` terminal output.
    """

    QUIET: bool = False
    """
    Don't write log messages to the :term:`CLI` terminal.
    """

    # TODO: delete in a future release (probably in 2025)
    NO_PRINT_RESULTS: bool = False
    """
    DEPRECATED. Setting this no longer has any effect,
    as it's now the default behavior.
    """

    PRINT_RESULTS: bool = False
    """
    Print JSON-formatted results from the operation to
    the terminal (stdout). Note that log messages will still
    be printed unless '--quiet' is specified.
    """

    NO_COLOR: bool = False
    """
    Don't color log messages in the :term:`CLI` terminal.
    """

    NO_LOGO: bool = False
    """
    Don't print the PEAT logo at startup in the :term:`CLI` terminal.
    """

    DRY_RUN: bool = False
    """
    "Dry run" when running on the CLI, do everything except running commands or
    connecting to servers. Actions won't be executed, but logs and state will
    still be written to files and saved to Elasticsearch (if enabled).
    This includes loading and verifying configuration and importing modules

    Useful for verifying a YAML config file or other settings are correct,
    or that a third-party PEAT module is imported correctly.
    """

    ASSUME_ONLINE: bool = False
    """
    Skip the host online check before scan/pull/push.
    """

    MAX_THREADS: int = 260
    """
    Maximum number of threads for any concurrent operations (scanning, etc.).
    """

    DEFAULT_TIMEOUT: float = 5.0
    """
    Default timeout for sockets and potentially other things.
    """

    RESOLVE_IP: bool = True
    """
    If PEAT should attempt to resolve device :term:`IP`
    address from a hostname or :term:`MAC` address.
    """

    RESOLVE_MAC: bool = True
    """
    If PEAT should attempt to resolve device :term:`MAC`
    address from it's :term:`IP` address.
    """

    RESOLVE_HOSTNAME: bool = True
    """
    If PEAT should attempt to resolve device hostname
    from it's :term:`IP` address.
    """

    FORCE_ONLINE_METHOD_PING: bool = False
    """
    Force :term:`ARP` and :term:`ICMP` requests to be used to check if a host
    is online, even if the system running PEAT isn't able to use them.
    """

    FORCE_ONLINE_METHOD_TCP: bool = False
    """
    Force :term:`TCP` SYNs to be used to check if a host is online, even if
    the system running PEAT is able to use :term:`ARP` or :term:`ICMP` to
    perform the checks.
    """

    ICMP_FALLBACK_TCP_SYN: bool = True
    """
    In the case of a :term:`ICMP` failure, fallback to attempting a
    :term:`TCP` SYN RST to check if the host is online. If false,
    then :term:`ICMP` failures will result in the host being marked
    as down, even if they're blocked by a firewall or gateway.
    """

    SYN_PORT: int = 80
    """
    Default port used for basic :term:`TCP` SYN online checks.
    The default :term:`HTTP` (web) port 80 is generally safe to check.
    """

    PUSH_SKIP_SCAN: bool = False
    """
    Skip scanning and verification of hosts being pushed to and assume
    all hosts are online and valid devices.

    .. note::
       This requires a single device type to be specified
       (the ``-d`` argument on the :term:`CLI`)
    """

    SCAN_SWEEP: bool = False
    """
    Simple host up/down check (equivalent to ``nmap -Pn <hosts>``).

    If serial ports are targeted, this will enumerate the active
    serial ports on the host.
    """

    INTENSIVE_SCAN: bool = False
    """
    Force identification checks of all ports during scanning.
    """

    HASH_ALGORITHMS: list[str] = ["md5", "sha1", "sha256", "sha512"]
    """
    Hash algorithms to use wherever hashes are calculated.
    Available algorithms are any provided by :mod:`hashlib`.
    """

    OUT_DIR: Path = Path.cwd() / "peat_results"
    """
    Default directory for all file output.

    :meta hide-value:
    """

    RUN_DIR: Path = OUT_DIR / f"default-run-dir_{START_TIME}_{RUN_ID}"
    """
    Output directory for all files associated with a single run of PEAT.

    Name format: ``<command>_<config-name>_<timestamp>_<run-id>``

    - ``<command>`` : PEAT command, e.g. "scan", "pull", "parse", etc.
    - ``<config-name>`` : name of YAML config file, set in ``metadata: name: "name"``.
        If no config name is specified, then the string ``default-config`` is used.
    - ``<timestamp>`` : start time of the PEAT run, e.g. ``2022-06-15_13-08-59``.
        This value is retrieved from ``consts.START_TIME``.
    - ``<run-id>`` : Run ID, aka ``agent.id``, e.g. ``165532013980``.
        This value is retrieved from ``consts.RUN_ID``.

    Examples:

    - ``pull_sceptre-test-config_2022-06-17_165532013980``
    - ``scan_default-config_2022-09-27_165532013980``

    :meta hide-value:
    """

    DEVICE_DIR: Path = RUN_DIR / "devices"
    """
    Output directory for files generated by PEAT device modules,
    e.g. pulled config files, firmware images, etc.
    This is the most relevant directory for the majority of PEAT users.

    .. note::
       Device file output can be disabled entirely by setting this to
       a empty string (``""``) or :obj:`None`. This can be useful for
       low-footprint use cases.

    :meta hide-value:
    """

    ELASTIC_DIR: Path = RUN_DIR / "elastic_data"
    """
    Directory where raw documents pushed to Elasticsearch are saved in JSON format.
    These can be used to rebuild the Elasticsearch indices if needed.

    .. note::
       Elastic doc saving can be disabled entirely by setting this to
       a empty string (``""``) or :obj:`None`.

    :meta hide-value:
    """

    LOG_DIR: Path = RUN_DIR / "logs"
    """
    Directory for PEAT's log files.
    Setting this to an empty string will disable output of these files.

    :term:`JSON` formatted log files are also saved here.
    These can be used to rebuild the ``peat-logs`` Elasticsearch index.

    Files that may be created in this directory include:

    - enip/* (Rockwell-specific)
    - peat.log
    - json-log.jsonl
    - elasticsearch.log
    - telnet.log

    :meta hide-value:
    """

    META_DIR: Path = RUN_DIR / "peat_metadata"
    """
    Directory for PEAT's run metadata, notably dumps of PEAT's
    configuration and internal state.

    Setting this to an empty string will disable output of these files.

    .. note::
       Log files are stored separately, in ``logs/``

    Files that may be created in this directory include:

    - peat_configuration.yaml
    - peat_configuration.json
    - peat_state.json
    - Copy of the config file used for the run,
        if applicable (e.g. ``-c my-config.yaml``)

    :meta hide-value:
    """

    SUMMARIES_DIR: Path = RUN_DIR / "summaries"
    """
    Directory for summary results for PEAT commands.

    Files that may be created in this directory include:

    - scan-summary.json
    - pull-summary.json
    - parse-summary.json

    :meta hide-value:
    """

    TEMP_DIR: Path = RUN_DIR / "temp"
    """
    Working directory for file artifacts.
    May be deleted when PEAT exits.

    :meta hide-value:
    """

    ZEEK_LOGDIR: Path = RUN_DIR / "zeek_logs"
    """
    Directory where Zeek logs will be saved. Also contains Zeek artifacts.
    """

    ELASTIC_SERVER: str = None
    """
    URL of the Elasticsearch server.
    """

    ELASTIC_SAVE_LOGS: bool = True
    """
    If PEAT logs should be sent to Elasticsearch.
    """

    ELASTIC_SAVE_CONFIG: bool = True
    """
    If PEAT Configuration dumps should be sent to Elasticsearch on exit.
    """

    ELASTIC_SAVE_STATE: bool = True
    """
    If PEAT State dumps should be sent to Elasticsearch on exit.
    """

    ELASTIC_SAVE_BLOBS: bool = False
    """
    If large binary blobs should be stored in Elasticsearch
    (e.g. firmware images).
    """

    ELASTIC_TIMEOUT: float = 10.0
    """
    Timeout to connect to the Elasticsearch server.
    """

    ELASTIC_DISABLE_DATED_INDICES: bool = False
    """
    Append the current date to Elasticsearch index names.

    Example: when false, a push to ``peat-configs`` on Feb 25 2021
    will actually push to an index named ``peat-configs-2021.02.25``.
    When this option disabled (set to True), the push will instead
    go to ``peat-configs`` (as above, without the date).
    """

    ELASTIC_ADDITIONAL_TAGS: list[str] = []
    """
    Additional tag strings to add to the ``tags`` field for
    each document pushed to Elasticsearch.
    """

    ELASTIC_LOG_INDEX: str = "peat-logs"
    """
    Base name of Elasticsearch index to use PEAT logging events.
    """

    ELASTIC_SCAN_INDEX: str = "peat-scan-summaries"
    """
    Base name of Elasticsearch index to use for scan result summaries,
    e.g. what normally gets written in ``peat_results/<run-dir>/summaries/``.
    """

    ELASTIC_PULL_INDEX: str = "peat-pull-summaries"
    """
    Base name of Elasticsearch index to use for pull result summaries,
    e.g. what normally gets written in ``peat_results/<run-dir>/summaries/``.
    """

    ELASTIC_PARSE_INDEX: str = "peat-parse-summaries"
    """
    Base name of Elasticsearch index to use for parse result summaries,
    e.g. what normally gets written in ``peat_results/<run-dir>/summaries/``.
    """

    ELASTIC_CONFIG_INDEX: str = "peat-configs"
    """
    Base name of Elasticsearch index to use for PEAT configuration dumps
    from runs of PEAT, e.g. what normally gets written in
    ``peat_results/<run-dir>/metadata/``.
    """

    ELASTIC_STATE_INDEX: str = "peat-state"
    """
    Base name of Elasticsearch index to use for PEAT state dumps
    from runs of PEAT, e.g. what normally gets written in
    ``peat_results/<run-dir>/metadata/``.
    """

    ELASTIC_HOSTS_INDEX: str = "ot-device-hosts-timeseries"
    """
    Base name of Elasticsearch index to use for :class:`~peat.data.models.DeviceData`
    data in 'timeseries' form (new entries are created for every collection
    performed or data parsed).

    Information collected by PEAT from field devices or parsed files.
    A new Elasticsearch document is created for every pull of datafrom a device
    (the data is 'timeseries', with differences visible between pulls over time).
    """

    ELASTIC_FILES_INDEX: str = "ot-device-files"
    """
    Base name of Elasticsearch index to use for :class:`~peat.data.models.File` data.

    Information about files present on the device, or that were present on the
    device at one point in time.
    """

    ELASTIC_REGISTERS_INDEX: str = "ot-device-registers"
    """
    Base name of Elasticsearch index to use for :class:`~peat.data.models.Register` data.

    Information about individual communication 'registers' (e.g. Modbus
    registers/coils, DNP3 data points, BACNet objects, etc.) that are
    configured on devices, as extracted from device configuration
    information.
    """

    ELASTIC_TAGS_INDEX: str = "ot-device-tags"
    """
    Base name of Elasticsearch index to use for :class:`~peat.data.models.Tag` data.

    Information about tag variables that are configured on devices,
    as extracted from device configuration information.
    """

    ELASTIC_IO_INDEX: str = "ot-device-io"
    """
    Base name of Elasticsearch index to use for :class:`~peat.data.models.IO` data.

    Information about I/O (Input/Output) available and/or configured
    on a device, as extracted from device configuration information.
    """

    ELASTIC_EVENTS_INDEX: str = "ot-device-events"
    """
    Base name of Elasticsearch index to use for :class:`~peat.data.models.Event`
    data from devices.

    Logging and other event history as extracted from devices.
    Examples include access logs, system logs, or protection history
    """

    ELASTIC_MEMORY_INDEX: str = "ot-device-memory"
    """
    Base name of Elasticsearch index to use for :class:`~peat.data.models.Memory`
    data from devices.

    Memory reads from devices, including address in memory, the value read,
    and information about where it came from and when the read occurred.
    """

    ELASTIC_UEFI_FILES_INDEX: str = "uefi-files"
    """
    Base name of elasticsearch index to use for :class:`peat.data.models.UEFIFiles`

    Information is parsed from a file
    """

    ELASTIC_UEFI_HASHES_INDEX: str = "uefi-hashes"
    """
    Base name of elasticsearch index to use for :class:`peat.data.models.UEFIHash`
    """
    HEAT_ELASTIC_SERVER: str = None
    """
    Elasticsearch server to pull :term:`HEAT` data from.
    """

    HEAT_INDEX_NAMES: str = "packets-*"
    """
    Names and/or patterns of Elasticsearch indices with Packetbeat
    data for :term:`HEAT`.
    """

    HEAT_DATE_RANGE: str = None
    """
    Date range to filter :term:`HEAT` extraction to.
    """

    HEAT_EXCLUDE_IPS: list[str] = []
    """
    IP addresses to exclude from packetbeat search
    (source and/or destination IP).
    """

    HEAT_ONLY_IPS: list[str] = []
    """
    IP address to limit packetbeat search to
    (source or destination IP).
    """

    HEAT_FILE_ONLY: bool = False
    """
    Extract the file(s) but don't parse them using PEAT.
    """

    HEAT_ARTIFACTS_DIR: Path = RUN_DIR / "heat_artifacts"
    """
    Directory where :term:`HEAT` artifacts should be saved.

    :meta hide-value:
    """

    PILLAGE: dict = {}
    """
    Configuration for ``peat pillage`` (:ref:`pillage`).
    """

    DEVICE_OPTIONS: dict = {}
    """
    Protocol and module configuration options that apply to all hosts.
    """

    HOSTS: list[dict] = []
    """
    Specify or override options for specific hosts.
    """

    PCAPS: Path | None = None
    """
    Specify folder that contains PCAPS for processing by HEAT.

    :meta hide-value:
    """

    HEAT_PROTOCOLS: list = []
    """
    Specify protocols for HEAT to use.
    """

    NO_RUN_ZEEK: bool = False
    """
    Don't have PEAT run Zeek on a PCAP, instead run it
    on a PCAP file, then process the output of the PCAP.

    NOTE: zeek_dir must be specified if no_run_zeek is true.
    """

    ZEEK_DIR: Path | None = None
    """
    Directory with existing Zeek output to use as input.

    This is an alternative to PEAT running Zeek on the PCAPs itself.

    NOTE: This argument is required if no_run_zeek is true.

    :meta hide-value:
    """


class State(SettingsManager):
    """
    Global persistent state singleton, e.g. caching results of expensive operations.
    """

    arp_table: str = ""
    """
    The host's ARP table. This is updated if a MAC address lookup is made and the ARP
    table is queried by PEAT. The ARP table is not always queried during lookups,
    so this variable may not always be populated. It also won't be populated if
    ``RESOLVE_MAC`` is False.
    """

    comm_type: AllowedCommTypes | None = None
    """
    Communication method being used for an active command (scan, pull, or push).
    This is a bit of a hack to allow leaking a bit of CLI-specific info
    to device modules that need it.

    Allowed values: ``unicast_ip``, ``broadcast_ip``, ``serial``

    :meta hide-value:
    """

    elastic: peat.Elastic | None = None
    """
    Elastic instance used to interact with a Elasticsearch or OpenSearch database.

    :meta hide-value:
    """

    local_interface_names: list[str] = []
    """
    Names of local network interfaces on the current system, e.g. ``eth0``.

    :meta hide-value:
    """

    local_interface_details: dict[str, dict[str, str]] = {}
    """
    Detailed local interface IPv4 and link configuration information.

    :meta hide-value:
    """

    local_interface_ips: list[str] = []
    """
    :term:`IP` addresses of local interfaces.

    :meta hide-value:
    """

    local_interface_macs: list[str] = []
    """
    :term:`MAC` addresses of local interfaces.

    :meta hide-value:
    """

    local_interface_objects: list[IPv4Interface] = []
    """
    :class:`~ipaddress.IPv4Interface` objects of the local interfaces.

    :meta hide-value:
    """

    local_interface_networks: dict[str, list[IPv4Network]] = defaultdict(list)
    """
    Mapping of local interface names to their associated subnets.

    :meta hide-value:
    """

    local_networks: list[IPv4Network] = []
    """
    Networks the local system is connected to.

    :meta hide-value:
    """

    default_interface_name: str = ""
    """
    The name of the default network interface of the local system.

    :meta hide-value:
    """

    default_interface_ip: str = ""
    """
    The :term:`IP` address of the default network interface of the local system.

    :meta hide-value:
    """

    default_interface_mac: str = ""
    """
    The :term:`MAC` address of the default network interface of the local system.

    :meta hide-value:
    """

    default_gateway: str = ""
    """
    The :term:`IP` address of the default gateway of the local system.

    :meta hide-value:
    """

    raw_socket_capable: bool = False
    """
    If RAW sockets are available (e.g. for :term:`ARP` or :term:`ICMP` requests).

    :meta hide-value:
    """

    entrypoint: EntrypointType = "Package"
    """
    How PEAT is being used (PEAT's "entrypoint").

    Allowed values:

    - CLI: PEAT's CLI internals.
    - Server: if being run as a server, e.g. web UI.
    - Package: any other use of PEAT's API.

    :meta hide-value:
    """

    peat_initialized: bool = False
    """
    If PEAT has been initialized, in other words
    :func:`peat.init.initialize_peat` has been called at least once.

    :meta hide-value:
    """

    written_files: set[str] = set()
    """
    Paths of files written by PEAT during the current run.
    Only includes files that were written using PEAT's APIs.

    .. note::
       These are NOT ordered by when they were written! (it's a :class:`set`)

    :meta hide-value:
    """

    superuser_privs: bool | None = None
    """
    Is PEAT running with permissions of ``root`` (POSIX)
    or ``Administrator`` (Windows).

    :meta hide-value:
    """

    error: bool = False
    """
    If any critical errors occurred during the run of PEAT.

    :meta hide-value:
    """


config = Configuration(label="configuration", env_prefix="PEAT_", init_env=True)
state = State(label="state", env_prefix="PEAT_STATE_", init_env=True)


__all__ = ["Configuration", "State", "config", "state"]

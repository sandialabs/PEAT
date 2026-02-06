import timeit
import traceback
from collections.abc import Callable
from concurrent import futures
from ipaddress import IPv4Address, IPv4Network
from operator import itemgetter
from pprint import pformat
from time import sleep

from humanfriendly.tables import format_pretty_table
from humanfriendly.terminal import ansi_strip
from humanfriendly.text import pluralize
from serial import SerialException

from peat import (
    DeviceError,
    DeviceModule,
    IdentifyMethod,
    IPMethod,
    SerialMethod,
    Service,
    __version__,
    config,
    consts,
    log,
    module_api,
    state,
    utils,
)
from peat.data import DeviceData, datastore
from peat.protocols import (
    check_host,
    check_tcp_port,
    check_udp_service,
    find_serial_ports,
    get_reachable_hosts,
    handle_scan_serial_exception,
    host_string_to_objs,
    hosts_to_ips,
    port_nums_to_addresses,
    sort_ips,
)
from peat.protocols.addresses import expand_filenames_to_hosts


def portscan(
    dev: DeviceData,
    methods: list[tuple[IPMethod, type[DeviceModule]]],
    finish_on_first_success: bool = False,
    full_check_snmp: bool = False,
) -> None:
    """
    Check service status on a host using a provided set of methods.

    Args:
        dev: Device to scan
        methods: List of methods to use. :class:`~peat.device.DeviceModule` classes
            can be provided and any methods associated with them will be added
            to the list of methods to use.
        finish_on_first_success: Return immediately once a method succeeds
            and skip the remaining methods.
        full_check_snmp: Check SNMP using full protocol messages.
            If False, simple TCP SYN-RSTs are used.
    """
    for meth, _ in methods:
        # Check if the port was already checked. This prevents duplication
        # of work if we know the status from elsewhere and also works around
        # duplicate ports (e.g. two separate methods that both use port 80).
        if dev.service_status({"protocol": meth.protocol}) != "unknown":
            continue

        options = dev.options[meth.protocol]
        options["port"] = _determine_port(dev, meth)

        # Module-defined function to check if a port is open
        if meth.port_function:
            success = meth.port_function(dev)
        # If the transport is TCP, use a traditional TCP SYN connect
        elif meth.transport == "tcp":
            success = check_tcp_port(dev.ip, options["port"], options["timeout"], reset=True)
        # TODO: Generic way to check UDP services (right now it's just SNMP)
        #   UDP services: CIP ('identify-type'), HAP, SNMP
        #   Maybe just require port_function be implemented for UDP?
        elif meth.transport == "udp":
            if full_check_snmp and meth.protocol == "snmp":
                timeout = options["timeout"]
                # Minor hack to prevent SNMP from bogging down scans
                if config.is_default_value("DEFAULT_TIMEOUT"):
                    timeout = 2.0
                success = check_udp_service(dev.ip, meth.protocol, options["port"], timeout)
            else:
                # TODO: hack by checking UDP services using TCP SYN-RSTs
                success = check_tcp_port(dev.ip, options["port"], options["timeout"], reset=True)
        else:
            raise DeviceError(f"No port check function for service '{meth.protocol}'")

        val = Service(
            protocol=meth.protocol,
            port=options["port"],
            transport=meth.transport,
            status="open" if success else "closed",
        )
        dev.store("service", val, interface_lookup={"ip": dev.ip})

        if success:
            dev._is_active = True
            # Don't scan any more ports
            if finish_on_first_success:
                return


def _determine_port(dev: DeviceData, method: IPMethod) -> int:
    """
    If the port isn't configured by the user and the method's default
    doesn't match the default for the service, then set the port to
    the method's default instead of the protocols default. A common
    example of this are methods for HTTP services listening on alternate
    ports (e.g. "8080" instead of "80").
    The configured port for the protocol for this device is changed
    to ensure future uses of this device in other areas of PEAT use
    the proper port (anything that uses dev.options[proto][port]).
    """
    options = dev.options[method.protocol]

    if (
        options["port"] == dev._DEFAULT_OPTIONS[method.protocol]["port"]
        and options["port"] != method.default_port
    ):
        return method.default_port
    else:
        return int(options["port"])


def _methods_table(
    meth_mods: list[tuple[IdentifyMethod, type[DeviceModule]]],
    dev: DeviceData | None = None,
) -> str:
    if isinstance(meth_mods[0][0], IPMethod) and "unicast" in meth_mods[0][0].type:
        cols = ["Protocol", "Port", "Reliability", "Method Name", "PEAT Module"]
        rows = [
            (
                m[0].protocol,
                _determine_port(dev, m[0]),
                m[0].reliability,
                m[0].name,
                m[1].__name__,
            )
            for m in meth_mods
        ]
        # Sort by port, then protocol name, then reliability
        rows.sort(key=itemgetter(1, 0, 2), reverse=True)
    elif isinstance(meth_mods[0][0], IPMethod) and "broadcast" in meth_mods[0][0].type:
        cols = ["Protocol", "Port", "Reliability", "Method Name", "PEAT Module"]
        rows = [
            (
                m[0].protocol,
                m[0].default_port,
                m[0].reliability,
                m[0].name,
                m[1].__name__,
            )
            for m in meth_mods
        ]
        # Sort by port, then protocol name, then reliability
        rows.sort(key=itemgetter(1, 0, 2), reverse=True)
    elif isinstance(meth_mods[0][0], SerialMethod):  # SerialMethod
        cols = ["Method Name", "Reliability", "PEAT Module"]
        rows = [(m[0].name, m[0].reliability, m[1].__name__) for m in meth_mods]
        # Sort by Module, then reliability, then name
        rows.sort(key=itemgetter(2, 1, 0))

    table_string = format_pretty_table(data=rows, column_names=cols)
    table_string = ansi_strip(table_string)
    return table_string


def unicast_ip_scan(
    hosts: list[str],
    device_types: list[str | type[DeviceModule]] | None = None,
) -> tuple[dict[str, bool], list[type[DeviceModule]], list[str]] | None:
    """
    Scan a single host directly ("unicast" messages).

    Args:
        hosts: Hosts to scan, as a list of dotted-decimal addresses,
            hostnames, subnets (:term:`CIDR` notation), address ranges,
            and/or :mod:`ipaddress` objects (:class:`~ipaddress.IPv4Address`/
            :class:`~ipaddress.IPv4Network`)
        device_types: Module names (strings) or :class:`~peat.device.DeviceModule`
            classes (objects) to use for identification

    Returns:
        Tuple with results for each device as a :class:`dict` and the
            the modules used for the scan as a :class:`list`. If the
            scan failed :obj:`None` is returned.
    """
    # * Convert mixed hosts/subnets/IPs into a sorted list of IPv4 addresses *
    unsorted_ips = hosts_to_ips(hosts)
    addrs = sort_ips(unsorted_ips)

    if not addrs:
        log.critical(
            f"Scan failed - none of the specified hosts are valid"
            f"\n{pformat(hosts, width=80, indent=2)}"
        )
        state.error = True
        return None

    # * Initial check of what hosts are active *
    active_hosts = addrs
    if config.ASSUME_ONLINE:
        log.warning("Skipping host online check, assuming all hosts are active")
    # If raw_socket_capable, perform online check using ARP/ICMP
    elif state.raw_socket_capable:
        active_hosts = get_reachable_hosts(addrs)
        for ip in active_hosts:
            datastore.get(ip)._is_active = True
        for addr in addrs:  # Indicate that host status has been checked
            datastore.get(addr)._cache["online_status_checked"] = True
    # Use TCP SYN for "peat scan --sweep" if ARP/ICMP are unavailable
    elif config.SCAN_SWEEP:
        active_hosts = get_reachable_hosts(addrs, ports=[config.SYN_PORT])
        for ip in active_hosts:
            dev = datastore.get(ip)
            dev._is_active = True
            dev.populate_fields()
            sweep_svc = Service(port=config.SYN_PORT, status="open", transport="tcp")
            dev.store("service", sweep_svc)
            # NOTE: must mark as verified to make it into Elasticsearch without
            # a "module" field. Since this is a sweep, we want data on the host,
            # even if it wasn't checked using a device module. So, we do it manually.
            dev.populate_fields()
            if state.elastic:
                dev.export_to_elastic()
    else:
        log.warning(
            "TCP SYNs will be used for online checks instead of ARP/ICMP "
            "due to system limitations on raw sockets (likely because of "
            "permissions)"
        )

    # Simple check for what hosts are online ("peat scan --sweep")
    if config.SCAN_SWEEP:
        log.info(
            f"Completed sweep of {pluralize(len(addrs), 'host')}, "
            f"{len(active_hosts)} hosts are active"
        )
        sweep_results = utils.sort(
            {  # Merged dict of online and offline hosts
                **dict.fromkeys(active_hosts, True),
                **{off: False for off in addrs if off not in active_hosts},
            }
        )
        return sweep_results, [], []  # no modules are used for sweep

    if not active_hosts:
        log.warning("Failed unicast_ip_scan: no hosts are active (lightweight checks or sweep)")
        return None

    # * Filter device types to only those with unicast IP methods *
    modules = module_api.lookup_types(device_types, filter_attr="ip_methods")
    modules = [m for m in modules if any(x.type == "unicast_ip" for x in m.ip_methods)]

    log.info(
        f"Scanning {pluralize(len(active_hosts), 'IP')} "
        f"using {pluralize(len(modules), 'module')}: "
        f"{', '.join(x.__name__ for x in modules)}"
    )

    # * Scan each host, in parallel *
    results = run_identify(check_host_unicast_ip, active_hosts, modules)

    return results, modules, addrs


def check_host_unicast_ip(ip: str, modules: list[type[DeviceModule]]) -> bool:
    """
    Identifies an unknown device using unicast IP communication.

    TCP SYN checks are used if :term:`ARP`/:term:`ICMP` scanning is unavailable
    on the host PEAT is running on (if ``state.raw_socket_capable`` is False).

    Args:
        ip: IPv4 address of the device
        modules: :class:`~peat.device.DeviceModule` classes to use for identification

    Returns:
        True if successfully identified, False if identification failed

    Raises:
        DeviceError: Critical error occurred during identification
    """
    if not ip:
        log.critical("check_host_unicast_ip(): ip is None or empty")
        state.error = True
        return False

    if not modules:
        log.critical(f"No modules specified for unicast scan of {ip}")
        state.error = True
        return False

    _log = log.bind(target=ip)
    start_time = timeit.default_timer()

    # Get the device from the global store or create if it doesn't exist
    dev = datastore.get(ip)  # type: DeviceData

    # Edge case: PEAT module for a host is set in config file, but not in
    # the list of modules that are available to scan. In this case, PEAT
    # should emit an error. Previously, it would attempt to use the methods
    # for that module if there were ports open that matched those methods.
    if dev._module and dev._module not in modules:
        _log.error(
            f"The PEAT module '{dev._module.__name__}' that was configured by the user "
            f"for {dev.ip} is not available in the modules that are currently allowed to "
            f"be used by PEAT for scanning. Ensure the module isn't being filtered by "
            f"the '-d' argument. You can also remove the restriction by changing or "
            f"removing the 'peat_module' option for the host in the YAML config. "
            f"Available modules: {', '.join(x.__name__ for x in modules)}"
        )
        state.error = True
        return False

    # If dev._module is specified (because the user configured it in the YAML file),
    # then restrict the methods to only those associated with that module.
    if dev._module:
        _log.debug(
            f"Forcing usage of module '{dev._module.__name__}' for scan of "
            f"{dev.ip} since it was configured in the YAML config file "
        )
        modules = [dev._module]

    # Collect the methods from modules
    methods = [
        (meth, dm)
        for dm in modules
        for meth in dm.ip_methods
        if meth.type == "unicast_ip" and isinstance(meth, IPMethod)
    ]  # type: list[tuple[IPMethod, Type[DeviceModule]]]

    # Sort by reliability, otherwise preserve original order. Python's
    # built-in sorting methods are stable (original order preserved if
    # two entries have the same key).
    methods.sort(key=lambda x: x[0].reliability, reverse=True)

    # Determine if device is online and responding
    # Skip the online check if user says so
    if not config.ASSUME_ONLINE:
        # Don't duplicate online status checks. Check the cache to see if
        # the online status of the host was already checked elsewhere.
        # This prevents redundant additional network traffic.
        if not dev._is_active and dev._cache.get("online_status_checked"):
            return False

        # Check if host is online using ARP or ICMP requests
        # If those aren't available, collect list of
        # ports from ip_methods and scan
        if not dev._is_active and state.raw_socket_capable:
            dev._is_active = check_host(dev.ip)
        elif not dev._is_active:  # Online check using port sweep
            portscan(
                dev=dev,
                methods=methods,
                full_check_snmp=config.INTENSIVE_SCAN,
                finish_on_first_success=not config.INTENSIVE_SCAN,
            )

        # Device isn't responding
        if not dev._is_active:
            if config.DEBUG >= 4:
                _log.trace4(f"{dev.ip} isn't active or responding")
            return False

    unique_ports = {_determine_port(dev, m[0]) for m in methods}
    _log.info(
        f"Checking {pluralize(len(unique_ports), 'port')} for {dev.ip} "
        f"using {pluralize(len(methods), 'method')}"
    )

    port_tbl = _methods_table(methods, dev)
    _log.debug(f"Port methods table\n{port_tbl}")

    # Generate set of protocols to use from the defined methods
    protos = {m[0].protocol for m in methods}  # type: set[str]

    # If no services known, scan ports. This will happen if host active check
    # used ARP/ICMP instead of a port sweep and there's no informer data.
    dev.populate_fields(network_only=True)  # Create Interface object(s)
    if not state.raw_socket_capable or not any(
        s.status in {"open", "verified"} for s in dev.service if s.protocol in protos
    ):
        # If port scan occurred earlier due to lack of raw sockets,
        # then we re-do it to determine what ports are open
        portscan(dev, methods, full_check_snmp=True)

    # If no ports are open, then the scan failed
    if not any(s.status in {"open", "verified"} for s in dev.service if s.protocol in protos):
        _log.info(f"No services found for {dev.ip}")
        return False

    # Generate Interface object and populate MAC/Hostname
    dev.populate_fields(network_only=True)

    # Scan through the services for "open" ports
    open_protocols = [
        s.protocol
        for s in dev.service
        if s.status in {"open", "verified"} and s.protocol in protos
    ]  # type: list[str]

    if not open_protocols and not config.INTENSIVE_SCAN:
        _log.debug(f"No open ports found for {dev.ip}\nServices: {dev.service}")
        return False
    elif not open_protocols and config.INTENSIVE_SCAN:
        # If INTENSIVE_SCAN is enabled, then all identify checks will be used,
        # regardless of open ports
        _log.warning(
            f"{dev.ip} has no open ports but INTENSIVE_SCAN is enabled, "
            f"continuing to check all potential services..."
        )
    else:
        # Determine what methods to use based on open ports and user options
        _log.info(
            f"{dev.ip} has {pluralize(len(open_protocols), 'open port')} "
            f"with {pluralize(len(open_protocols), 'known protocol')}: "
            f"{', '.join(open_protocols)}"
        )
        methods = [m for m in methods if m[0].protocol in open_protocols]

    # Filter out methods that don't have an identify function defined
    methods = [m for m in methods if m[0].identify_function]

    id_tbl = _methods_table(methods, dev)
    _log.info(
        f"Fingerprinting {dev.ip} using {pluralize(len(methods), 'matching method')}\n{id_tbl}"
    )

    # Try each method
    for method, module in methods:
        if not method.identify_function:
            raise consts.PeatError(f"No identify_function defined for method!\n{repr(method)}")

        try:
            _log.debug(f"Identifying {dev.ip} using {module.__name__} {method.protocol} method")
            successful = bool(method.identify_function(dev))
        except Exception as ex:
            _log.warning(
                f"{module.__name__} {method.protocol} method "
                f"failed for {dev.ip} due to an exception: {ex}"
            )
            _log.trace3(f"{traceback.format_exc()}")
            successful = False

        # If the identify method succeeded, then store the service info,
        # mark the device as verified, and update it's data model.
        if successful:
            svc = Service(
                protocol=method.protocol,
                port=dev.options[method.protocol]["port"],
                transport=method.transport,
                status="verified",
            )
            dev.store("service", svc, interface_lookup={"ip": dev.ip})

            # Minor hack to ensure 'verified' status gets updated
            idx = None
            for i, d_svc in enumerate(dev.service):
                if d_svc.protocol == method.protocol:
                    idx = i
                    break
            if idx is not None:
                if not dev.service[idx].transport:
                    dev.service[idx].transport = method.transport
                dev.service[idx].status = "verified"

            dev._is_verified = True
            module.update_dev(dev)  # annotate dev with model/vendor/OS info
            dev._module = module

            _log.info(
                f"Identification method '{method.protocol}' from "
                f"module '{module.__name__}' succeeded for {dev.ip}"
            )

            # Break and finish if identification succeeded, unless
            # intensive scanning is enabled.
            if not config.INTENSIVE_SCAN:
                break
        else:
            # Not successful
            _log.debug(
                f"Identification method '{method.protocol}' from "
                f"module '{module.__name__}' failed for {dev.ip}"
            )
            sleep(0.2)

    elapsed_time = timeit.default_timer() - start_time

    if not dev._is_verified:
        _log.warning(
            f"Failed IP verification of {dev.ip} in {utils.fmt_duration(elapsed_time)} "
            f"using {pluralize(len(methods), 'method')}: {[m[0].name for m in methods]} "
            f"(protocols: {open_protocols})"
        )
        return False

    _log.info(
        f"Scanned {dev.ip} in {utils.fmt_duration(elapsed_time)} "
        f"using {pluralize(len(methods), 'method')} "
        f"(protocols: {', '.join(open_protocols)})"
    )

    return True


def broadcast_scan(
    targets: list[str],
    device_types: list[str | type[DeviceModule]] | None = None,
) -> tuple[dict[str, bool], list[type[DeviceModule]], list[str]] | None:
    """
    Discover devices via network broadcasts.

    .. warning::
       Layer 2 broadcast scanning is not currently supported (as of December 2021)

    If the module supports discovery via Layer 2 (e.g. broadcast :term:`MAC` address
    or network interface) and/or Layer 3 broadcasts (192.168.0.255, etc.). Multicast
    is also considered to be a form of broadcast from PEAT's perspective.

    .. code-block:: bash

       # These should work for "peat pull" as well as scan
       peat scan -d clx -b eno2np1
       peat scan -d clx -b 192.168.0.255
       peat scan -d clx -b 192.168.0.0/24
       peat scan -d clx -b 192.168.0.255/24
       peat scan -d clx -b 192.168.0.255/24 192.168.0.0/24
       peat scan -d clx -b eno2np1 192.168.0.0/24 examples/broadcast_targets.txt

    Args:
        targets: Targets for broadcast scanning. These can be IPv4 subnets,
            IPv4 broadcast addresses, network interfaces, or paths to text
            files containing targets (one target per line).
        device_types: Module names (strings) or :class:`~peat.device.DeviceModule`
            classes (objects) to use for identification

    Returns:
        :class:`tuple` with results for each device as a :class:`dict`, the
            the modules used for the scan as a :class:`list`, and
            the resolved targets as a :class:`list`. If the
            scan failed :obj:`None` is returned.
    """
    if not targets:
        log.error("No broadcast targets specified")
        state.error = True
        return None

    start_time = timeit.default_timer()

    # Expand any filenames into targets
    log.trace(f"Raw broadcast targets (including any file paths): {targets}")
    expanded_targets = {str(x) for x in expand_filenames_to_hosts(targets)}  # type: set[str]
    log.trace(f"Raw broadcast targets (file paths removed/read from): {expanded_targets}")
    log.debug(f"{pluralize(len(expanded_targets), 'broadcast target')} provided")

    # interfaces are simply the local host interfaces
    # that the packets will be sent out of.
    bcast_ip_targets = set()  # type: set[str]
    interfaces = set()  # type: set[str]

    for target in expanded_targets:
        # If any of the targets are in the dict of local interfaces, add the
        # interface broadcast address(es) to the list of Layer 3 target IPs
        if target in state.local_interface_networks:
            if not state.local_interface_networks[target]:
                log.warning(f"No networks configured for interface '{target}'")
            for net in state.local_interface_networks[target]:
                bcast_ip_targets.add(str(net.broadcast_address))
                interfaces.add(target)

        # IP address
        elif target.count(".") == 3:
            objs = host_string_to_objs(target, strict_network=False)
            if isinstance(objs, IPv4Address):
                if not objs.is_multicast and not str(objs).endswith(".255"):
                    log.error(f"IP '{str(objs)}' is likely not multicast or broadcast")
                ip_obj = objs
                bcast_ip_targets.add(str(ip_obj))
            elif isinstance(objs, IPv4Network):
                ip_obj = objs.broadcast_address
                bcast_ip_targets.add(str(ip_obj))
            else:
                log.critical(
                    f"IP target '{str(objs)}' resolved to multiple IPs. "
                    f"This was likely not intended. Note that IP range "
                    f"notation ('x.x.x.40-50') is not supported for "
                    f"broadcast targets, as it doesn't make sense for "
                    f"broadcasts."
                )
                state.error = True
                return None

            # If address is part of any local networks, add the local
            # interface of that network to list of interfaces to use.
            for if_name, if_net in state.local_interface_networks.items():
                if ip_obj in if_net:
                    interfaces.add(if_name)
                    break

        # MAC address (not yet supported)
        elif target.count(":") == 5:
            log.critical(f"MAC address targets are not supported yet. Target: {target}")
            state.error = True
            return None

        # Bad target
        else:
            log.critical(
                f"Broadcast target '{target}' isn't valid. If it's an interface, "
                f"make sure that interface is present on the local system. If it's "
                f"a broadcast address, make sure a local interface is configured "
                f"with that address."
            )
            state.error = True
            return None

    log.debug(
        f"{len(bcast_ip_targets)} IP broadcast targets that will use "
        f"{len(interfaces)} interfaces on the host"
    )
    if config.DEBUG:
        log.debug(f"bcast_ip_targets : {bcast_ip_targets}")
        log.debug(f"interfaces       : {interfaces}")

    # TODO: need to figure out how to do Layer2 here.
    #   'af_link' is always going to be "ff:ff:ff:ff:ff:ff" for "broadcast" field.
    #   This will result in a broadcast on ALL interfaces...which is not what we want.
    # - Can we force scapy/socket to use a specific interface?
    # - Promiscuous ARP for device discovery? (Scapy has ability to do this)
    # - Use IPMethod.supports_layer2 to filter methods for layer 2 scanning?

    # Filter device types to only those with ip_methods defined, and at least
    # one of their methods is of type "broadcast_ip".
    modules = module_api.lookup_types(device_types, filter_attr="ip_methods")
    modules = [m for m in modules if any(x.type == "broadcast_ip" for x in m.ip_methods)]
    log.info(
        f"Broadcast scanning {pluralize(len(bcast_ip_targets), 'IP target')} using "
        f"{pluralize(len(modules), 'module')}: "
        f"{', '.join(x.__name__ for x in modules)}"
    )

    # Collect the methods from modules by filtering to those
    # with a type of "broadcast_ip".
    methods = [
        (meth, dm)
        for dm in modules
        for meth in dm.ip_methods
        if meth.type == "broadcast_ip" and isinstance(meth, IPMethod)
    ]  # type: list[tuple[IPMethod, Type[DeviceModule]]]

    # Sort by reliability, otherwise preserve original order. Python's
    # built-in sorting methods are stable (original order preserved if
    # two entries have the same key).
    methods.sort(key=lambda x: x[0].reliability, reverse=True)

    log.info(f"Broadcast scan methods\n{_methods_table(methods)}")

    # This contains the targets that were "successful", in that at least
    # one device responded to the broadcast. In most cases, this will only
    # have one item, the broadcast IP of the scan. The cases it has more
    # than one are if the user specified multiple broadcast targets to scan,
    # e.g. "peat scan -b 192.168.0.255 10.0.0.255 172.16.0.255"
    bcast_results = {}  # type: dict[str, bool]

    # Try each broadcast method
    sorted_bcast_ip_targets = sorted(bcast_ip_targets)
    for target in sorted_bcast_ip_targets:
        for method, module in methods:
            if not method.identify_function:
                raise consts.PeatError(f"No identify_function defined for method!\n{repr(method)}")

            try:
                target_results = method.identify_function(target)
            except Exception as ex:
                log.warning(
                    f"Broadcast {module.__name__} {method.name} method "
                    f"failed for {target} due to an exception: {ex}"
                )
                target_results = []

            if target_results:
                bcast_results[target] = True

                # Add devices to data model
                for dev_desc in target_results:
                    dev = datastore.get(dev_desc["ip"])
                    svc = Service(
                        protocol=method.protocol,
                        port=dev_desc["port"],
                        transport=method.transport,
                        status="verified",
                    )
                    dev.store("service", svc, interface_lookup={"ip": dev.ip})

                    # --- TODO: HACK (see comment above in check_unicast_ip)
                    idx = None
                    for i, d_svc in enumerate(dev.service):
                        if d_svc.protocol == method.protocol:
                            idx = i
                            break
                    if idx is not None:
                        if not dev.service[idx].transport:
                            dev.service[idx].transport = method.transport
                        dev.service[idx].status = "verified"
                    # --- END HACK

                    dev._is_verified = True
                    dev._is_active = True
                    module.update_dev(dev)  # annotate dev with model/vendor/OS info
                    dev._module = module

                    log.info(
                        f"Identification method '{method.protocol}' from "
                        f"module '{module.__name__}' succeeded for {dev.ip}"
                    )
            else:
                bcast_results[target] = False

    elapsed = timeit.default_timer() - start_time
    log.info(
        f"Finished broadcast scanning of {pluralize(len(expanded_targets), 'target')} "
        f"in {utils.fmt_duration(elapsed)} using {pluralize(len(methods), 'method')}"
    )

    return bcast_results, modules, sorted_bcast_ip_targets


def serial_scan(
    serial_ports: list[str],
    device_types: list[str | type[DeviceModule]] | None = None,
) -> tuple[dict[str, bool], list[type[DeviceModule]], list[str]] | None:
    """
    Scan serial ports for devices.

    Args:
        serial_ports: Serial ports to scan, as a list of integers or ranges.
        device_types: Module names (strings) or :class:`~peat.device.DeviceModule`
            classes (objects) to use for identification

    Returns:
        :class:`tuple` with results for each device as a :class:`dict`, the
            the modules used for the scan as a :class:`list`, and
            the resolved targets as a :class:`list`. If the
            scan failed :obj:`None` is returned.
    """
    if not serial_ports:
        log.critical("serial_scan: serial port list is empty")
        state.error = True
        return None

    # Convert serial port list strings (e.g. ["0-1"]) to a list of ports
    # (e.g. ['/dev/ttyS0', '/dev/ttyS1', '/dev/ttyUSB0', '/dev/ttyUSB1'])
    serial_port_addresses = port_nums_to_addresses(serial_ports)

    if not serial_port_addresses:
        log.critical(f"Serial port string parsing failed (arguments: {serial_ports})")
        state.error = True
        return None

    # Enumerate active serial ports with "--sweep"/"--enumerate"
    # Windows example : peat scan -s 0-4 --sweep -vV
    # Linux example   : sudo -H $(which peat) scan -s 0-4 --sweep -vV
    if config.SCAN_SWEEP:
        active_ports = find_serial_ports(filter_list=serial_port_addresses)
        for port in active_ports:
            dev = datastore.get(port, "serial_port")
            dev._is_active = True
        log.info(
            f"Completed sweep of {pluralize(len(serial_port_addresses), 'serial port')}, "
            f"{len(active_ports)} ports are active"
        )
        sweep_results = utils.sort(
            {  # Merged dict of online and offline ports
                **dict.fromkeys(active_ports, True),
                **{off: False for off in serial_port_addresses if off not in active_ports},
            }
        )
        return sweep_results, [], []  # no modules are used for sweep

    # * Filter device types to only those with Serial methods *
    modules = module_api.lookup_types(device_types, filter_attr="serial_methods")
    modules = [m for m in modules if any(x.type == "direct" for x in m.serial_methods)]

    # * Perform the scan in parallel *
    # TODO: should this be run serially (heh) instead of in parallel?
    log.info(
        f"Scanning {pluralize(len(serial_port_addresses), 'serial port')} "
        f"using {pluralize(len(modules), 'module')}: "
        f"{', '.join(x.__name__ for x in modules)}"
    )
    results = run_identify(check_host_serial, serial_port_addresses, modules)

    return results, modules, serial_port_addresses


def check_host_serial(port: str, modules: list[type[DeviceModule]]) -> bool:
    """
    Identifies an unknown device using serial communication.

    Args:
        port: Serial port to check
        modules: :class:`~peat.device.DeviceModule` classes to use for identification

    Returns:
        True if successfully identified, False if identification failed

    Raises:
        DeviceError: Critical error occurred during identification
    """
    if not port:
        log.critical("check_host_serial(): port is None or empty")
        state.error = True
        return False

    if not modules:
        log.critical(f"No device modules specified for serial scan of {port}")
        state.error = True
        return False

    dev = datastore.get(port, "serial_port")

    # * Collect the methods from modules *
    methods = [
        (meth, dm)
        for dm in modules
        for meth in dm.serial_methods
        if meth.type == "direct" and isinstance(meth, SerialMethod)
    ]  # type: list[tuple[SerialMethod, Type[DeviceModule]]]

    methods.sort(key=lambda x: x[0].reliability, reverse=True)

    # TODO: method to check if a serial port is active before
    #  running the identify methods? Use to set dev._is_active.
    # create a pyserial object, then call isOpen. pass the object to identify
    # methods to use for their checks. try multiple baud rates, which are
    # collected from the device options and/or identify method metadata.
    # do the same thing for other settings, like 8N1
    # those should probably be user-configurable

    for method, module in methods:
        if not method.identify_function:
            raise consts.PeatError(
                f"No identify_function defined for method!\nMethod: "
                f"{repr(method)}\nModule: {module}\nSerial port: {port}"
            )

        try:
            id_result = method.identify_function(dev)  # type: bool
        except SerialException as ex:
            if not handle_scan_serial_exception(dev.serial_port, ex):
                return False
            id_result = False

        if id_result:
            dev._is_active = True
            dev._is_verified = True
            dev._module = module
            module.update_dev(dev)
            return True

    return False


def run_identify(
    scanning_function: Callable, addresses: list[str], modules: list[type[DeviceModule]]
) -> dict[str, bool]:
    """
    Generic function to execute scanning functions in parallel.

    This works with IP and serial scanning functions.

    Args:
        scanning_function: Identify function object to call
        addresses: Host addresses to identify
        modules: :class:`~peat.device.DeviceModule` classes to use for identification

    Returns:
        The result of identification for each host as a :class:`dict`,
        with keys being host strings and values booleans indicating the
        result of the identification.
    """
    log.info(
        f"Beginning scan of {pluralize(len(addresses), 'host')}..."
        f"go get a coffee, this may take a while"
    )

    start_time = timeit.default_timer()

    # Keyed by address
    discovered = {}  # type: dict[str, bool]

    # Run identify checks in threads
    with futures.ThreadPoolExecutor(config.MAX_THREADS) as executor:
        id_results: dict[str, futures.Future] = {}

        # Submit jobs
        for addr in addresses:
            id_results[addr] = executor.submit(scanning_function, addr, modules)

        # Wait on results
        for addr, future in id_results.items():
            try:
                discovered[addr] = future.result()
            except Exception as err:
                log.error(f"Exception occurred while checking {addr}: {err}")
                discovered[addr] = False

    elapsed_time = timeit.default_timer() - start_time

    log.info(
        f"Completed scan of {pluralize(len(addresses), 'device')} in "
        f"{utils.fmt_duration(elapsed_time)} ({pluralize(len(discovered), 'result')})"
    )

    return discovered


def scan(
    scan_targets: list[str],
    scan_type: consts.AllowedCommTypes,
    device_types: list[str | type[DeviceModule]] | None = None,
) -> dict[str, dict | list | str | float | int] | None:
    """
    Scan IP networks and hosts and/or serial ports for :term:`OT` devices.

    Args:
        scan_targets: What to scan, such as network hosts or serial ports
        scan_type: Communication type of the targets. Allowed values:

            - ``unicast_ip``
            - ``broadcast_ip``
            - ``serial``
        device_types: mixed device type strings, alias strings or
            :class:`~peat.device.DeviceModule` classes to scan using.
            If :obj:`None`, all currently imported :class:`~peat.device.DeviceModule`
            modules are used.

    Returns:
        :ref:`scan-summary` as a :class:`dict`, or :obj:`None` if an error occurred
    """
    if config.INTENSIVE_SCAN:
        log.warning("Intensive scanning is ENABLED")

    start_time = timeit.default_timer()

    # * Scan using the scan_type *
    try:
        if scan_type == "unicast_ip":
            func_return = unicast_ip_scan(scan_targets, device_types)
        elif scan_type == "broadcast_ip":
            func_return = broadcast_scan(scan_targets, device_types)
        elif scan_type == "serial":
            func_return = serial_scan(scan_targets, device_types)
        else:
            log.critical(f"Invalid scan_type '{scan_type}'")
            state.error = True
            return None

        # scan function returned None, it failed
        if not func_return:
            return None

        # NOTE: "resolved_targets" are the actual targets used by the scan function
        # after the original targets list was resolved, e.g. converting networks
        # into IPs or reading data from files.
        results = func_return[0]
        modules_used = func_return[1]
        resolved_targets = func_return[2]
    except Exception:
        duration = timeit.default_timer() - start_time
        log.exception(
            f"{scan_type} scan failed after {utils.fmt_duration(duration)} "
            f"due to an unhandled exception"
        )
        state.error = True
        return None

    scan_duration = timeit.default_timer() - start_time

    if not results:
        log.warning(
            f"{scan_type} scan failed: no results (duration: {utils.fmt_duration(scan_duration)})"
        )
        return None

    # * Combine any duplicate devices *
    datastore.deduplicate()

    # * Format scan results *
    online_hosts = [
        dev.get_comm_id() for dev in datastore.objects if dev._is_active and not dev._is_verified
    ]  # type: list[str]

    # Remove fields that are excessive for a summary
    excluded_fields = ["register", "registers", "tag", "io", "event", "memory", "extra"]
    verified_hosts = [
        {
            **dev.export(exclude_fields=excluded_fields),
            "peat_module": dev._module.__name__ if dev._module else "",
        }
        for dev in datastore.verified
    ]  # type: list[dict]

    # Minor hack to make results from a sweep scan usable in a future scan
    if config.SCAN_SWEEP:
        scan_modules = ["scan_sweep"]
    else:
        scan_modules = module_api.lookup_names(modules_used)

    scan_summary = {
        "peat_version": __version__,
        "peat_run_id": str(consts.RUN_ID),
        "scan_duration": scan_duration,
        "scan_modules": scan_modules,
        "scan_type": scan_type,
        "scan_targets": resolved_targets,
        "scan_original_targets": scan_targets,
        "num_hosts_active": len(online_hosts) + len(verified_hosts),
        "num_hosts_online": len(online_hosts),
        "num_hosts_verified": len(verified_hosts),
        "hosts_online": online_hosts,
        "hosts_verified": verified_hosts,
    }

    # * Save scan results to a file *
    utils.save_results_summary(scan_summary, "scan-summary")

    # * Push scan results summary to Elasticsearch *
    if state.elastic:
        log.info(
            f"Pushing scan result summary to {state.elastic.type} "
            f"(index basename: {config.ELASTIC_SCAN_INDEX})"
        )

        if not state.elastic.push(config.ELASTIC_SCAN_INDEX, scan_summary):
            log.error(f"Failed to push scan result summary to {state.elastic.type}")

        for dev in datastore.verified:
            dev.export_to_elastic()

    return scan_summary


__all__ = ["broadcast_scan", "scan", "serial_scan", "unicast_ip_scan"]

from ipaddress import IPv4Address, IPv4Interface, IPv4Network
from pathlib import Path

import netifaces

from peat import consts, log, state


def get_in_scope_interfaces(
    targets: list[IPv4Address | IPv4Network],
) -> list[str]:
    """
    Determine what network interfaces are in scope given a list of targets.

    Args:
        targets: List of :mod:`ipaddress` objects to use for
            scoping (to check interfaces against)

    Returns:
        List of interface names that the targets fall into the networks of
    """
    log.debug(f"Searching for in-scope interfaces for {len(targets)} targets...")

    # While this is not terribly efficient (n^2 + 2n), it's good enough for us
    # Using a Set allows us to add without duplication
    in_scope = set()  # type: set[str]

    for target in targets:
        for iface_name, iface_nets in state.local_interface_networks.items():
            for net in iface_nets:
                if (isinstance(target, IPv4Network) and target.overlaps(net)) or (
                    isinstance(target, IPv4Address) and target in net
                ):
                    in_scope.add(iface_name)
                    break

    sorted_ifs = sorted(in_scope)  # type: list[str]
    log.debug(f"Found {len(sorted_ifs)} in-scope interfaces for {len(targets)} targets")
    log.trace(f"In-scope interfaces: {sorted_ifs}")

    return sorted_ifs


def update_local_interface_cache():
    """
    Populate cache of the local system's network interface information.
    """
    log.debug("Updating local network interface cache...")

    interface_names = netifaces.interfaces()  # type: list[str]
    state.local_interface_names.extend(interface_names)

    for if_name in interface_names:
        if_addresses = netifaces.ifaddresses(if_name)

        inet4 = if_addresses.get(netifaces.AF_INET)
        if inet4 is not None:
            # Store the interface addresses (for debugging and logging)
            state.local_interface_details[if_name] = {"af_inet": inet4}

            # Iterate through all addresses on the
            # interface and add to the global state.
            for item in inet4:
                if not item.get("netmask") or not item.get("addr"):
                    log.warning(f"Skipping Unusual Network Interface {item}")
                    continue

                state.local_interface_ips.append(item["addr"])

                obj = IPv4Interface(f"{item['addr']}/{item['netmask']}")
                state.local_interface_objects.append(obj)

                if str(obj.network.network_address) not in ["0.0.0.0", "169.254.0.0"]:
                    # Add to overall list of networks connected to this host
                    state.local_networks.append(obj.network)
                    # Add to list of networks associated with this interface
                    # NOTE: interfaces can have multiple networks associated with them!
                    state.local_interface_networks[if_name].append(obj.network)

        link = if_addresses.get(netifaces.AF_LINK)
        if link is not None:
            if if_name not in state.local_interface_details:
                state.local_interface_details[if_name] = {"af_link": link}
            else:
                state.local_interface_details[if_name]["af_link"] = link

            for link_item in link:
                state.local_interface_macs.append(link_item["addr"])

    # Default gateway and default interfaces
    try:
        gws = netifaces.gateways()  # type: dict[str, dict]
        if not gws.get("default"):
            log.warning("No default gateway defined")
            return

        gw_ip, iface = gws["default"][netifaces.AF_INET]

        state.default_gateway = gw_ip
        state.default_interface_name = iface

        if iface in state.local_interface_details:
            af_inet = state.local_interface_details[iface].get("af_inet")
            if af_inet:
                state.default_interface_ip = af_inet[0].get("addr", "")

            af_link = state.local_interface_details[iface].get("af_inet")
            if af_link:
                state.default_interface_mac = af_link[0].get("addr", "")
    except Exception:
        log.exception("failed to find default interface or gateway")


def is_promiscuous(iface: str) -> bool:
    """
    Checks if a local network interface is in promiscuous mode.

    .. warning::
       This method does not support Windows (however, :term:`WSL` works fine)

    Args:
        iface: Name of the interface to check

    Returns:
        If the interface is in promiscuous mode
    """
    if consts.POSIX:  # NOTE: this seems to work fine on WSL
        # Source: https://goyalankit.com/blog/promiscuous-mode-detection
        flag_file = Path(f"/sys/class/net/{iface}/flags").resolve()

        if flag_file.exists():
            flags = flag_file.read_text().strip()
            if int(flags, 16) & 0x100:
                log.debug(f"Interface '{iface}' is in promiscuous mode")
                return True
            log.debug(
                f"Interface '{iface}' is not in promiscuous mode, as expected (Flags: {flags})"
            )
        else:
            log.debug(
                f"Failed promiscuous mode detection for interface "
                f"'{iface}': file '{str(flag_file)}' does not exist"
            )

    return False


__all__ = [
    "get_in_scope_interfaces",
    "is_promiscuous",
    "update_local_interface_cache",
]

"""
Methods to pull from Schneider Modicon M340 PLCs.

This includes process logic, configuration, and firmware.

Authors

- Christopher Goes
- Mark Woodard
- Patrica Schulz
"""

import binascii
import socket

from peat import CommError
from peat import log as peat_logger
from peat import utils
from peat.protocols import FTP, SNMP

from .umas_packets import UMASResponse, send_umas_packet

# TODO: use Schneider MIB and proper object names instead of raw OIDs
# The MIB just needs to be compiled like we did for the SIPROTEC MIBs
# misc/m340/SchneiderTFE-V01-04.mib


# TODO: what parts of this are status, and what are config?
def pull_network_config(
    ip: str, timeout: float = 1.0, snmp_community: str = "public"
) -> dict:
    """
    Pull configuration information using SNMP, FTP, and Modbus/TCP.

    Args:
        ip: IP address of the device
        timeout: Time to wait for a service to respond, in seconds
        snmp_community: SNMPv1 Community String to use

    Returns:
        The device configuration information
    """
    log = peat_logger.bind(target=ip)
    log.debug(
        f"Pulling configuration using network services for Schneider device {ip}..."
    )
    device_info = {}

    # Get configuration information from network sources
    # TODO: verified_services
    for service in device_info.get("verified_services", ["FTP", "SNMP", "Modbus/TCP"]):
        # TODO: snmp "verification" may "fail" due to a incorrect community string
        #   We can get a correct one from the project file config
        #   and re-verify using updated string if we find it in the config
        if service == "SNMP":
            try:
                # Pull data from service and add to info
                snmp_module, system = _get_snmp_metadata(
                    ip, community=snmp_community, timeout=timeout
                )
            except Exception as err:
                log.exception(f"Could not pull SNMP metadata: {err}")
                continue  # Skip to next service if there is an error

            # Add the overall system info straight into the device info
            device_info.update(system)

            # Add the information for each module to its corresponding dict
            module_name = "module_" + str(snmp_module["slot"])  # module_<slot #>
            if module_name in device_info:
                # If module exists, add the info
                device_info[module_name].update(snmp_module)
            else:
                # If it doesn't, create it using the info
                device_info[module_name] = snmp_module
        elif service == "FTP":
            try:
                # Pull and parse data from service
                ftp_info = _get_ftp_metadata(ip, timeout=timeout)
            except Exception as err:
                log.exception(f"Could not pull FTP metadata: {err}")
                continue  # Skip to next service if there is an error

            # Merge the FTP info into overall device info
            for index, ftp_value in ftp_info.items():
                # TODO: check slot number
                found_device = False
                if isinstance(ftp_value, dict) and "device" in ftp_value:
                    for j, info_value in device_info.items():
                        if (
                            isinstance(info_value, dict)
                            and info_value.get("model_name") == ftp_value["device"]
                        ):
                            # Check if MAC address found via FTP differs
                            if (
                                "mac_address" in device_info[j]
                                and "mac_address" in ftp_info[index]
                                and device_info[j]["mac_address"]
                                != ftp_info[index]["mac_address"]
                            ):
                                log.warning(
                                    f"Conflicting MAC addresses found for "
                                    f"module {j!s} in device {ip}"
                                )
                                device_info[j]["conflicted_mac_address"] = device_info[
                                    j
                                ]["mac_address"]

                            # Merge the module dicts
                            device_info[j].update(ftp_info[index])
                            found_device = True
                            break

                    if not found_device:
                        device_info[index] = ftp_value  # For things without a module
                else:  # Non-devices (e.g Loader status)
                    device_info[index] = ftp_value
        elif service == "Modbus/TCP":
            try:
                # Pull data from service and add to info
                device_info.update(_get_modbus_metadata(ip, timeout=timeout))
            except Exception as ex:
                log.error(f"Could not pull Modbus/TCP metadata. Error: {ex}")
                continue  # Skip to next service if there is an error
        else:
            log.error(f"Unknown service for device {ip}: {service!s}")

    log.debug(
        f"Finished pulling configuration using network "
        f"services for Schneider device {ip}",
    )
    return device_info


def _get_snmp_metadata(
    ip: str, community: str = "public", timeout: float = 0.5, max_failures: int = 7
) -> tuple[dict, dict]:
    """
    Gets as much device metadata as possible over SNMP.

    Args:
        ip: IPv4 address of the device
        community: SNMP Community string to use
        timeout: SNMP protocol timeout, in seconds
        max_failures: max number of failed requests before raising an exception

    Returns:
        Info for the module hosting SNMP and the overall system, respectfully
    """
    log = peat_logger.bind(target=ip)
    log.info(f"Pulling configuration information for device {ip} over SNMP...")
    module_info = {}
    system_info = {}

    # TODO: make these dicts module-level global constants, mark as typing.Final
    # SNMP OIDs to pull from device.
    # Format: "info_returned": "fully-qualified_oid"
    # Refer to the .MIB file for details on each OID.
    #
    # Since these OIDs are non-mandatory, the requests to make
    # depend on communicationServices results.
    #
    # OIDs for information specific to the module running the SNMP server.
    # First key in tuple is OID, second is type.
    module_oids = {
        # Slot of the CPU
        "slot": ("4.1.3833.1.7.10.0", int),
        # Full name and version of hardware
        "model_name": ("4.1.3833.1.7.1.0", str),
        "module_description": ("2.1.1.1.0", str),
        # Status of module (1=bad, 2=good)
        "module_status": ("4.1.3833.1.7.4.0", int),
        "mac_address": ("4.1.3833.1.7.18.0", str),
        "configured_ipv4_address": ("4.1.3833.1.7.15.0", str),
        "configured_ipv4_netmask": ("4.1.3833.1.7.16.0", str),
        "configured_ipv4_gateway": ("4.1.3833.1.7.17.0", str),
        # Static or DHCP
        "ip_config_mode": ("4.1.3833.1.7.5.0", str),
        # Number of network interfaces present in the module, regardless of state
        "num_network_interfaces": ("2.1.2.1.0", int),
        "bandwidth_management": ("4.1.3833.1.7.7.0", int),
        "communication_services": ("4.1.3833.1.7.3.0", int),
    }

    # OIDs with SMTP email server configuration and status information
    smtp_oids = {
        "service_status": ("4.1.3833.1.9.1.1.1.2.0", int),
        "ipv4_address": ("4.1.3833.1.9.1.1.1.3.0", str),
        "mail_sent_count": ("4.1.3833.1.9.1.1.1.4.0", int),
        "error_count": ("4.1.3833.1.9.1.1.1.5.0", int),
        "last_error": ("4.1.3833.1.9.1.1.1.6.0", int),
        "last_mail_elapsed_time": ("4.1.3833.1.9.1.1.1.7.0", int),
        "link_service_status": ("4.1.3833.1.9.1.1.1.8.0", str),
        # The number of time that the link to the SMTP server has been detected down.
        "server_check_fail_count": ("4.1.3833.1.9.1.1.1.9.0", int),
    }

    # OIDs with Port 502 service configuration and status information
    port_502_oids = {
        # The protocols supported by the Port502 Messaging service:
        # modbusThroughGateway(1)         -- MODBUS protocol through UNITE Gateway
        # modbusDirect (2)                -- MODBUS direct
        # unite(4)                        -- UNITE protocol only
        # modbusThroughGatewayAndUnite(5) -- MODBUS through Gateway and UNITE protocol
        # modbusDirectAndUnite(6)         -- MODBUS direct and UNITE protocol
        "supported_protocol": ("4.1.3833.1.2.2.0", int),
        "service_status": ("4.1.3833.1.2.1.0", str),
        # 1=disabled, 2=enabled
        "port_security": ("4.1.3833.1.2.3.0", int),
        "max_connections": ("4.1.3833.1.2.4.0", int),
        "total_messages_received": ("4.1.3833.1.2.9.0", int),
        "total_messages_sent": ("4.1.3833.1.2.10.0", int),
        "total_errors_sent": ("4.1.3833.1.2.11.0", int),
        # TODO: enumerate through all entries in IPSecurityTable (4.1.3833.1.2.7)
        #   Basically, the offending IP address, and how many attempts they made
    }

    # OIDs with Web server configuration and status information
    web_oids = {
        "service_status": ("4.1.3833.1.5.1.0", int),
        # 1=disabled, 2=enabled
        "password_status": ("4.1.3833.1.5.2.0", int),
        "successful_attempts": ("4.1.3833.1.5.3.0", int),
        "failed_attempts": ("4.1.3833.1.5.4.0", int),
    }

    # OIDs with system-wide information
    system_oids = {
        # profileCPUType
        "full_model": ("4.1.3833.1.7.11.0", str),
        "system_uptime": ("2.1.31.1.5.0", int),
        "implementation_class": ("4.1.3833.1.7.19.0", str),
        "firmware_version": ("4.1.3833.1.7.2.0", str),
    }

    # Create SNMP object to use for pulling data
    snmp = SNMP(ip=ip, timeout=timeout, community=community)
    num_failures = 0

    # Pull information for the module running the SNMP server
    # TODO: threading would help a lot here
    log.debug("Pulling SNMP device modules info...")
    for name, oid_pair in module_oids.items():
        response = snmp.get(f"1.3.6.1.{oid_pair[0]}")
        if not response:
            num_failures += 1
            if num_failures >= max_failures:
                raise CommError(
                    f"Number of failed SNMP query attempts exceeded max of {max_failures}"
                )

            continue

        data = oid_pair[1](response[0]["value_string"])  # Convert data
        if data != "":
            if name == "mac_address":
                # Handle MAC address being represented as
                # raw bytes and not text characters.
                mac = binascii.b2a_hex(bytes(data, "utf-8")).decode().upper()
                module_info["mac_address"] = ":".join(
                    a + b for a, b in zip(mac[::2], mac[1::2])
                )
            elif "ipv4" in name:
                # snmp.get() will generate a IP string
                module_info[name] = data
            elif name == "module_status":
                module_info[name] = "ok" if data == 2 else "nok"
            elif name == "bandwidth_management":
                module_info[name] = "enabled" if data == 2 else "disabled"
            elif name == "communication_services":
                srvcs = {}
                bits = [int(x) for x in f"{int(data):07b}"]
                srvcs["port_502_messaging"] = (
                    "supported" if bits[0] == 1 else "unsupported"
                )
                srvcs["io_scanning"] = "supported" if bits[1] == 1 else "unsupported"
                srvcs["global_data"] = "supported" if bits[2] == 1 else "unsupported"
                srvcs["web"] = "supported" if bits[3] == 1 else "unsupported"
                srvcs["address_server"] = "supported" if bits[4] == 1 else "unsupported"
                srvcs["time_management"] = (
                    "supported" if bits[5] == 1 else "unsupported"
                )
                srvcs["email"] = "supported" if bits[6] == 1 else "unsupported"
                module_info[name] = srvcs
            else:
                module_info[name] = data

    # Pull SMTP email server information for the module
    smtp_info = {}
    log.debug("Pulling SNMP email server info...")
    for name, oid_pair in smtp_oids.items():
        response = snmp.get(f"1.3.6.1.{oid_pair[0]}")
        if not response:
            continue

        data = oid_pair[1](response[0]["value_string"])  # Convert data
        if data != "":
            if "ipv4" in name:
                # snmp.get() will generate a IP string
                smtp_info[name] = data
            elif name == "link_service_status":
                # 1 = nok, SMTP server is unreachable
                # 2 = ok, SMTP server can be reached
                smtp_info[name] = "reachable" if data == 2 else "unreachable"
            elif name == "service_status":
                if data == 1:
                    smtp_info[name] = "no configuration"
                elif data == 2:
                    smtp_info[name] = "operational and running"
                else:
                    smtp_info[name] = "stopped"
            else:
                smtp_info[name] = data
    module_info["smtp_server"] = smtp_info

    # Pull Port 502 service information for the module
    supp_protos = {
        1: "modbusThroughGateway",
        2: "modbusDirect",
        # Don't ask me what 3 is...it's like Station 9-3/4
        4: "unite",
        5: "modbusThroughGatewayAndUnite",
        6: "modbusDirectAndUnite",
    }
    port_502_info = {}
    log.debug("Pulling SNMP Port502 info...")
    for name, oid_pair in port_502_oids.items():
        response = snmp.get(f"1.3.6.1.{oid_pair[0]}")
        if not response:
            continue

        # Convert data
        data = oid_pair[1](response[0]["value_string"])
        if data != "":
            if name == "port_security":
                port_502_info[name] = "enabled" if data == 2 else "disabled"
            elif name == "supported_protocol":
                port_502_info[name] = supp_protos[data]
            elif name == "service_status":
                port_502_info[name] = "operational" if data == 2 else "no configuration"
            else:
                port_502_info[name] = data
    module_info["port_502"] = port_502_info

    # Pull Web server info
    web_info = {}
    log.debug("Pulling SNMP web server info...")
    for name, oid_pair in web_oids.items():
        response = snmp.get(f"1.3.6.1.{oid_pair[0]}")
        if not response:
            continue

        # Convert dataQ
        data = oid_pair[1](response[0]["value_string"])
        if data != "":
            if name == "password_status":
                web_info[name] = "enabled" if data == 2 else "disabled"
            elif name == "service_status":
                web_info[name] = "operational" if data == 2 else "no configuration"
            else:
                web_info[name] = data
    module_info["web_server"] = web_info

    # Get information on LEDs on the module and their state
    # TODO: make more generic by dynamically determining
    # how many LEDs there are at runtime.
    led_oids = {
        "name": ("4.1.3833.1.7.9.1.2", str),
        "description": ("4.1.3833.1.7.9.1.3", str),
        "state": ("4.1.3833.1.7.9.1.4", int),
    }
    led_info = {}
    log.debug("Pulling SNMP LED info...")
    for name, oid_pair in led_oids.items():
        # Pull information on each LED over SNMP
        responses = snmp.get(
            identity=f"1.3.6.1.{oid_pair[0]}",
            single_query=False,
            # TODO: manual limit as workaround until MIB import is added
            # Assume there are 5 LEDs
            query_limit=5,
        )
        if not responses:
            continue

        led_info[name] = [oid_pair[1](x["value_encoded"]) for x in responses]
    for i in range(5):
        # Convert from the lists of values per OID to dict of info per LED
        info = {}
        for k in led_oids.keys():
            info[k] = led_info[k][i]
        module_info["led_" + str(i)] = info

    # Pull information for the overall system
    log.debug("Pulling SNMP overall system info...")
    for name, oid_pair in system_oids.items():
        response = snmp.get(f"1.3.6.1.{oid_pair[0]}")
        if not response:
            continue

        data = oid_pair[1](response[0]["value_string"])
        if data != "":
            system_info[name] = data

    return module_info, system_info


def _get_ftp_metadata(
    ip: str,
    user: str = "loader",
    passwd: str = "fwdownload",
    port: int = 21,
    timeout: float = 5.0,
) -> dict:
    """
    Gets as much device metadata as possible over FTP.

    Args:
        ip: IPv4 address of the device
        user: FTP username
        passwd: FTP password
        port: TCP port for FTP service
        timeout: Number of seconds to wait before timing out

    Returns:
        The information found, or empty :class:`dict` if no info was found
    """
    log = peat_logger.bind(target=f"{ip}:{port}")
    log.info(f"Pulling configuration information for {ip}:{port} via FTP...")

    try:
        with FTP(ip, port, timeout) as ftp:
            if not ftp.login(user, passwd):
                log.error(f"Failed FTP login on {ip}:{port}")
                return {}

            ldst_data = ftp.cmd("LDST")
            dinf_data = ftp.cmd("DINF")
            sd_data = ftp.cmd("FREE")
    except Exception as ex:
        log.error(f"Failed to pull FTP data from {ip}: {ex}")
        return {}

    device_info = {}

    # ** Loader status (LDST) **
    loader_status = {}
    ldst_data = ldst_data.split("\n")[1]  # Remove "200" lines
    ldst_data = ldst_data.replace(" ", "").split(",")  # Clean spaces and split
    for pair in ldst_data:
        split = pair.split("=")
        loader_status[utils.convert_to_snake_case(split[0])] = split[1]
    device_info["loader_status"] = loader_status

    # ** Device info (DINF) **
    # Each module is defined by: FwLoc, HwId, FwId, Device, Ir, Desc, Date, MAC
    # Split, Remove "200" lines, recombine
    dinf_data = "".join(dinf_data.split("\n")[1:-1])
    module_number = 0
    next_str, parted, curr_str = dinf_data.rpartition("FwLoc=")
    while "FwLoc=" in parted:
        # Split into key-values, remove trailing whitespace and single quotes
        module_data = [x.strip().replace("'", "") for x in curr_str.split(",")]

        # Remove empty strings
        module_data = list(filter(None, module_data))
        module_info = {}
        module_tag = "device_" + str(module_number)

        # Get the metadata from the key-value pairs
        module_info["fw_loc"] = module_data[0]

        for pair in module_data[1:]:
            split = pair.split("=")

            if split[0] == "Desc":
                key = "description"
            elif split[0] == "HwId":
                key = "hardware_id"
            else:
                key = utils.convert_to_snake_case(split[0])

            if key == "ir":
                module_info[key] = int(split[1])
            # TODO: is "Date" the manufacture date or firmware flash date?
            elif key == "date":
                module_info["timestamp"] = split[1].replace("#dt", "")
            elif key == "mac":
                module_info["mac_address"] = split[1].replace("-", ":")
            else:
                module_info[key] = split[1]

        # Save the module info
        device_info[module_tag] = module_info

        # Move to the next section (next module)
        next_str, parted, curr_str = next_str.rpartition("FwLoc=")
        module_number += 1

    # ** Free space on the SD card (FREE) **
    device_info["free_space_sd_card"] = int(sd_data.split("=")[-1].strip())

    return device_info


def _get_modbus_metadata(ip: str, timeout: float = 5.0, port: int = 502) -> dict:
    """
    Gets as much device metadata as possible over Modbus/TCP.

    Args:
        ip: IPv4 address of the device
        timeout: Number of seconds to wait before timing out
        port: TCP port of the Modbus service

    Returns:
        The information found, or empty :class:`dict` if none was found
    """
    log = peat_logger.bind(target=f"{ip}:{port}")
    log.info(f"Pulling configuration information from {ip} over Modbus/TCP...")

    # TODO: put socket in a with statement
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        sock.connect((ip, port))
    except OSError as err:
        log.error(f"Failed to pull Modbus metadata from {ip}: {err}")
        sock.close()
        return {}

    device_info = {}

    # Get the memory card model
    # Source: github.com/digitalbond/Redpoint/blob/master/modicon-info.nse
    # TODO: is there more information from this?
    payload = binascii.unhexlify("01bf00000005005a000606")
    response = send_umas_packet(sock, payload, UMASResponse)
    device_info["memory_card_model"] = bytes(response.payload)[3:-1].decode()

    sock.close()
    log.debug(f"Metadata found over Modbus for device {ip}: {device_info!s}")

    return device_info

import ast
import copy

from peat import DeviceData, Interface, Service, User, consts, log, utils

from .fortigate_consts import FG_TIMEZONES

# HA: High Availability
# VDOM: Virtual Domain(s)

# TODO: change dev.service to be key'd by port?


def strip_quotes(data: dict):
    if isinstance(data, dict):
        return {strip_quotes(key): strip_quotes(value) for key, value in data.items()}
    elif isinstance(data, list):
        return [strip_quotes(item) for item in data]
    elif isinstance(data, str):
        return data.replace('"', "")
    else:
        return data


def fg_conf_to_dict(raw_data: str) -> dict:
    """
    Converts a raw Fortigate configuration file to a Python
    dictionary using Python's ast library.
    """

    prepared_content = []
    indent_level = 0

    # TODO: extract config-version from first line in file
    # TODO: dev.endian

    for line in raw_data.splitlines():
        line = line.strip()

        if not line or line.startswith("#"):  # Skip empty lines and comments
            continue

        if line.startswith("config") or line.startswith("edit"):
            block_name = line.split(maxsplit=1)[1].strip('"')
            prepared_content.append(" " * indent_level + f"'{block_name}': {{")
            indent_level += 4

        elif line.startswith("set"):
            key, value = line.split(maxsplit=1)[1].split(maxsplit=1)
            if value == "''":  # this breaks how parsing is being done
                value = '""'
            prepared_content.append(" " * indent_level + f"'{key}': '{value}',")

        elif line.startswith("next") or line.startswith("end"):
            indent_level -= 4
            prepared_content.append(" " * indent_level + "},")

    # Wrap in a top-level dictionary
    prepared_content = "{\n" + "\n".join(prepared_content) + "\n}"

    # Parse the Python-like dictionary into a Python object
    try:
        parsed_dict = ast.literal_eval(prepared_content)
    except (SyntaxError, ValueError) as e:
        raise ValueError(f"Failed to parse config: {e}") from None

    # nest the config sections (un-flatten)
    un_flattened = {}
    for key, value in parsed_dict.items():
        if " " in key:
            parts = key.split(" ")
            d = un_flattened
            for part in parts[:-1]:
                if part not in d:
                    d[part] = {}
                d = d[part]
            d[parts[-1]] = value
        else:
            un_flattened[key] = value

    # TODO: strip quotation marks from strings
    un_flattened = strip_quotes(un_flattened)

    return un_flattened


def process_fg_system(system: dict[str, dict], dev: DeviceData) -> None:
    # === global ===
    if system["global"].get("hostname"):
        dev.hostname = system["global"].pop("hostname")
    if system["global"].get("alias"):
        dev.name = system["global"].pop("alias")

    # Parse timezone from integer to standard string
    # The fortigate timezones don't match TZ database names
    # For now, just use the name that was extracted from docs.
    if system["global"].get("timezone"):
        try:
            # TODO: use pytz and levenshtein distance to determine name,
            # since a given offset can have multiple timezones associated.
            # https://stackoverflow.com/a/35086476
            tz_name = FG_TIMEZONES[int(system["global"].pop("timezone"))]["timezone"]
            dev.geo.timezone = tz_name
        except (ValueError, KeyError) as ex:
            log.warning(f"Failed to parse Fortigate timezone: {ex}")

    # === interface ===
    # Network interfaces
    for if_name, si in system.get("interface", {}).items():
        iface = Interface(
            name=if_name,
            id=if_name,
        )

        # TODO: parse "speed", set iface.speed and iface.duplex
        # don't have an example config with this parameter set

        # IP address and subnet mask, space-separated
        if si.get("ip"):
            iface.ip, iface.subnet_mask = si.pop("ip").split(" ")

        # Don't have examples of this, hope it works
        if si.get("macaddr"):
            iface.mac = si.pop("macaddr")

        if si.get("alias"):
            # this can be a human-readable string, e.g. "OUTofBand Mgmt Interface"
            iface.alias = si.pop("alias")
        if si.get("description"):
            iface.description.description = si.pop("description")

        if si.get("type"):
            iface.type = si.pop("type").lower()
            iface.physical = bool(iface.type == "physical")

        if si.get("snmp-index"):
            si["snmp-index"] = int(si["snmp-index"])

        # Permitted types of management access to this interface
        if si.get("allowaccess"):
            protocols = si["allowaccess"].replace("ping", "icmp").split(" ")
            dev.related.protocols.update(protocols)

            for proto in protocols:
                svc = dev.retrieve("service", {"protocol": proto})
                if svc and not any(s.protocol == proto for s in iface.services):
                    iface.services.append(svc)
                else:
                    svc = Service(protocol=proto)
                    dev.store("service", svc, lookup="protocol")
                    iface.services.append(svc)

        # save remaining parameters in "extra"
        iface.extra = si
        dev.store("interface", iface, lookup="id")

    # === accprofile ===
    # Roles and permissions
    if system.get("accprofile"):
        dev.related.roles.update(system["accprofile"].keys())

    # === admin ===
    # Admin users
    for name, sa in system["admin"].items():
        user = User(name=name)

        # VDOM: Virtual Domain
        if sa.get("accprofile"):
            role = sa.pop("accprofile")
            user.roles.add(role)
            user.permissions.update(system.get("accprofile", {}).keys())

        # exclude excessive/uninteresting data from user.extra
        for key in [
            "gui-dashboard",
            "gui-default-dashboard-template",
            "gui-ignore-release-overview-version",
            "password",
        ]:
            sa.pop(key, None)

        # store remaining values
        user.extra = sa

        dev.store("users", user, lookup="name")

    # DNS configuration
    if system.get("dns"):
        for key in [
            "primary",
            "secondary",
            "alt-primary",
            "alt-secondary",
            "ip6-primary",
            "ip6-secondary",
            "source-ip",
        ]:
            if system["dns"].get(key):
                if utils.is_ip(system["dns"][key]):
                    dev.related.ip.add(system["dns"][key])
                else:
                    log.warning(f"Invalid IP for Fortigate DNS server: {system['dns'][key]}")

        if system["dns"].get("server-hostname"):
            dev.related.hosts.add(system["dns"]["server-hostname"])

        # cleartext => DNS over UDP/56 or TCP/53
        # dot = DNS over TLS
        # doh = DNS over HTTPS
        if system["dns"].get("protocol"):
            proto = system["dns"]["protocol"]
            if proto == "cleartext":
                proto = "dns"
            dev.related.protocols.add(proto)

    # === snmp sysinfo ===
    if system.get("snmp"):
        svc = dev.retrieve("service", {"protocol": "snmp"})
        if not svc:
            svc = Service(protocol="snmp")
        # this is basic and API needs improvement
        elif isinstance(svc, list):
            svc = svc[0]

        # TODO: assume SNMP port is default for now, our example
        # config didn't have it configured anywhere.
        svc.port = 161
        svc.transport = "udp"  # SNMP is always UDP :)

        if system["snmp"].get("sysinfo"):
            sns = system["snmp"]["sysinfo"]
            if sns.get("description"):
                if not dev.description.description:
                    dev.description.description = sns["description"]
                else:
                    dev.description.description += f"---SNMP description: {sns['description']}"

            if sns.get("status"):
                svc.enabled = consts.str_to_bool(sns.pop("status"))

            if sns.get("location"):
                dev.geo.name = sns.pop("location")

            if sns.get("contact-info"):
                contact = sns.pop("contact-info")
                dev.description.contact_info = contact
                if utils.is_email(contact):
                    dev.related.emails.add(contact)

        # SNMP community configuration. I can't make much sense of it
        # at the moment, I think it's SNMP TRAP targets.
        for comm in system["snmp"].get("community", {}).values():
            # SNMP managers
            if key in ["hosts", "hosts6"]:
                if comm.get(key):
                    for host in comm[key].values():
                        if host.get("ip"):
                            # IP and subnet mask
                            ip = host["ip"].split(" ")[0]
                            if utils.is_ip(ip):
                                dev.related.ip.add(ip)

        dev.store("service", svc, lookup="protocol")

    # This has a email address
    if system.get("fortiguard"):
        sai = system["fortiguard"].get("service-account-id")
        if sai and utils.is_email(sai):
            dev.related.emails.add(sai)

    # "Configure the email server used by the FortiGate various things.
    # For example, for sending email messages to users to support
    # user authentication features."
    if system.get("email-server"):
        ses = system["email-server"]
        dev.related.protocols.add("smtp")

        if ses.get("server"):
            if not utils.is_ip(ses["server"]):
                dev.related.hosts.add(ses["server"])

        # Extract IP addresses
        for key in ["server", "source-ip", "source-ip6"]:
            if ses.get(key) and utils.is_ip(ses[key]):
                dev.related.ip.add(ses[key])

        if ses.get("port"):
            dev.related.ports.add(int(ses["port"]))

        if ses.get("username"):
            dev.related.user.add(ses["username"])

    # A session helper binds a service to a TCP or UDP port.
    # https://community.fortinet.com/t5/FortiGate/Technical-Tip-Enable-and-disable-FortiGate-system-session/ta-p/191762
    for p_id, p_vals in system.get("session-helper", {}).items():
        # Each of these values should have name, protocol, port
        # "protocol" => IP protocol numbers defined by IANA
        # 6 => TCP, 17 => UDP
        svc = Service(protocol=p_vals["name"])
        svc.port = int(p_vals["port"])
        svc.transport = consts.IANA_IP_PROTOS.get(int(p_vals["protocol"]), "")
        svc.protocol_id = str(p_id)
        dev.store("service", svc, lookup="protocol")

    # DHCP server configuration
    for dh in system.get("dhcp", {}).get("server", {}).values():
        # TODO: add a DHCP service and associate it with relevant interfaces
        # svc = Service(protocol="dhcp")

        if dh.get("default-gateway") and utils.is_ip(dh["default-gateway"]):
            dev.related.ip.add(dh["default-gateway"])

    # TODO: system["ntp"]
    # TODO: "system sdwan" => related.urls, related.protocol

    # TODO
    # save remaining parameters in "extra"
    # dev.extra["system"] = system


def process_fg_conf(fg_conf: dict[str, dict], dev: DeviceData):
    # Reference: FortiOS-7.2.9-CLI_Reference.pdf

    # make a copy that can be safely mutated during processing
    conf = copy.deepcopy(fg_conf)

    if conf.get("system"):
        process_fg_system(conf["system"], dev)

    # Global FortiAnalyzer settings
    if conf.get("log"):
        # TODO: conf["log"]["tap-device"] => port/service

        if conf["log"].get("fortianalyzer", {}).get("setting"):
            fas = conf["log"]["fortianalyzer"]["setting"]

            # Extract IP addresses
            for key in ["server", "source-ip"]:
                if fas.get(key) and utils.is_ip(fas[key]):
                    dev.related.ip.add(fas[key])

            dev.extra["fortianalyzer"] = fas

    # TODO: verify this in the UI
    if conf.get("web-proxy", {}).get("explicit"):
        wpe = conf["web-proxy"]["explicit"]
        # TODO: add a service for HTTP
        # TODO: there may be HTTP services on multiple ports,
        #   we need to do better lookup than "protocol" (maybe "port"?)
        # if wpe.get("status"):
        #     consts.str_to_bool(wpe["status"])
        if wpe.get("http-incoming-port"):
            dev.related.ports.add(int(wpe["http-incoming-port"]))

    # TODO: "user local" and "user group" => Users

    # TODO: add protocols from conf["router"]
    # TODO: conf["router"]["static"]
    # TODO: conf["router"]["ospf"]

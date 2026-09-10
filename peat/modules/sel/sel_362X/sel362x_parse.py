"""
Parse methods for the SEL 3622 and 3620

Authors:

- Francisco Santana
- Nehal Ameen
"""

from hashlib import sha256
from pathlib import Path
from typing import Any, Final, Literal
from zipfile import ZipFile

from bs4 import BeautifulSoup
from bs4.element import ResultSet, Tag
from loguru import logger

from peat import DeviceData

# ---------------------------------------------------------------------------- #
#                                Helper Methods                                #
# ---------------------------------------------------------------------------- #


def ptagattr(attr: dict[str, str | list[str]]) -> str:
    """
    Pretty-print the list of tag attributes
    """
    result = ""

    for a in attr:
        if isinstance(attr[a], str):
            result += f"\n- {a}: {attr[a]}"
        else:
            possible_values = attr[a]
            out = f"{possible_values[0]}"

            if len(possible_values) > 1:
                for v in possible_values[1:]:
                    out += f" | {v}"

            result += f"\n- {a}: {out}"
    return result


def find_tag(
    source: BeautifulSoup | Tag,
    tagty: str | None = None,
    attrib: dict[str, str | list[str]] = {},
    recursive: bool = True,
) -> Tag | None:
    """
    Get a tag from a page or a group
    """

    tag = source.find(tagty, attrib, recursive)

    if not isinstance(tag, Tag):
        return None
    else:
        return tag


def find_tag_f(
    source: BeautifulSoup | Tag,
    tagty: str,
    attrib: dict[str, str | list[str]] = {},
    recursive: bool = True,
) -> Tag:
    """
    Find a tag from a page or group, or raise an exception
    """

    tag = find_tag(source, tagty, attrib, recursive)

    if not tag:
        raise Exception(f"Failed to find {tagty} with attributes {ptagattr(attrib)}")

    return tag


def find_tags(
    source: BeautifulSoup | Tag,
    tagty: str,
    attrib: dict[str, str | list[str]] = {},
    recursive: bool = True,
) -> list[Tag]:
    """
    Get every tag from a page or a group
    """

    tag = source.find_all(tagty, attrib, recursive)

    if not isinstance(tag, ResultSet):
        return []
    else:
        return [t for t in tag]


def find_table(
    source: BeautifulSoup | Tag,
    attrib: dict[str, str | list[str]] = {},
) -> Tag:
    """
    Specialization of find_tag for tables
    """
    t = find_tag(source, "table", attrib)

    if not isinstance(t, Tag):
        raise Exception(f"Failed to find table with attributes {ptagattr(attrib)}")
    else:
        return t


def get_table_rows(table: Tag, recurse: bool = False) -> list[Tag]:
    """
    Specialization of find_tags for table rows
    """
    t = find_tags(table, "tr", attrib={"class": ["odd", "even"]}, recursive=recurse)

    if not t:
        return []
    else:
        return t


def get_text_of(
    source: Tag,
    tag: str | None = None,
    attrib: dict[str, str | list[str]] = {},
    sep: str = "\n",
    strip: bool = True,
) -> str:
    """
    Specialization of find_tag which gets the text of the result

    If there is no result, it returns an empty string
    """

    if not tag and not attrib:
        return source.get_text(sep, strip)

    t = find_tag(source, tag, attrib)

    if not t:
        return ""

    return t.get_text(sep, strip)


def get_text_of_f(
    source: Tag,
    tag: str,
    attrib: dict[str, str | list[str]] = {},
    sep: str = "\n",
    strip: bool = True,
) -> str:
    """
    Get the text of a tag or raise an exception if absent
    """

    t = find_tag(source, tag, attrib)

    if not t:
        raise Exception(f"Could not find tag {tag}")

    return t.get_text(sep, strip)


def get_attrib(tag: Tag, attr: str) -> str | None:
    """
    Get an attribute, or None if absent
    """

    v = tag.get(attr)

    return v if isinstance(v, str) else None


def get_attrib_f(tag: Tag, attr: str) -> str:
    """
    Get an attribute or raise an exception if absent
    """

    v = get_attrib(tag, attr)

    if not v:
        raise Exception(f"Attribute {attr} is not present in tag {tag.name}")
    else:
        return v


def get_value(tag: Tag) -> str:
    """
    Get the string value of a tag, else return an empty string
    """

    v = get_attrib(tag, "value")

    return v or ""


def get_txt_input_value(soup: BeautifulSoup | Tag, eid: str) -> str:
    """Get the value of a text input by ID"""
    tag = find_tag_f(soup, "input", {"type": "text", "id": eid})

    return get_value(tag).strip()


def get_select_input_value(soup: BeautifulSoup | Tag, eid: str) -> str | None:
    """Get the value of a select input"""
    tag = find_tag_f(soup, "select", {"id": eid})

    opt = find_tag(tag, "option", {"selected": "selected"})
    if not opt:
        return None

    return opt.get_text("", True)


def get_checkbox_value(soup: BeautifulSoup | Tag, eid: str) -> bool:
    """Get the value of a checkbox"""
    tag = find_tag_f(soup, "input", {"type": "checkbox", "id": eid})
    value = tag.get("value")
    return value == "true"


def element_exists_by_id(soup: BeautifulSoup | Tag, tagty: str, eid: str) -> bool:
    """Check if an element with a given ID exists"""
    return isinstance(find_tag(soup, tagty, {"id": eid}), Tag)


def get_field_value(form: Tag, id: str) -> str | bool:
    """
    Get a field from a form
    """
    tag = find_tag_f(form, "input", {"id": id, "name": id})

    result = get_value(tag)

    if tag.get("type") == "checkbox":
        result = result == "true"

    return result


def get_input_value(s: BeautifulSoup, type: Literal["checkbox", "text"], id: str) -> str:
    """
    Get the value of an input field based on its type and ID.
    """
    return get_value(find_tag_f(s, "input", {"type": type, "id": id}))


def get_radio_value(s: BeautifulSoup, name: str) -> str:
    """
    Get the value of a radio field based on its name
    """
    return get_value(find_tag_f(s, "input", {"type": "radio", "name": name, "checked": ""}))


# ---------------------------------------------------------------------------- #
#                              AllowedClients.sel                              #
# ---------------------------------------------------------------------------- #


def parse_clients(soup: BeautifulSoup) -> dict[str, Any]:
    """Performs a basic parse of the table contents in the main page"""
    result = {}

    table = find_table(soup, {"id": "SharedClients"})
    rows = get_table_rows(table)

    for row in rows:
        alias = get_text_of(row, "td", {"class": "Alias"})
        address = get_text_of(row, "td", {"class": "IP"})
        description = get_text_of(row, "td", {"class": "Description"})

        types = find_tag_f(row, "td", {"class": "Types"})

        imgs = find_tags(types, "img")
        types = types.get_text(";", True).split(";")

        result[alias] = {
            "address": address,
            "description": description,
            "types": [
                types[i].strip("\u00a0")
                for i in range(len(types))
                if imgs[i].get("src") in ["/images/checked.JPG"]
            ],
        }

    return result


# ---------------------------------------------------------------------------- #
#                                 Firewall.sel                                 #
# ---------------------------------------------------------------------------- #


def parse_firewall_rules(soup: BeautifulSoup) -> dict[str, Any]:
    """
    Parse the firewall's configuration
    """

    def parse_firewall_rules(tag: Tag) -> dict[str, Any]:
        """Parse a row containing a rule"""
        result = {}

        try:
            strs = [
                "globalOrder",
                "ruleInterface",
                "StatusName",
                "sourcePort",
                "descProtocolRule",
                "destPort",
            ]

            def getk(tag: Tag, k: str) -> list[str]:
                return get_text_of(tag, "td", {"class": k}).splitlines()

            values = {k: getk(tag, k) for k in strs}

            result["order"] = values["globalOrder"][0].strip()
            result["interface"] = values["ruleInterface"][0].strip()
            result["name"] = values["StatusName"][0].strip()
            result["status"] = values["StatusName"][1].strip()
            result["source_address"] = values["sourcePort"][0].strip()
            result["source_port"] = values["sourcePort"][1].strip()
            # Just in case the description field ends up supporting line breaks (the text box used to fill it does)
            result["description"] = " ".join(values["descProtocolRule"][:-1]).strip()
            protorule = values["descProtocolRule"][-1].split("\u00a0")
            result["protocol"] = protorule[0].strip()
            result["action"] = protorule[-1].strip()
            result["destination_address"] = values["destPort"][0].strip()
            result["destination_port"] = values["destPort"][1].strip()
        except:
            logger.warning("Failed to parse row")

        return result

    GENERAL_KEYS = {
        "drop_ping": "dropPing",
        "drop_traceroute": "dropTraceroute",
        "require_encryption": "mustBeEncrypted",
        "allow_all_encrypted": "allowAllEncrypted",
    }

    def getinpt(soup: BeautifulSoup, k: str) -> str:
        v = find_tag_f(soup, "input", {"id": k})
        return get_value(v)

    result: dict[str, Any] = {k: getinpt(soup, GENERAL_KEYS[k]) for k in GENERAL_KEYS}

    result["rules"] = [
        parse_firewall_rules(row) for row in find_tags(soup, "tr", {"class": ["odd", "even"]})
    ]

    return result


# ---------------------------------------------------------------------------- #
#                                   Hosts.sel                                  #
# ---------------------------------------------------------------------------- #


def parse_hosts(soup: BeautifulSoup) -> dict[str, Any]:
    """
    Parse the page
    """
    result = {}

    table = find_table(soup, {"id": "HostnameTable"})
    rows = get_table_rows(table)

    for row in rows:
        name = get_text_of(row, "td", {"class": "hostname"})
        address = get_text_of(row, "td", {"class": "ip_address"})

        result[name] = address
    return result


# ---------------------------------------------------------------------------- #
#                                   index.sel                                  #
# ---------------------------------------------------------------------------- #


def parse_index(soup: BeautifulSoup, data: dict[str, Any]):
    dashboard = find_tag_f(soup, "div", {"id": "dashBoard"})
    tables = find_tags(dashboard, "table", recursive=False)

    def parse_sys_stat(table: Tag, data: dict[str, Any]):
        ROWS = {
            "ipsec_connections": "ipsecConnections",
            "web_users": "webUsers",
            "uptime": "uptime",
            "hours": "hours",
            "power_cycles": "powerCycles",
            "firewall_rules": "firewallRules",
        }

        data["system_statistics"] = {
            row: get_text_of(table, "td", {"id": ROWS[row]}) for row in ROWS
        }

    def parse_led_indicators(table: Tag, data: dict[str, Any]):
        cells = find_tags(table, "td")

        result = {}

        for cell in cells:
            txt = cell.get_text("", True).lower()
            img = find_tag(cell, "img")

            if not img:
                result[txt] = "unknown"
            else:
                imgsrc = str(img.get("src"))
                if "led_red.png" in imgsrc:
                    result[txt] = "red"
                elif "led_green.png" in imgsrc:
                    result[txt] = "green"
                else:
                    result[txt] = "off"

        data["led_indicators"] = result

    def parse_network_stats(table: Tag, data: dict[str, Any]):
        tables = find_tags(table, "table")

        nics = tables[0]
        iscx = tables[1]

        # Do not do this if network settings failed to parse
        if "network" in data:
            logger.info("Parsing Ethernet Stats")
            nic_rows = find_tags(nics, "tr")
            for row in nic_rows[1:]:
                row_text = row.get_text(";", True).split(";")
                name = row_text[0]
                bin = int(row_text[2].split(" ")[0])
                bout = int(row_text[3].split(" ")[0])

                if name in data["network"]["interfaces"]:
                    data["network"]["interfaces"][name].update(
                        {
                            "bytes_in": bin,
                            "bytes_out": bout,
                        }
                    )

        if "ipsec" in data:
            logger.info("Parsing IPsec Stats")
            data["ipsec"]["stats"] = {}
            icsx_rows = find_tags(iscx, "tr")

            for row in icsx_rows[1:]:
                text = row.get_text("\n", True).splitlines()
                name = text[0]
                state = text[1]
                bin = int(text[2].split(" ")[0])
                bout = int(text[3].split(" ")[0])

                data["ipsec"]["stats"][name] = {
                    "state": state,
                    "in": bin,
                    "out": bout,
                }

    def parse_version_information(table: Tag, data: dict[str, Any]):
        ROWS = {
            "serial_number": "serialNo",
            "version": "version",
            "fid": "fid",
        }

        data["version_information"] = {
            row: get_text_of(table, "td", {"id": ROWS[row]}) for row in ROWS
        }

    # Tables, by the first caption in that table
    PARSERS = {
        "System Statistics": parse_sys_stat,
        "LED Indicators": parse_led_indicators,
        "Ethernet Connections": parse_network_stats,
        "Version Information": parse_version_information,
    }

    for table in tables:
        caption = get_text_of(table, "caption")

        if caption not in PARSERS:
            continue

        logger.info(f"Parsing table {caption}")

        PARSERS[caption](table, data)


# ---------------------------------------------------------------------------- #
#                                   IPsec.sel                                  #
# ---------------------------------------------------------------------------- #


def parse_ipsec_connections(soup: BeautifulSoup) -> dict[str, Any]:
    """Performs a basic parse of the table contents in the main page"""
    result = {}

    enabled = find_tag_f(soup, "input", {"id": "Enabled"})
    enabled = enabled.get("checked") == "checked"

    drop_on_ocsp_loss = find_tag_f(soup, "input", {"id": "DropOCSP"})
    drop_on_ocsp_loss = drop_on_ocsp_loss.get("checked") == "checked"

    result["enabled"] = enabled
    result["ocsp_loss"] = "Drop" if drop_on_ocsp_loss else "Keep"

    table = find_table(soup, {"id": "IPsecList"})
    rows = get_table_rows(table)

    connections = []

    for row in rows:
        r = {}
        # Each group of lines handles different fields. Each will get and parse each respective field as necessary.
        local_nets = [
            {"name": x[0], "subnet": x[1]}
            for x in [
                x.get_text(";", True).split(";")
                for x in find_tags(row, "td", {"class": "localNetwork"})
            ]
        ]

        local_gw = get_text_of(row, "td", {"class": "LGAlias"})
        local_gwip = get_text_of(row, "td", {"class": "LGIP"})
        cxfwd = get_text_of(row, "td", {"class": "connectionForward"})

        remote_nets = [
            {"name": x[0], "subnet": x[1]}
            for x in [
                x.get_text(";", True).split(";")
                for x in find_tags(row, "td", {"class": "remoteNetwork"})
            ]
        ]

        remote_gw = get_text_of(row, "td", {"class": "RGAlias"})
        remote_gwip = get_text_of(row, "td", {"class": "remoteGateway"})

        r["local"] = {
            "networks": local_nets,
            "gateway": {"alias": local_gw, "address": local_gwip},
        }

        r["auth"] = cxfwd

        r["remote"] = {
            "networks": remote_nets,
            "gateway": {"alias": remote_gw, "address": remote_gwip},
        }

        connections.append(r)

    result["connections"] = connections

    return result


# ---------------------------------------------------------------------------- #
#                                   LDAP.sel                                   #
# ---------------------------------------------------------------------------- #


def parse_ldap_settings(soup: BeautifulSoup) -> dict[str, Any]:
    GLOBAL_SETTINGS_NAME = "LDAPSettingsTable"
    GLOBAL_SETTINGS = {
        "enabled": "enabled",
        "user_id_attribute": "user_id_attr",
        "group_member_attribute": "group_member_attr",
        "sync_interval": "sync_interval",
        "search_base": "search_base",
        "bind_dn": "binddn",
    }

    LDAP_SERVER_LIST_NAME = "LDAPServersTable"
    LDAP_SERVER_LIST = ["priority", "ldap_hostname", "port"]

    ATTRIBUTE_STRINGS_NAME = "LDAPAttributeTable"
    ATTRIBUTE_STRINGS = [
        {"label": "f_name_label", "attribute": "f_name"},
        {"label": "l_name_label", "attribute": "l_name"},
        {"label": "email_label", "attribute": "email"},
        {"label": "phone_label", "attribute": "phone"},
    ]

    GROUP_MAPPINGS_NAME = "LDAPGroupTable"
    GROUP_MAPPINGS = {
        "role": "device_role",
        "dn": "ldap_dn",
    }

    result = {}

    table = find_table(soup, {"id": GLOBAL_SETTINGS_NAME})

    logger.debug("/// Parsing global settings...")
    result["config"] = {
        key: get_text_of(table, "td", {"id": GLOBAL_SETTINGS[key]}) for key in GLOBAL_SETTINGS
    }

    table = find_table(soup, {"id": LDAP_SERVER_LIST_NAME})

    list = get_table_rows(table)

    servers = {}
    logger.debug("/// Parsing LDAP server list...")
    for row in list:
        r = {key: get_text_of(row, "td", {"id": key}) for key in LDAP_SERVER_LIST}
        hostname = r["ldap_hostname"]
        del r["ldap_hostname"]
        servers[hostname] = r
    result["servers"] = servers

    table = find_table(soup, {"id": ATTRIBUTE_STRINGS_NAME})

    attrs = {}
    logger.debug("/// Parsing attributes...")
    for pair in ATTRIBUTE_STRINGS:
        p = {k: get_text_of(table, "td", {"id": pair[k]}) for k in pair}
        attrs[p["label"]] = p["attribute"]
    result["attributes"] = attrs

    table = find_table(soup, {"id": GROUP_MAPPINGS_NAME})

    list = get_table_rows(table)

    groupmaps = {}
    logger.debug("/// Parsing group mappings...")
    for row in list:
        r = {key: get_text_of(row, "td", {"id": GROUP_MAPPINGS[key]}) for key in GROUP_MAPPINGS}

        if r["role"] not in groupmaps:
            groupmaps[r["role"]] = []

        groupmaps[r["role"]].push(r["dn"])
    result["group_mappings"] = groupmaps

    return result


# ---------------------------------------------------------------------------- #
#                                  Syslog.sel                                  #
# ---------------------------------------------------------------------------- #


def parse_syslog_settings(soup: BeautifulSoup) -> dict[str, Any]:
    oum = get_text_of(soup, "div", {"id": "syslog_oldest_message_numb"})

    sellvl = get_text_of(soup, "td", {"class": "loggingThresholdFG"}).removeprefix(
        "Selected Level: "
    )

    def parse_row(tr: Tag) -> dict[str, Any]:
        ip = get_text_of_f(tr, "td", {"class": "syslog_ip"})
        port = get_text_of_f(tr, "td", {"class": "port"})
        threshold = get_text_of_f(tr, "td", {"class": "threshold"})
        description = get_text_of_f(tr, "td", {"class": "description"})

        return {
            "ip": ip,
            "port": port,
            "threshold": threshold,
            "description": description,
        }

    table = find_table(soup, {"id": "SyslogDestinations"})
    entries = {str(tr.get("id", "N/A")): parse_row(tr) for tr in get_table_rows(table)}

    return {
        "oldest_unacknowledged": oum,
        "threshold_level": sellvl,
        "destinations": entries,
    }


# ---------------------------------------------------------------------------- #
#                               SysLogReport.sel                               #
# ---------------------------------------------------------------------------- #


def parse_syslog_report(csv: list[str]) -> dict[str, Any]:
    logs = []

    headers = [s.lower() for s in csv[0].split(",")]

    i = 1
    while i < len(csv):
        line = csv[i]
        while line[-1] != "'":  # Syslog messages are quoted
            i += 1
            line += " " + csv[i].strip()

        line = line.split(",")

        logs.append(
            {
                headers[0]: int(line[0]),
                headers[1]: line[1] != "f",
                headers[2]: line[2],
                headers[3]: line[3],
                headers[4]: line[4],
                headers[5]: line[5],
                headers[6]: ",".join(line[6:]).strip("'"),
            }
        )

        i += 1

    logs.sort(key=lambda x: x["id"])

    severities = {}
    facilities = {}
    tags = {}
    acked = 0

    for log in logs:
        sev = log["severity"]
        fac = log["facility"]
        tag = log["tag"]

        if log["acked"]:
            acked += 1

        if sev not in severities:
            severities[sev] = 1
        else:
            severities[sev] += 1
        if fac not in facilities:
            facilities[fac] = 1
        else:
            facilities[fac] += 1
        if tag not in tags:
            tags[tag] = 1
        else:
            tags[tag] += 1

    return {
        "by_severity": severities,
        "by_facility": facilities,
        "by_tag": tags,
        "total_logs": len(logs),
        "acknowledged": acked,
        "logs": logs,
    }


# ---------------------------------------------------------------------------- #
#                                LocalGroups.sel                               #
# ---------------------------------------------------------------------------- #


def parse_local_groups(soup: BeautifulSoup) -> dict[str, Any]:
    table = find_table(soup, {"id": "local_groups"})

    rows = get_table_rows(table, False)

    result = {get_attrib_f(row, "id"): [] for row in rows}

    for group in result:
        gtable = find_tag_f(table, "tr", {"id": f"group_{group}_users"})
        members = find_tags(gtable, "td", {"class": "Alias"})
        result[group] = [member.get_text(strip=True) for member in members]

    return result


# ---------------------------------------------------------------------------- #
#                                   X509.sel                                   #
# ---------------------------------------------------------------------------- #

# TODO: Convert to using the X509 data model
def parse_certificates_advanced(soup: BeautifulSoup) -> dict[str, Any]:
    """More advanced parsing for more advanced data"""
    ADVANCED_DATA = {
        "version": "version",
        "serial_number": "serial_number",
        "name": "name",
        "subject_alt_names": "subject_alt_name",
        "subject": "distinguished_name",
        "country": "country",
        "state": "state",
        "locality": "locality",
        "org_name": "organization_name",
        "org_unit_name": "organization_unit_name",
        "common_name": "common_name",
        "email": "email_addr",
        "issuer_subject": "issuer_dn",
        "issuer_country": "issuer_country",
        "issuer_state": "issuer_state",
        "issuer_locality": "issuer_locality",
        "issuer_org_name": "issuer_organization_name",
        "issuer_org_unit_name": "issuer_organization_unit_name",
        "issuer_common_name": "issuer_common_name",
        "issuer_email": "issuer_email_addr",
        "valid_start": "valid_start",
        "valid_end": "valid_end",
        "is_ca": "is_ca",
        "ocsp_uri": "ocsp_uri",
        "rsa_key": "rsa_key",
    }

    result = {}

    for k in ADVANCED_DATA:
        result[k] = get_text_of(soup, "label", {"id": ADVANCED_DATA[k]})

    return result


def parse_certificates_basic(soup: BeautifulSoup) -> dict[str, Any]:
    """Performs a basic parse of the table contents in the main page"""
    BASIC_DATA = {
        "name": "name",
        "country": "country",
        "is_ca": "ca",
        "valid_start": "start",
        "valid_end": "end",
        "oscp_uri": "ocsp",
    }

    result = {}

    table = find_table(soup, {"id": "x509List"})
    rows = get_table_rows(table)

    for row in rows:
        x = {k: get_text_of(row, "td", {"class": f"x509_{BASIC_DATA[k]}"}) for k in BASIC_DATA}

        name = x["name"]
        del x["name"]
        result[name] = x

    return result


# ---------------------------------------------------------------------------- #
#                    WebServer.sel / ManagementInterface.sel                   #
# ---------------------------------------------------------------------------- #


def parse_global_web_server_config(soup: BeautifulSoup) -> dict[str, Any]:
    table = find_table(soup, {"id": "WebInterface"})

    sess_timeout = get_txt_input_value(table, "SessionTimeout")
    cert = get_select_input_value(table, "X509Certificate")
    if not cert:
        cert = "Default"

    result = {
        "port": int(get_txt_input_value(table, "Port")),
        "session_timeout": f"{sess_timeout} minutes",
        "cert": cert,
    }

    if element_exists_by_id(table, "input", "ServicePortEnabled"):
        result["service_port"] = {}
        result["service_port"]["enabled"] = get_checkbox_value(table, "ServicePortEnabled")
        result["service_port"]["port"] = int(get_txt_input_value(table, "ServicePortNumber"))

    return result


def parse_web_server_listeners(soup: BeautifulSoup) -> dict[str, Any]:
    COLUMNS = {
        "alias": "ui_AddressAlias",
        "ip": "ui_IP",
        "vlan_id": "ui_VLAN",
    }

    table = find_table(soup, {"id": "webServer"})

    rows = get_table_rows(table)
    result = {}

    for row in rows:
        r = {col: get_text_of(row, "td", {"class": COLUMNS[col]}) for col in COLUMNS}

        a = r["alias"]
        del r["alias"]
        result[a] = r

    return result


# ---------------------------------------------------------------------------- #
#                                   Users.sel                                  #
# ---------------------------------------------------------------------------- #


def parse_user_info(dev: DeviceData, soup: BeautifulSoup) -> dict[str, Any]:
    """
    Parse an individual user's data (must be a /Users_Form.sel page)
    """
    USER_FORM_FIELDS = {
        "username": "Username",
        "first_name": "FirstName",
        "last_name": "LastName",
        "title": "Title",
        "division": "Division",
        "identification": "EmployeeIdentification",
        "address": "Address",
        "city": "City",
        "state": "State",
        "country": "Country",
        "postal_code": "PostalCode",
        "work_phone": "WorkPhone",
        "mobile_phone": "MobilePhone",
        "email": "Email",
        "admin": "Admin",
        "enabled": "Enabled",
    }

    USER_TABLE_FIELDS = {
        "created": "ui_CreationDate",
        "last_login": "ui_LastLoginDate",
        "last_password_update": "ui_PasswordModDate",
    }

    result = {}

    form = find_table(soup, {"class": "formLayout"})

    for field in USER_FORM_FIELDS:
        id = USER_FORM_FIELDS[field]
        data = get_field_value(form, id)

        if field == "username" and data == "":
            raise Exception(f"Bad field entry: username is empty")

        result[field] = "N/A" if data == "" else data

    table = find_table(soup, {"id": "localUser"})

    row = find_tag_f(table, "tr", {"id": result["username"]})

    for field in USER_TABLE_FIELDS:
        result[field] = get_text_of(row, "div", {"class": USER_TABLE_FIELDS[field]}) or "N/A"

    return {result["username"]: result}


# ---------------------------------------------------------------------------- #
#                                UsagePolicy.sel                               #
# ---------------------------------------------------------------------------- #


def parse_usage_policy(soup: BeautifulSoup) -> str:
    return get_text_of_f(soup, "textarea", {"id": "UseBanner"})


# ---------------------------------------------------------------------------- #
#                               StaticRoutes.sel                               #
# ---------------------------------------------------------------------------- #


def parse_static_routes(soup: BeautifulSoup) -> dict[str, Any]:
    def get_connection_rule(row: Tag) -> Literal["Forward", "Drop", "Reject"]:
        """
        Get the rulename of the connection (Forward, Drop, or Reject)
        """
        fwd = find_tag(row, "td", {"class": "connectionForward"})
        drp = find_tag(row, "td", {"class": "connectionDrop"})
        rej = find_tag(row, "td", {"class": "connectionReject"})

        if fwd:
            return "Forward"
        elif drp:
            return "Drop"
        elif rej:
            return "Reject"
        else:
            raise Exception("Could not get rule")

    def extract_row(row: Tag) -> tuple[str, dict[str, Any]]:
        """
        Extracts the static route configuration from a row of the table
        """
        result = {}
        id = get_attrib(row, "id") or ""
        logger.debug(f"id={id}")

        action = get_connection_rule(row)
        logger.debug(f"--> action={action}")

        gateway = get_text_of(row, "td", {"class": "remoteGateway"}, ",").split(",")
        logger.debug(f"--> gateway={gateway}")

        remote = get_text_of(row, "td", {"class": "remoteNetwork"}, ",").split(",")[1]
        logger.debug(f"--> remote={remote}")

        result["action"] = action
        result["network"] = remote

        if action == "Forward":
            result["gateway_name"] = gateway[0]
            result["gateway_address"] = gateway[1]

        return id, result

    def extract_rows(rows: list[Tag]) -> list[tuple[str, dict[str, Any]]]:
        """
        Extracts ALL rows from the result set
        """
        return [extract_row(row) for row in rows]  # Extract row data

    return {
        id: data
        for id, data in extract_rows(
            get_table_rows(find_table(soup, {"id": "staticRoute", "class": "fieldList"}))
        )
    }


# ---------------------------------------------------------------------------- #
#                               SSH_Host_Key.sel                               #
# ---------------------------------------------------------------------------- #


def parse_host_keys(soup: BeautifulSoup) -> dict[str, Any]:
    """Read the public keys on this system"""
    FORMS = {
        "dsa_pubkey": "pubSSH",
        "rsa_pubkey": "pubRSA",
    }

    result = {f: get_text_of(find_tag_f(soup, "form", {"id": FORMS[f]}), "pre") for f in FORMS}

    return result


# ---------------------------------------------------------------------------- #
#                                   SNMP.sel                                   #
# ---------------------------------------------------------------------------- #


def parse_mibs(dev: DeviceData, path: str | Path) -> dict[str, Any]:
    """Parse the MIBS files (for now, copies the files)"""
    mibs_dir = dev.get_out_dir() / "MIBS"
    zfile = ZipFile(dev.get_out_dir() / path)
    zfile.extractall(mibs_dir)

    dev.related.files.add(path)

    result = {}
    for file in mibs_dir.iterdir():
        dev.related.files.add(file.parent / file.name)
        text = file.read_text()
        hash = sha256(text.encode()).hexdigest()

        result[str(file.name)] = {
            "sha256sum": hash,
            "content": file.read_text(),
        }

    return {"mibs": result}


def parse_snmp_settings(soup: BeautifulSoup) -> dict[str, Any]:
    """Parse SNMP settings"""
    PROFILES_COLUMNS = {
        "name": ["Alias"],
        "version": ["Version"],
        "auth": ["AuthenticationProtocol"],
        "encryption": ["EncryptionProtocol"],
        "permissions": ["Permissions"],
    }

    TRAP_SERVERS_COLUMNS = {
        "alias": ["ServerAlias"],
        "address": ["IPAddress"],
        "profile": ["ProfileAlias"],
        "traps": ["Traps"],
    }
    result = {}

    enabled = find_tag_f(soup, "input", {"id": "Enabled", "type": "checkbox"})
    result["enabled"] = get_value(enabled) == "true"

    eid = find_table(soup, {"id": "snmp_engine"})
    result["engine_id"] = get_text_of(eid, "td", {"class": "Alias"}).split(": ")[1]

    table = find_table(soup, {"id": "snmp_profiles"})
    profiles = get_table_rows(table)

    parsed_profiles = []
    for profile in profiles:
        p = {}
        for col in PROFILES_COLUMNS:
            r = get_text_of(profile, "td", {"class": PROFILES_COLUMNS[col]})

            if col == "permissions":
                r = [s.strip() for s in r.split(",")]

            p[col] = r
        parsed_profiles.append(p)

    result["profiles"] = parsed_profiles

    table = find_table(soup, {"id": "snmp_trap_servers"})
    trap_servers = get_table_rows(table)

    parsed_servers = []
    for server in trap_servers:
        assert isinstance(server, Tag)
        p = {}
        for col in TRAP_SERVERS_COLUMNS:
            r = get_text_of(server, "td", {"class": TRAP_SERVERS_COLUMNS[col]}, ",")

            if col == "traps":
                r = [s.strip() for s in r.split(",")]

            p[col] = r
        parsed_servers.append(p)

    result["servers"] = parsed_servers

    return result


# ---------------------------------------------------------------------------- #
#                            SerialPortSettings.sel                            #
# ---------------------------------------------------------------------------- #


def parse_serial_port_settings(soup: BeautifulSoup) -> dict[str, Any]:
    COLUMNS = {
        "profile": ["ui_ProfileName"],
        "baud_rate": ["ui_BaudRate"],
        "data_bits": ["ui_DataBit"],
        "parity": ["ui_Parity"],
        "stop_bits": ["ui_StopBit"],
        "hw_flow_control": ["ui_FlowControl"],
        "interface": ["ui_Interface"],
        "alias": ["ui_SerialPortAlias"],
    }

    result = {}

    table = find_table(soup, {"id": "serialPorts"})
    entries = get_table_rows(table)

    for e in entries:
        entry = {}
        state = find_tag(e, "td", {"class": "disabledSerialPort"})
        entry["state"] = "Disabled" if state else "Enabled"

        for c in COLUMNS:
            entry[c] = get_text_of(e, "td", {"class": COLUMNS[c]})

        logger.debug(
            f"/// {entry['alias']} is {entry['state']} (baud={entry['baud_rate']}, db={entry['data_bits']}, p={entry['parity']}, sb={entry['stop_bits']}, hwfc={entry['hw_flow_control']}, if={entry['interface']})"
        )

        alias = entry["alias"]
        del entry["alias"]
        result[alias] = entry

    return result


# ---------------------------------------------------------------------------- #
#                            SerialPortProfiles.sel                            #
# ---------------------------------------------------------------------------- #


def parse_serial_port_profiles(soup: BeautifulSoup) -> dict[str, Any]:
    COLUMNS = {
        "name": ["ui_ProfileName"],
        "baud_rate": ["ui_BaudRate"],
        "data_bits": ["ui_DataBit"],
        "parity": ["ui_Parity"],
        "stop_bits": ["ui_StopBit"],
        "hw_flow_control": ["ui_FlowControl"],
        "comm_interface": ["ui_Interface"],
        "frame_size": ["ui_FrameSize"],
    }

    result = {}

    table = find_table(soup, {"id": ["serialPorts", "byteBasedSerialPorts"]})
    entries = get_table_rows(table)

    for e in entries:
        entry = {}

        for c in COLUMNS:
            value = get_text_of(e, attrib={"class": COLUMNS[c]})

            if c == "baud_rate":
                if value.endswith("*"):
                    value = value.strip("*")
                    entry["intercharacter_delay"] = "on"
                else:
                    entry["intercharacter_delay"] = "off"
                pass

            entry[c] = value

        name = entry["name"]
        del entry["name"]
        result[name] = entry

    return result


# ---------------------------------------------------------------------------- #
#                                  RADIUS.sel                                  #
# ---------------------------------------------------------------------------- #


def parse_radius_settings(soup: BeautifulSoup) -> dict[str, Any]:
    SETTINGS_TABLE_CHECKBOXES: Final[dict[str, str]] = {
        "enabled": "radius_auth",
        "accounting_enabled": "radius_acct",
        "use_encrypted_usernames": "encrypted_username",
        "log_accounting_updates": "syslog",
        "verify_server_identity": "verify_cert",
    }

    SETTINGS_TABLE_HOST_DROPDOWNS: Final[dict[str, str]] = {
        "primary_server": "Phost",
        "secondary_server": "Shost",
    }

    SETTINGS_TABLE_HOST_IP_ADDR: Final[dict[str, list[str]]] = {
        "primary_server": [
            "IPAddress_1P",
            "IPAddress_2P",
            "IPAddress_3P",
            "IPAddress_4P",
        ],
        "secondary_server": [
            "IPAddress_1S",
            "IPAddress_2S",
            "IPAddress_3S",
            "IPAddress_4S",
        ],
    }

    SETTINGS_TABLE_HOST_PORTS: Final[dict[str, dict[str, tuple[str, int]]]] = {
        "primary_server": {
            "auth": ("p_auth_port", 1812),
            "acct": ("p_acct_port", 1813),
        },
        "secondary_server": {
            "auth": ("s_auth_port", 1812),
            "acct": ("s_acct_port", 1813),
        },
    }

    result = {}
    get_host_ports = []

    table = find_table(soup, {"id": "RADIUSSettingsTable"})

    for checkbox in SETTINGS_TABLE_CHECKBOXES:
        result[checkbox] = (
            get_attrib(
                find_tag_f(table, "input", {"name": SETTINGS_TABLE_CHECKBOXES[checkbox]}),
                "checked",
            )
            == "checked"
        )

    for dropdown in SETTINGS_TABLE_HOST_DROPDOWNS:
        # Get the dropdown item in the table
        v = find_tag_f(table, "select", {"id": SETTINGS_TABLE_HOST_DROPDOWNS[dropdown]})
        # Get the selected option
        s = find_tag_f(v, "option", {"selected": "selected"})
        # Get the IP address if the selected item is "IP Address"
        if s.get("value", "0") == "0":
            # Assert that the dropdown is recognized
            if dropdown in SETTINGS_TABLE_HOST_IP_ADDR:
                # Get the IP address
                addr_parts = []
                for part in SETTINGS_TABLE_HOST_IP_ADDR[dropdown]:
                    v = find_tag_f(table, "input", {"id": part})
                    value = get_value(v)
                    if value == "":
                        addr_parts = []
                        break
                    else:
                        addr_parts.append(value)
                # If incomplete, not configured
                if len(addr_parts) != 4:
                    result[dropdown] = "N/A"
                else:
                    result[dropdown] = {"address": ".".join(addr_parts)}
                    get_host_ports.append(dropdown)
        else:
            # Get the name of the host being used
            result[dropdown] = {"hostname": s.get_text(strip=True)}
            get_host_ports.append(dropdown)

    # For hosts that have an address, get their ports as well.
    for host in get_host_ports:
        if host in SETTINGS_TABLE_HOST_PORTS:
            for portname in SETTINGS_TABLE_HOST_PORTS[host]:
                p, d = SETTINGS_TABLE_HOST_PORTS[host][portname]
                v = find_tag_f(table, "input", {"id": p})
                port = get_value(v)

                if port == "":
                    port = d
                result[host][portname] = int(port)

    v = find_tag_f(table, "select", {"name": "RADIUSAuthTypeId"})
    result["auth_type"] = get_text_of(v, "option", {"selected": "selected"})

    v = find_tag_f(table, "input", {"id": "message_timeout"})
    result["timeout"] = get_value(v)

    return result


# ---------------------------------------------------------------------------- #
#                               PortMappings.sel                               #
# ---------------------------------------------------------------------------- #


def parse_port_mappings(soup: BeautifulSoup) -> dict[str, Any]:
    """Performs a basic parse of the table contents in the main page"""
    result = {}

    table = find_table(soup, {"id": "PortMappingGroups"})

    rows = find_tags(table, "tr", {"class": ["odd", "oddProxy", "even", "evenProxy"]})
    # Convert into tuples; this makes parsing simpler.
    rows = [(rows[i * 2], rows[i * 2 + 1]) for i in range(len(rows) // 2)]

    for name, conf in rows:
        # We need all of these to be tags.
        name = get_text_of(name, "td", {"class": "ui_group_alias"})

        conf = find_table(conf, {"class": "groupMaps"})
        maps = find_tags(conf, "table", {"class": "groupMaps"})

        parsed = []

        # TODO: figure out how the odd table at the bottom of the row is populated, then try to populate it to parse it
        # For now, we'll ignore it

        for map in maps:
            x = {}

            # Device name
            x["alias"] = get_text_of(map, "div", {"class": "groupDeviceLabelActive"})

            # Check if the image is of a serial device.
            comm_dev_serial = find_tag(
                map,
                "div",
                {"class": ["groupSerialPortInactive", "groupSerialPortActive"]},
            )
            # If it is, "Serial". Otherwise, "Ethernet".
            x["device"] = "Serial" if comm_dev_serial else "Ethernet"

            # Device listen address
            gcla = find_tag_f(map, "td", {"class": "groupCommLinkActive"})
            comm_dev_listen = find_tag(gcla, "span")
            if isinstance(comm_dev_listen, Tag):
                listen = comm_dev_listen.get_text("", True).split(":")
                if len(listen) >= 2:
                    x["listen"] = {"ip": listen[0], "port": listen[1]}
                else:
                    x["listen"] = listen

            # Protocol
            x["proto"] = get_text_of(map, "label", {"class": "commStatsProtocol"})

            # Statistics (if they exist)
            comm_stats = find_tag(map, "a", {"class": "diagnosPopUp"})
            if isinstance(comm_stats, Tag):
                lines = comm_stats.get_text(";", True).split(";")
                x["stats"] = {}

                for stat in lines:
                    s = stat.split(":")
                    # Lowercase, camelcase to match schema of JSON output
                    s[0] = s[0].lower().replace(" ", "_")

                    x["stats"][s[0]] = s[1]

            parsed.append(x)

        result[name] = parsed

    return result


# ---------------------------------------------------------------------------- #
#                              PhysicalSensors.sel                             #
# ---------------------------------------------------------------------------- #


def parse_sensors_enabled(s: BeautifulSoup) -> str:
    """
    Get if the physical sensors are globally enabled
    """

    return get_input_value(s, "checkbox", "g_enable")


def parse_sensor_input_contact(s: BeautifulSoup) -> dict[str, Any]:
    """
    Get the configuration of the input contacts (front pair of wire grips)
    """

    # TODO: extract most recent events
    # NOTE: the sample device seems to have broken sensors
    ic_current_state = find_tag_f(s, "td", {"id": "ic_current_state"})

    return {
        "enabled": get_input_value(s, "checkbox", "ic_enable"),
        "on_msg": get_input_value(s, "text", "ic_syslog_energized"),
        "off_msg": get_input_value(s, "text", "ic_syslog_deenergized"),
        "state": ic_current_state.get_text(strip=True).removeprefix("Current State: "),
    }


def parse_sensor_light(s: BeautifulSoup) -> dict[str, Any]:
    """
    Get the configuration of the light sensor (hole to the right of the SEL logo)
    """

    # TODO: extract most recent events
    # NOTE: the sample device seems to have broken sensors
    LS_MAP = ["High", "Medium", "Low"]

    sensitivity = get_radio_value(s, "ls_sensitivity_id")
    if not sensitivity.isnumeric():  # Ensure it is numeric (prevent breakage)
        sensitivity = "UNKNOWN"
    else:  # Parse and check range
        sensitivity = int(sensitivity)
        if sensitivity >= 1 and sensitivity <= 3:
            sensitivity = "UNKNOWN"
        else:  # Convert to human-readable string
            sensitivity = LS_MAP[int(sensitivity)]

    return {
        "enabled": get_input_value(s, "checkbox", "ls_enable"),
        "sensitivity": sensitivity,
    }


def parse_sensor_motion(s: BeautifulSoup) -> dict[str, Any]:
    """
    Get the configuration of the motion sensor (detects jostling and tilting)
    """

    # TODO: extract most recent events
    # NOTE: the sample device seems to have broken sensors
    ACCEL_MAP = ["Tilt Only", "Impact and Tilt"]

    sensitivity = get_radio_value(s, "accelerometer_sensitivity_id")
    if not sensitivity.isnumeric():  # Ensure it is numeric (prevent breakage)
        sensitivity = "UNKNOWN"
    else:  # Parse and check range
        sensitivity = int(sensitivity)
        if sensitivity >= 1 and sensitivity <= 3:
            sensitivity = "UNKNOWN"
        else:  # Convert to human-readable string
            sensitivity = ACCEL_MAP[int(sensitivity)]

    return {
        "enabled": get_input_value(s, "checkbox", "accel_enable"),
        "sensitivity": sensitivity,
    }


# ---------------------------------------------------------------------------- #
#                            PasswordManagement.sel                            #
# ---------------------------------------------------------------------------- #


def parse_passwd_mgmt(soup: BeautifulSoup) -> dict[str, Any]:
    """Performs a basic parse of the table contents in the main page"""
    SPANS = {
        "next_generation_date": "display_nextGenerateDate",
        "next_generation_time": "display_nextGenerateTime",
        "next_change_date": "display_nextChangeDate",
        "next_change_time": "display_nextChangeTime",
    }

    result: dict[str, str | list[str]] = {
        s: get_text_of(soup, "span", {"id": SPANS[s]}) for s in SPANS
    }

    messages = get_text_of(soup, "div", {"id": "Messages"}).splitlines()
    if len(messages) > 0:
        result["messages"] = messages

    return result


# ---------------------------------------------------------------------------- #
#                              NetworkSettings.sel                             #
# ---------------------------------------------------------------------------- #


def parse_global_network_config(
    soup: BeautifulSoup,
) -> dict[Literal["hostname", "domain", "gateway", "dhcp_gateway"], Any]:
    """
    Retrieve the global configuration
    """
    hostname = get_text_of(soup, "td", {"id": "display_Hostname"})
    domain = get_text_of(soup, "td", {"id": "display_DomainName"})
    gateway = get_text_of(soup, "td", {"id": "display_Gateway"})

    result = {}
    if len(hostname) > 0:
        result["hostname"] = hostname
    if len(domain) > 0:
        result["domain"] = domain
    if len(gateway) > 0:
        result["gateway"] = gateway

    return result


def parse_network_nics(
    soup: BeautifulSoup,
) -> dict[str, dict[Literal["status", "configured"], bool]]:
    """
    Retrieve NIC status
    """
    table = find_table(soup, {"id": "NetworkInterfaces"})
    entries = find_tags(table, "img")
    result = {}

    for img in entries:
        # Ignore images without an alt text
        if not "alt" in img.attrs:
            continue

        # Get information from the alt text, as it says practically everything
        data = get_attrib_f(img, "alt").split(" - ")

        result[data[0]] = {"status": data[1], "configured": data[2]}

    return result


def parse_network_addresses(
    soup: BeautifulSoup,
) -> tuple[
    dict[str, Any],
    dict[str, list[str]],
]:
    """
    Retrieve network addresses and bridges

    The first element of the tuple is a dictionary of configuration data, while the other is
    """
    table = find_table(soup, {"id": "EthernetAddress"})
    entries = get_table_rows(table)

    def get_row(
        row: Tag,
    ) -> tuple[
        str,
        dict[Literal["interface", "ip", "vlan", "webserver"], Any],
        bool,
    ]:
        repr = {}

        alias = get_text_of(row, "td", {"class": "ui_AddressAlias"})
        repr["interface"] = get_text_of(row, "td", {"class": "ui_InterfaceAlias"})
        repr["address"] = get_text_of(row, "td", {"class": "ui_IP"})

        val = get_text_of(row, "td", {"class": "ui_VLAN"})
        if val.isnumeric():  # Only include the VLAN ID if there is one
            repr["vlan"] = int(val)

        msec = find_tag(row, "td", {"class": "ui_MACsec"})
        if msec:
            repr["MACsec"] = get_text_of(msec)

        repr["webserver"] = get_text_of(row, "td", {"class": "ui_WebServer"}) == "Yes"

        return alias, repr, "odd" in row.attrs["class"]

    # Parse all rows. This may be done the same regardless of the contents of the row
    parsed = [get_row(entry) for entry in entries]

    # Process the results. Bridged interfaces will all be either even or odd if they belong to the same bridge
    addresses = {}
    bridges: dict[str, list] = {}
    prev_o = True
    prev_a = ""

    for n, r, o in parsed:
        if prev_o == o:
            if not prev_a in bridges:
                bridges[prev_a] = []
            bridges[prev_a].append(r["interface"])
        else:
            prev_o = o
            prev_a = n
            addresses[n] = r

    return addresses, bridges


def parse_nat_config(soup: BeautifulSoup) -> dict[str, Any]:
    """Parses NAT config"""
    from re import split

    def parse_global_nat_config(table: Tag | BeautifulSoup) -> dict[str, Any]:
        result = {}
        CELLS = {
            "status": "display_AddressTranslationStatus",
            "network_alias": "nat_NetworkAlias",
            "subnet": "nat_IpAddress",
        }

        for cell in CELLS:
            result[cell] = get_text_of(table, attrib={"id": CELLS[cell]})

        return result

    def parse_nat_rule(row: Tag) -> dict[str, Any]:
        """Parses a row in the rules table"""
        result: dict[str, str | dict] = {}
        CELLS = {
            "alias": "ruleAlias",
            "protocol": "ruleProtocolName",
            "source": "rulePublicSource",
            "destination": "rulePrivateDestination",
            "verbose_logging": "ruleVerboseLogging",
        }

        for cell in CELLS:
            result[cell] = get_text_of(row, attrib={"class": CELLS[cell]})

        src = result["source"]
        assert isinstance(src, str)
        src = split(r"[:/]", src)
        result["source"] = {
            "address": src[0],
            "prefix": src[1],
            "port": src[2],
        }

        dst = result["destination"]
        assert isinstance(dst, str)
        dst = dst.split(":")
        result["destination"] = {
            "address": dst[0],
            "port": dst[1],
        }

        tag = find_tag(row, "span")
        if tag:
            result["message"] = get_attrib_f(tag, "title")

        return result

    result = parse_global_nat_config(soup)
    table = find_table(soup, {"id": "portForwardingRules"})
    rows = get_table_rows(table)

    rules = []
    for row in rows:
        rules.append(parse_nat_rule(row))

    result["rules"] = rules

    return result

"""
Parse data from /Diagnostics.sel.

Author: Francisco Santana
"""

from pathlib import Path
from types import FunctionType
from typing import Any

from bs4 import BeautifulSoup
from bs4.element import Tag
from loguru import logger

from peat import DeviceData


def countws(line: str) -> int:
    if len(line) == 0:
        return 0

    cur = 0
    while line[cur] == " ":
        cur += 1

    return cur


def parse_chain(chain: list[str]) -> dict[str, Any]:
    line = chain[0].split(" ")
    result = {}
    result["name"] = line[1]
    paren = chain[0].split("(")[1].split(" ")

    if paren[0] == "policy":
        if len(paren) > 2:
            result["policy"] = paren[1]
            paren = paren[2:]
        else:
            paren = []

    paren = " ".join(paren).strip("()").split(", ")
    ext = {x[1].strip(): x[0].strip() for x in [y.split(" ") for y in paren]}
    result.update(ext)

    tbl_header = [x for x in chain[1].split(" ") if len(x) > 0]

    if len(chain) <= 2:
        return result

    tbl = chain[2:]

    rules = []

    for row in tbl:
        cols = [x for x in row.split(" ") if len(x) > 0]
        row = {}
        for i in range(len(tbl_header)):
            row[tbl_header[i]] = cols[i]

        if len(cols) > len(tbl_header):
            row["extra"] = " ".join(cols[len(tbl_header) :])

        rules.append(row)

    result["rules"] = rules

    return result


def parse_firewall_state(lines: list[str]) -> dict[str, Any]:
    result = {}
    chains = []
    cur = 1
    last = 0

    # Split by chain
    while cur < len(lines):
        while cur < len(lines) and len(lines[cur]) > 4 and lines[cur][:5] != "Chain":
            cur += 1

        chains.append(lines[last:cur])
        last = cur
        cur += 1

    chains.append(lines[last:cur])

    for chain in chains:
        if len(chain) <= 1:
            continue

        chain = parse_chain(chain)
        name = chain["name"]
        del chain["name"]
        result[name] = chain

    return result


def parse_network_state(state: list[str]) -> dict[str, Any]:
    result = {}
    ifaces: list[list[str]] = []
    cur = 1
    last = 0

    # Split by interface
    while cur < len(state):
        while cur < len(state) and countws(state[cur]) > 0:
            cur += 1

        ifaces.append(state[last:cur])
        last = cur
        cur += 1

    for ns in ifaces:
        fl = ns[0].split(" ")
        lc = {}

        id = int(fl[0].strip(":"))
        lc["name"] = fl[1].strip(":")
        lc["conf"] = fl[2].strip("<>").split(",")

        pairs = [(fl[i - 1], fl[i]) for i in range(4, len(fl), 2)]

        for p in pairs:
            if p[1].isnumeric():
                lc[p[0]] = int(p[1])
            else:
                lc[p[0]] = p[1]

        lnws = countws(ns[1])
        fl = [x for x in ns[1].split(" ") if len(x) > 0]

        lc["link_type"] = fl[0].split("/")[1]
        if lc["link_type"] != "void":
            lc["link_addr"] = fl[1]
            lc["broadcast"] = fl[3]

        if len(ns) > 2:  # TODO: parse inet addresses and lifetimes
            lc["extra"] = [l[lnws:] for l in ns[2:]]

        result[id] = lc

    return result


def parse_route_table(lines: list[str]) -> list[str]:
    result = []

    for line in lines:  # TODO: find a way to properly parse each line
        if len(line) == 0:
            continue

        result.append(" ".join([l for l in line.split(" ") if len(l) > 0]))

    return result


def parse_hard_drive_usage(lines: list[str]) -> list[dict[str, Any]]:
    result = []

    for line in lines[1:]:
        line = [x for x in line.split(" ") if len(x) > 0]

        if len(line) == 0:
            continue

        result.append(
            {
                "filesystem": line[0],
                "size": line[1],
                "used": line[2],
                "available": line[3],
                "use_percent": line[4],
                "mounted_on": " ".join(line[5:]),
            }
        )

    return result


def parse_process_list(lines: list[str]) -> list[dict[str, Any]]:
    result = []

    for line in lines[1:]:
        line = [x for x in line.split(" ") if len(x) > 0]

        if len(line) == 0:
            continue

        result.append(
            {
                "labels": line[0].split(":"),
                "pid": int(line[1]),
                "user": line[2],
                "time": line[3],
                "command": " ".join(line[4:]),
            }
        )

    return result


def parse_free_mem(lines: list[str]) -> dict[str, Any]:
    mem = [x for x in lines[1].split(" ") if len(x) > 0]

    return {
        "physical": {
            "total": int(mem[1]),
            "used": int(mem[2]),
            "free": int(mem[3]),
            "shared": int(mem[4]),
            "buffers": int(mem[5]),
        },
        "buffers": {
            "used": int(mem[1]),
            "free": int(mem[2]),
        },
        "swap": {
            "total": int(mem[1]),
            "used": int(mem[2]),
            "free": int(mem[3]),
        },
    }


def first_line_parser(lines: list[str]) -> str:
    if len(lines) == 0:
        return ""
    return lines[0]


def noop_parser(lines: list[str]) -> list[str]:
    return lines


def joiner_parser(joiner: str) -> FunctionType:
    fn = lambda x: joiner.join(x)
    fn.__name__ = "Joiner"
    return fn


def int_parser(lines: list[str]) -> int:
    if len(lines) == 0:
        return 0
    return int(lines[0].strip())


def equals_parser(expected: str, if_equals: Any = True, otherwise: Any = False) -> FunctionType:
    fn = lambda x: if_equals if len(x) > 0 and x[0] == expected else otherwise
    fn.__name__ = f"equals_parser({expected})"
    return fn


def parse_diagnostics(
    soup: BeautifulSoup,
    headers: list[str],
    fields: list[str],
    parsers: list[FunctionType],
) -> dict[str, Any]:
    """
    Generic parser

    PARAMETERS:
        - soup    -> BeautifulSoup object encapsulating the page
        - headers -> List of strings representing the headers to be scanned for
        - fields  -> List of fields to store the parsed results to
        - parsers -> List of parsers for use in parsing diagnostics output
    """
    result = {}

    pre = soup.find("pre", {"id": "diagnosticsText"})
    assert isinstance(pre, Tag)
    pre = pre.get_text("\n", True).splitlines()

    result["pulled"] = " ".join(pre[0].split(" ")[1:]).strip("()")

    cur = 0  #  Cursor position
    begin = 0  # First line for next parser
    header = -1  # Header to look for
    p = -2  # Parser to execute

    while header < len(headers):
        # Increment parser and header, set begin to next
        p += 1
        header += 1
        begin = cur + 1

        if header == len(headers):
            cur = len(pre)  # Set cursor to end
        else:
            logger.debug(f"Finding header {headers[header]}")

            # Search for header in each line
            while cur < len(pre) and pre[cur] != headers[header]:
                cur += 1

        if p < 0:
            continue

        logger.debug(f"Parsing {fields[p]} with {parsers[p].__name__}")

        try:  # Try to parse; try-except to prevent outright failure
            result[fields[p]] = parsers[p](pre[begin : cur - 1])
        except Exception as e:
            logger.warning(f"Failed to parse with {parsers[p].__name__}")

    return result


def parse_diagnostics_R200(soup: BeautifulSoup) -> dict[str, Any]:
    """Parse the page (Firmware R200)"""
    HEADERS_R200 = [
        "Firewall State:",
        "Network State:",
        "Route Table State:",
        "Hard Drive Usage:",
        "Process List:",
        "Entropy Available:",
        "IPsec Configuration:",
        "IPsec State:",
        "IPsec Policy:",
        "IPsec Status:",
        "IPsec Total:",
        "Free Memory:",
        "Hardware Offload Events:",
        "SELinux Audit Failures:",
        "SELinux Enabled:",
        "Autoscopy Status:",
        "Whitelist Enabled:",
    ]

    FIELDS_R200 = [
        "firewall_state",
        "network_state",
        "route_table_state",
        "hard_drive_usage",
        "process_list",
        "available_entropy",
        "ipsec_config",
        "ipsec_state",
        "ipsec_policy",
        "ipsec_status",
        "ipsec_total",
        "free_memory",
        "hardware_offload_events",
        "selinux_audit_failures",
        "selinux",
        "autoscopy_status",
        "whitelist",
    ]

    PARSERS_R200 = [
        parse_firewall_state,  # Firewall state
        parse_network_state,  # Network state
        parse_route_table,  # Route table state
        parse_hard_drive_usage,  # Hard drive usage
        parse_process_list,  # Process list
        int_parser,  # Available entropy
        joiner_parser("\n"),  # TODO: does ipsec config need its own parser?
        first_line_parser,  # TODO: find an example for ipsec state
        first_line_parser,  # TODO: find an example for ipsec policy
        first_line_parser,  # TODO: find an example for ipsec status
        first_line_parser,  # TODO: find an example for ipsec total
        parse_free_mem,  # Free memory
        first_line_parser,  # TODO: find an example for hardware offload events
        first_line_parser,  # TODO: find an example for SELinux audit failures
        first_line_parser,  # SELinux Enabled
        equals_parser("1"),  # Autoscopy Status
        equals_parser('"1"'),  # Whitelist Enabled
    ]
    return parse_diagnostics(soup, HEADERS_R200, FIELDS_R200, PARSERS_R200)


def parse_diagnostics_R212(soup: BeautifulSoup) -> dict[str, Any]:
    """Parse the page (R212)"""
    HEADERS_R212 = [
        "Firewall State:",
        "NAT State:",
        "NAT and Port Forwarding connections:",
        "Network State:",
        "Route Table State:",
        "Hard Drive Usage:",
        "Process List:",
        "Entropy Available:",
        "IPsec Configuration:",
        "IPsec State:",
        "IPsec Policy:",
        "IPsec Status:",
        "IPsec Total:",
        "Free Memory:",
        "Hardware Offload Events:",
        "SELinux Audit Failures:",
        "SELinux Enabled:",
        "Autoscopy Status:",
        "Whitelist Enabled:",
    ]

    FIELDS_R212 = [
        "firewall_state",
        "nat_state",
        "nat_and_port_forwarding_connections",
        "network_state",
        "route_table_state",
        "hard_drive_usage",
        "process_list",
        "available_entropy",
        "ipsec_config",
        "ipsec_state",
        "ipsec_policy",
        "ipsec_status",
        "ipsec_total",
        "free_memory",
        "hardware_offload_events",
        "selinux_audit_failures",
        "selinux",
        "autoscopy_status",
        "whitelist",
    ]

    PARSERS_R212 = [
        parse_firewall_state,  # Firewall state
        parse_firewall_state,  # NAT state
        first_line_parser,  # NAT and Port Forwarding Connections
        parse_network_state,  # Network state
        parse_route_table,  # Route table state
        parse_hard_drive_usage,  # Hard drive usage
        parse_process_list,  # Process list
        int_parser,  # Available entropy
        joiner_parser("\n"),  # TODO: does ipsec config need its own parser?
        first_line_parser,  # TODO: find an example for ipsec state
        first_line_parser,  # TODO: find an example for ipsec policy
        first_line_parser,  # TODO: find an example for ipsec status
        first_line_parser,  # TODO: find an example for ipsec total
        parse_free_mem,  # Free memory
        first_line_parser,  # TODO: find an example for hardware offload events
        first_line_parser,  # TODO: find an example for SELinux audit failures
        first_line_parser,  # SELinux Enabled
        equals_parser("1"),  # Autoscopy Status
        equals_parser('"1"'),  # Whitelist Enabled
    ]

    return parse_diagnostics(soup, HEADERS_R212, FIELDS_R212, PARSERS_R212)

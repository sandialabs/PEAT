"""
Parsers and processors for Fortigate event logs.
These include "memory" events and other event sources.

Fortigate logs work this way.
Each log has a type, e.g. "System Events" or "Security Rating Events",
and a location, e.g. "Memory".

- There are three log locations:
    - Memory, means on the local device. These are usually present.
    - Fortianalyzer, which I think is an external configured device
    - FortiGate Cloud...the cloud
- There are a variety of types (API endpoints in parentheses):
    - System (system)
    - Router (router)
    - SD-WAN (sdwan)
    - User (user)
    - HA (ha)
    - Security Rating (security-rating)
    - WiFi (wireless)
    - SDN Connector (connector)
    - CIFS (cifs-auth-fail)
    - REST API (rest-api)

{'ha', 'system', 'vpn', 'security-rating', 'wireless', 'rest-api', 'user'}

I've only seen entries from "Memory" location, assuming logs from the
other two locations have the same format.
"""

import re
from datetime import datetime, UTC

from peat import DeviceData, Event, utils
from peat.protocols.common import IPV4_RE


def parse_fg_events(raw_data: str) -> list[dict[str, str]]:
    """
    Converts raw Fortigate event log file into a list of events,
    with key=value pairs as dicts.
    """
    parsed_data = []
    log_pattern = re.compile(r'(\w+)="([^"]+)"|(\w+)=([\w\.\-:]+)')

    for line in raw_data.splitlines():
        entry = {}

        for match in log_pattern.findall(line):
            key = match[0] if match[0] else match[2]
            value = match[1] if match[1] else match[3]
            entry[key] = value

        entry["raw_line"] = line
        parsed_data.append(entry)

    return parsed_data


def process_fg_events(events: list[dict[str, str]], dev: DeviceData) -> None:
    """
    Processes parsed fortigate events into the PEAT device data model.
    """
    for evt in events:
        # "eventtime" is UTC time, the date/time fields are timezone-adjusted
        # per the "TZ" field. For example, if the "tz" field is "-6000", then
        # the date/time fields would be 6 hours behind "eventtime".
        # Therefore, the "eventtime" field can be used as UTC, and the
        # "date", "time", and "tz" fields can be ignored.
        #
        # "eventtime" is in Nanoseconds
        # Python's datetime library can handle microseconds.
        # To address this, divide the nanosecond number to microseconds
        ts = datetime.fromtimestamp(int(evt["eventtime"]) / 1e9, tz=UTC)

        dataset = "memory"
        if evt.get("type"):
            dataset += f"_{evt['type']}"  # "event"
        if evt.get("subtype"):
            dataset += f"_{evt['subtype']}"  # Ex: "rest-api", "system"

        # no inherent sequence numbers
        event = Event(
            created=ts,
            dataset=dataset,
            id=evt.get("logid", ""),
            original=evt["raw_line"],
        )

        # extract IPs from anywhere in the line
        for ip_addr in re.findall(IPV4_RE, evt["raw_line"]):
            if utils.is_ip(ip_addr):
                dev.related.ip.add(ip_addr)

        for key in ["ip", "srcip", "dstip"]:
            if evt.get(key) and utils.is_ip(evt[key]):
                dev.related.ip.add(evt[key])

        if evt.get("mac"):
            dev.related.mac.add(evt["mac"].upper())

        if evt.get("msg"):
            event.message = evt["msg"]

            if evt.get("logdesc"):
                event.extra["logdesc"] = evt["logdesc"]

            if (
                "unable" in evt["msg"].lower()
                or "failed" in evt["msg"].lower()
                or evt["level"] == "critical"
            ):
                event.outcome = "failure"
            elif "started" in evt["msg"]:
                event.outcome = "success"

            if "logged in" in evt["msg"]:
                event.category.add("authentication")
                event.category.add("session")
                event.category.add("network")
                event.type.add("connection")
        elif evt.get("logdesc"):
            event.message = evt["logdesc"]

        if evt.get("user"):
            dev.related.user.add(evt["user"])
        if evt.get("profile"):
            dev.related.roles.add(evt["profile"])
        if evt.get("srcip") and evt.get("method"):
            dev.related.protocols.add(evt["method"])

        if "successful" in evt["raw_line"] or evt.get("status") == "success":
            event.outcome = "success"

        if evt.get("action") == "perf-stats":
            event.category.add("host")
            event.kind.add("metric")

        if evt.get("action"):
            event.action = evt["action"]

        if evt.get("level", "") in ["error", "critical"]:
            event.type.add("error")

        if evt.get("hostname"):
            dev.related.hosts.add(evt["hostname"])
            event.type.add("connection")

        # Copy everything to "extra" except irrelevant fields
        # This is due to the log events being split into many
        # key-value pairs, which depend on the subtype and
        # the exact event that occurred, and is impossible to
        # enumerate all possible keys. So, exclude, not include.
        for key, value in evt.items():
            if key not in [
                "raw_line",  # event.original
                # excluding date, time, and tz because irrelevant when eventtime is UTC
                "date",
                "time",
                "tz",
                "eventtime",  # event.created
                "logid",  # event.id
                "type",  # event.dataset
                "subtype",  # event.dataset
                "msg",  # event.message
                "logdesc",  # event.message, or already added to event.extra
                "action",  # set in => event.action
            ]:
                event.extra[key] = value

        dev.event.append(event)

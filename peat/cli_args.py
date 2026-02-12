"""
Commandline argument parsing and help. Used by cli_main.py.
"""

from __future__ import annotations

import argparse
import sys

from pathvalidate.argparse import validate_filepath_arg

help_str = """
To get help for a command, run "peat <command> --help" (example: "peat scan --help").

To get examples of how to use a command, run "peat <command> --examples" (example: "peat parse --examples"). Alternatively, to list examples for all commands, run "peat scan --all-examples".

To list modules currently imported by PEAT: "peat scan --list-modules" (or other --list-* arguments, as detailed above in the "optional arguments" section).

Data collected by PEAT is written to files in "./peat_results/" in the current directory (by default). Data can also be saved to Elasticsearch. See the help for specific sub-commands for details.

Refer to the PEAT documentation for a list of supported devices.
You can also run --list-modules or --list-all to get a list of the currently included device modules (e.g., "peat scan --list-modules").

On Linux, the man page may be available: "man peat"

Refer to the PEAT documentation for further information about PEAT's usage.

To report bugs or get help please contact peat@sandia.gov
"""


scan_examples = """
# Scan a single host
peat scan -i 192.0.2.1

# Discover devices on a network (scan a subnet) using Unicast IP
peat scan -i 192.0.2.0/24

# Discover devices on a network using IP broadcasts
peat scan -b 192.0.2.0/24

# Search for M340 and ControlLogix devices
peat scan -d m340 controllogix -i 192.0.2.0/24

# Search for PLCs
peat scan -d plc -i 192.0.2.0/24

# Discover devices on multiple networks, with verbose output
peat scan -v -i 192.168.200.0/24 192.0.2.0/24

# Scan a specific range of IP addresses (192.0.2.200 - 192.0.2.205)
peat scan -i 192.0.2.200-205

# Multiple subnets, specific IP, and only SCEPTRE and SEL devices
peat scan -d sceptre sel -i 192.0.2.0/24 192.0.0.0/24 192.168.0.10

# Multiple ranges of host arguments
# This combination resolves to 755 unique IPs
peat scan -i 172.16-30.80-90.12-14 192.0.2.19-23 localhost 10.0.9.0/24

# Broadcast using an interface
peat scan -b eth1

# Broadcast from a file
peat scan -b examples/broadcast_targets.txt

# Broadcast combinations
peat scan -b 192.0.2.0/24 192.0.0.255 192.168.0.0/25 eth1 examples/broadcast_targets.txt

# Use the results of a previous scan
peat scan -f examples/example-scan-summary.json

# Same as above, but with scan results piped to standard input (stdin)
cat examples/example-scan-summary.json | peat scan -f -

# Use a text file with hosts to target separated by newlines
peat scan -i examples/target_hosts.txt

# Use a JSON file with hosts to target as a JSON array
peat scan -i examples/target_hosts.json

# Use a combination of files and host strings
peat scan -i examples/target_hosts.txt examples/target_hosts.json 172.16.3.0/24 10.0.0.1

# Pipe results of one scan to another (note the "-q/--quiet" argument)
peat scan -q --print-results -d clx -i 192.0.2.0/24 | peat scan -f -

# Another example of piping results of one scan to another
# Note that '-E' is shorthand for '--print-results'
peat scan -q -E --sweep -i 192.0.2.0/24 | peat scan -f -

# Assume the host is online and skip the online check (similar to nmap -Pn)
# NOTE: this significantly increases the scan time of more than one host!
peat scan --assume-online -i 192.0.2.0/24

# Use previous results and skip online check
# Note: "-Y" is a shorthand for "--assume-online"
peat scan -Y -f examples/example-scan-summary.json

# Just find what hosts are online (similar to nmap -sn or -sS)
peat scan --sweep -i 192.0.2.0/24

# Upload results to an Elasticsearch server listening on localhost
peat scan -d selrelay -i 192.0.2.0/24 -e

# Send results to a Malcolm instance running on localhost
# Malcolm uses OpenSearch instead of Elasticsearch
peat scan -d selrelay -i 192.0.2.0/24 -e https://user:pass@localhost/mapi/opensearch

# Upload results to a remote Elasticsearch server
peat scan -d selrelay -i 192.0.2.0/24 -e http://192.0.2.20:9200

# Search for devices on serial ports 0 through 4 (COM0-4 on Windows or /dev/ttyS0-4 on Linux)
peat scan -s 0-4

# Scan for serial devices on /dev/ttyUSB0 and /dev/ttyS1
peat scan -s /dev/ttyUSB0 /dev/ttyS1

# Only use baud rate of 19200 when checking ports
peat scan -s 0-4 --baudrates 19200

# Enumerate active serial ports on a host
# On Windows, this would be COM0 - COM9
# On Linux, this would be /dev/ttyS0 - /dev/ttyS9 and /dev/ttyUSB0 - /dev/ttyUSB9
peat scan -s 0-9 --sweep

# Scan for SEL relays connected to serial devices on serial ports COM4 and COM6
peat scan -d selrelay -s COM4 COM6

# Same as above, but only attempt baud rate of 9600
peat scan -d selrelay -s COM4 COM6 --baudrates 9600

# Force identification checks of all ports during scanning, regardless of
# the status of the port and including closed ports. This takes significantly
# longer and generates much more traffic and load on devices. Only use if
# you aren't worried about potential performance impacts to field devices!
peat scan -d controllogix -i 192.0.2.0/24 --intensive-scan

# Name the run "scan_example". This will put results in ./peat_results/scan_example/
peat scan --run-name scan_example -d clx -i 192.0.2.0/24

# Use PEAT configuration settings from a YAML file (preferred method)
peat scan -d clx -i 192.0.2.0/24 -c peat-config.yaml

# List available modules
peat scan --list-modules

# List aliases
peat scan --list-aliases

# List mappings of aliases to PEAT module(s)
peat scan --list-alias-mappings

# List all modules, aliases, and alias to module mappings
peat scan --list-all

# Dry run, no scan will be executed
# Useful for verifying configuration options before pulling the
# metaphorical trigger on a scan.
peat scan --dry-run -d clx -i 192.0.2.0/24 -c peat-config.yaml
"""  # End scan_examples


pull_examples = """
# Pull artifacts from a single device
peat pull -i 192.0.2.1

# Pull artifacts from all devices on a subnet
peat pull -i 192.0.2.0/24

# Pull all devices discovered using IP broadcasts
peat pull -b 192.0.2.0/24

# Pull from an AB ControlLogix PLC
peat pull -d controllogix -i 192.0.2.1

# Pull from all RTUs on a subnet
peat pull -d rtu -i 192.0.2.0/24

# Pull from a single M340 PLC, with a 1-second timeout
peat pull -d m340 -i 192.0.2.41 -T 1.0

# Pull from any M340 and ControlLogix PLCs with
# IPs in the range from 192.0.2.1 and 192.0.2.5
peat pull -d m340 controllogix -i 192.0.2.1-5

# Pull from multiple subnets and a specific IP
peat pull -i 192.0.2.0/24 192.0.0.0/24 192.168.0.10

# Only output the results from the pull, no logs (-q is equivalent to --quiet)
peat pull -q --print-results -d m340 -i 192.0.2.1

# Pull from all M340 PLCs and upload results to a local Elasticsearch server
peat pull -d m340 -i 192.0.2.0/24 -e

# Send results to a Malcolm instance running on localhost
# Malcolm uses OpenSearch instead of Elasticsearch
peat pull -d m340 -i 192.0.2.0/24 -e https://user:pass@localhost/mapi/opensearch

# Upload pull results to a remote Elasticsearch server running on 192.0.0.33
# NOTE: utilize a PEAT YAML config file to further customize Elasticsearch settings (e.g. index names)
peat pull -d m340 -i 192.0.2.0/24 -e http://192.0.0.33:9200

# Pull logic and config from M340 and upload results to a local Elasticsearch server
peat pull -v -d m340 -i 192.0.2.0/24 -e

# Use the results of a previous scan, pull, or push
peat pull -f examples/example-scan-summary.json
cat examples/example-scan-summary.json | peat pull -f -

# Use a text file with hosts to target separated by newlines
peat pull -i examples/target_hosts.txt

# Assume the host is online and skip the online check (similar to nmap -Pn)
peat pull -d sceptre --assume-online -i 192.0.2.35
# "-Y" is a shorthand for "--assume-online"
peat pull -d sceptre -Y -i 192.0.2.35

# Use previous results and skip online check
peat pull --assume-online -f examples/example-scan-summary.json

# Pull from a Woodward 2301E on serial port 0 (COM0 on Windows or /dev/ttyS0 on Linux)
peat pull -d 2301e -s 0

# Colorize and format the results of a pull using 'jq'
# Note that '-E' is shorthand for '--print-results'
peat pull -q -E -d clx -i 192.0.2.0/24 | jq .

# Name the run "pull_example". This will put results in ./peat_results/pull_example/
peat pull --run-name pull_example -d clx -i 192.0.2.0/24

# YAML configuration file with PEAT settings
# This enables fine-grained configuration, including login credentials
peat pull -d clx -i 192.0.2.0/24 -c peat-config.yaml

# Dry run, no pull will be executed
# Useful for verifying configuration options before pulling the
# metaphorical trigger on a pull.
peat pull --dry-run -d clx -i 192.0.2.0/24
"""  # End pull examples


parse_examples = """
# Run on a saved Schneider M340 project file (aka "Station.apx" in Unity)
peat parse -d m340 ./project-file.apx

# Grab the first .apx file found in the directory
peat parse -d m340 ./folder/

# Parse a Schneider Unity project file on Windows (e.g. on a engineering workstation)
peat parse -d m340 'C:\\Projects\\Station.apx'

# Parse a SET_ALL.txt file from a SEL relay
peat parse -d selrelay ./SET_ALL.TXT

# Parse configuration from a SEL QuickSet database (*.rdb file)
peat parse -d sel breaker-1.rdb
peat parse -d sel ./*.rdb

# Multiple file paths arguments. PEAT will automatically select the
# appropriate module to use based on the file names, in this case SELRelay.
peat parse ./set_all.txt ./751_001.rdb

# Parse piped input (Linux and MacOS)
cat ./SET_ALL.TXT | peat parse -d selrelay

# Parse input via file redirection
peat parse -d m340 < ./project-file.apx

# Piping in Windows PowerShell
# Note: Get-Content won't work with binary blobs
Get-Content .\\set_all.txt | peat parse -d selrelay

# Process parse results using 'jq' to extract the IP address
peat parse -q --print-results -d m340 ./project-file.apx | jq '.["M340"][]["ip"]'

# Count number of events using 'jq'
# '-E' is shorthand for '--print-results'
peat pull -q -E -d selrtac -i 192.0.2.2 | jq '.event | length'

# Upload results to a Elasticsearch server running on localhost
peat parse -e -d selrelay ./SET_ALL.TXT

# Send results to a Malcolm instance running on localhost
# Malcolm uses OpenSearch instead of Elasticsearch
peat parse -d selrelay -e https://user:pass@localhost/mapi/opensearch ./SET_ALL.TXT

# Upload results to a remote Elasticsearch server at 192.0.2.5
peat parse -e http://192.0.2.5:9200 -d selrelay ./SET_ALL.TXT

# Parse out of a directory (NOTE: this recursively searches for files!)
peat parse -d m340 ./m340_files/

# Name the run "parse_example"
# This will put results in './peat_results/parse_example/'
peat parse --run-name parse_example -d selrelay ./SET_ALL.TXT

# YAML configuration file with PEAT settings
# This enables fine-grained configuration, including login credentials
peat parse -c peat-config.yaml -d sel ./SET_ALL.TXT
"""  # End parse examples


push_examples = """
# !!! NOTE !!!
# Due to a Python quirk, a '--' is required between optional
# arguments (such as device types or hosts) and the positional
# argument (the push filepath). Otherwise, it will error.

# Push firmware to an Allen-Bradley ControlLogix 1756 PLC
peat push -d controllogix -i 192.0.2.1 -- ./1756.011.dmk

# Push a single configuration file to a SEL relay
peat push -d selrelay -i 192.0.2.1 -- SET_1.TXT

# Push a directory containing configuration files to a SEL 451 Relay
peat push -d selrelay -i 192.0.2.1 -- ./SETTINGS/

# NOTE: currently, only a single file or directory can be specified for a push,
# multiple files cannot be specified. A workaround is to create a new directory,
# copy the config files to be pushed to the new directory, then specify that
# directory in the push command.
mkdir ./custom_configs/
cp ./SET_1.TXT ./SET_6.TXT ./custom_configs/
peat push -d selrelay -i 192.0.2.1 -- ./custom_configs/

# Update the config of all SEL relays on multiple subnets
peat push -d selrelay -i 192.0.2.0/24 192.0.0.0/24 -- ./SET_1.TXT

# Skip the scan and verification step before performing a push.
# This also implicitly skips the online check, implying '--assume-online'.
peat push --push-skip-scan -d selrelay -i 192.0.2.22 -- ./SET_1.TXT

# Use PEAT configuration settings from a YAML file
peat push -d selrelay -i 192.0.2.222 -c peat-config.yaml -- ./examples/devices

# Dry run, no push will be executed.
# Useful for verifying configuration options before pulling the
# metaphorical trigger on a push.
peat push --dry-run -d selrelay -i 192.0.2.21 -c peat-config.yaml -- ./examples/devices
"""  # End push examples


pillage_examples = """
# See the "Pillage" section in the PEAT documentation
# for a detailed explanation of the PILLAGE config,
# or refer to the example PEAT config YAML file.

# NOTE: the pillage output and extracted files
# are copied to the "pillage_results/" directory.

# Pillage files from a raw disk image
peat pillage -c peat-config.json -P raw_disk.img

# Pillage files from a mounted drive or local directory
peat pillage -c peat-config.json -P /home/user/pillage_this

# Pillage files from a VMDK image and upload results to a local Elasticsearch server
peat pillage -c peat-config.json -P raw_disk.vmdk -e

# Pillage files from a qcow2 image and upload results to a remote Elasticsearch server
peat pillage -c peat-config.json -P raw_disk.qcow2 -e http://192.0.2.33:9200/
"""  # End pillage examples


heat_examples = """
# HEAT: High-fidelity Extraction of Artifacts from Traffic

# List protocols available for use with HEAT
peat heat --list-heat-protocols

# Process packet data from the 'heat-elastic' Elasticsearch server and
# store the results in 'results-elastic' Elasticsearch server.
# NOTE: if '--heat-elastic-server' isn't specified then the value
# of '-e'/'--elastic-server' is used instead.
peat heat -e http://results-elastic:9200/ --heat-elastic-server http://heat-elastic:9200/

# Limit data to only Elasticsearch indices beginning with "packetbeat-2017."
# NOTE: '-e' with no argument defaults to 'http://localhost:9200/'
peat heat -e --heat-index-names "packetbeat-2017.*"

# Only output the files that were extracted and exit.
# The results will not be parsed by PEAT and will not be stored in Elasticsearch.
# These files will be in ./peat_results/<run-dir>/heat_artifacts/ (by default).
# This location is configurable using HEAT_ARTIFACTS_DIR or --heat-artifacts-dir.
peat heat -e --heat-file-only

# Exclude any results with an IP address of 192.0.2.10 or 192.0.2.20
# as the source or destination. Subnet ranges can also be used here.
peat heat -e --heat-exclude-ips 192.0.2.10 192.0.2.20

# Exclude any results from the subnet 192.0.2.0/24 (192.0.2.1 - 192.0.2.254)
peat heat -e --heat-exclude-ips 192.0.2.0/24

# Only include results with an IP from the subnet 192.0.2.0/24
# as the source or destination.
peat heat -e --heat-only-ips 192.0.2.0/24

# Limit search to a specific time range
peat heat -e --heat-date-range "2021-07-15T00:00:00.000 - 2021-07-16T12:34:12.143"

# Use PEAT configuration settings from a YAML file
peat heat -e -c peat-config.yaml
"""  # End HEAT examples


ALL_EXAMPLES: dict[str, str] = {
    "scan": scan_examples,
    "pull": pull_examples,
    "parse": parse_examples,
    "push": push_examples,
    "pillage": pillage_examples,
    "heat": heat_examples,
}


def build_argument_parser(version: str = "0.0.0") -> argparse.ArgumentParser:
    """
    Builds the argparse parser for parsing CLI commands and arguments.

    The ordering of how the arguments are added to the parsers matters.
    It looks wacky in the code, but it leads to cleaner output for the user.
    """

    parser = argparse.ArgumentParser(
        prog="peat",
        # Raw formatter prevents argparse from stripping
        # multiple newlines from the output.
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=help_str,
        description="PEAT: Process Extraction and Analysis Tool",
    )

    # --version, prints the string "PEAT <version>" and exits
    parser.add_argument("--version", action="version", version=f"PEAT {version}")

    # PEAT sub-commands (parse/pull/scan/push/pillage/heat)
    subparsers = parser.add_subparsers(title="commands")

    # Parse command
    parse_description = "Parse and extract data from project files, device configs, and PEAT pulls"
    parse_parser = subparsers.add_parser(
        name="parse",
        # help: displayed next to the sub-command when running "peat --help"
        help=parse_description,
        # description: displayed before the arguments when running "peat <command> --help"
        description=parse_description,
    )
    parse_parser.set_defaults(func="parse")

    # Pull command
    pull_description = "Pull and extract firmware, configs, logic, and/or logs from devices"
    pull_parser = subparsers.add_parser(
        name="pull",
        help=pull_description,
        description=pull_description,
    )
    pull_parser.set_defaults(func="pull")

    # Scan command
    scan_description = "Scan the network for devices"
    scan_parser = subparsers.add_parser(
        name="scan",
        help=scan_description,
        description=scan_description,
    )
    scan_parser.set_defaults(func="scan")

    # Push command
    push_description = "Push firmware, configuration, or logic to a device"
    push_parser = subparsers.add_parser(
        name="push",
        help=push_description,
        description=push_description,
    )
    push_parser.set_defaults(func="push")

    # Pillage command
    pillage_description = "Find and parse firmware, configuration, and logic from a disk image"
    pillage_parser = subparsers.add_parser(
        name="pillage",
        help=pillage_description,
        description=pillage_description,
    )
    pillage_parser.set_defaults(func="pillage")

    # HEAT command
    heat_description = (
        "HEAT (High-fidelity Extraction of Artifacts from Traffic). "
        "This feature finds file artifacts in network traffic parsed "
        "using ingest-tshark and stored in Elasticsearch. "
        "Examples of file artifacts include device firmware images, "
        "configuration files, and other files PEAT knows how to parse."
    )
    heat_parser = subparsers.add_parser(
        name="heat",
        help=heat_description,
        description=heat_description,
    )
    heat_parser.set_defaults(func="heat")

    # Config-Builder command
    config_builder_description = (
        "PEAT Configuration Builder - Textual in-console GUI for generating "
        "template YAML configuration files to use with PEAT."
    )
    config_builder_parser = subparsers.add_parser(
        name="config-builder",
        help=config_builder_description,
        description=config_builder_description,
    )
    config_builder_parser.set_defaults(func="config-builder")

    # Encrypt command
    encrypt_description = (
        "Encrypt a config file using PEAT's built in encryption capability. Must specify the file path to the config file using the -f flag. "
        "The encrypted file will be saved to the same directory as the original unencrypted config. "
        "The new file will be named the same as the unencrypted file, but will have 'encrypted_' added to the beginning of the filename. "
        "WARNING: PEAT will not save the encrypted file's password for you, it is up to you to remember it"
    )
    encrypt_parser = subparsers.add_parser(
        name="encrypt",
        # help: displayed next to the sub-command when running "peat --help"
        help=encrypt_description,
        # description: displayed before the arguments when running "peat <command> --help"
        description=encrypt_description,
    )
    encrypt_parser.set_defaults(func="encrypt")

    decrypt_description = (
        "Decrypt a config file using PEAT's built in decryption capability. Must specify the file path to the config file. "
        "The decrypted file will be saved to the same directory as the original encrypted config. "
        "IMPORTANT: PEAT will only decrypt configs that have previously been encrypted by PEAT, and upon receiving the correct password"
    )
    decrypt_parser = subparsers.add_parser(
        name="decrypt",
        # help: displayed next to the sub-command when running "peat --help"
        help=decrypt_description,
        # description: displayed before the arguments when running "peat <command> --help"
        description=decrypt_description,
    )
    decrypt_parser.set_defaults(func="decrypt")

    # Add arguments that we want specified after a command to all subparsers.
    # This is where any "general" peat arguments go (e.g "verbose").
    # NOTE: We add these before the command-specific
    #   arguments to order the usage list properly.
    # NOTE: "default=None" means "use the default in peat.config or elsewhere"
    for _, subp in subparsers.choices.items():
        group = subp.add_argument_group("general arguments")
        group.add_argument(
            "-c",
            "--config-file",
            type=str,
            metavar="FILE",
            default=None,
            help="Load PEAT configuration from a file (YAML or JSON)",
        )
        group.add_argument(
            "-I",
            "--import-modules",
            type=str,
            metavar="PATH",
            nargs="+",
            default=None,
            dest="additional_modules",
            help="Director(ies) or file(s) containing 3rd-party PEAT device "
            "module(s) to import and use. Modules are Python code "
            '(.py files) that subclass and implement "peat.DeviceModule".',
        )
        group.add_argument(
            "--no-color",
            action="store_true",
            default=None,
            help="Do not color terminal output",
        )
        group.add_argument(
            "--no-logo",
            action="store_true",
            default=None,
            help="Do not print the ASCII art startup logo",
        )
        group.add_argument(
            "-o",
            "--out-dir",
            type=validate_filepath_arg,
            metavar="PATH",
            default=None,
            help="Output directory for all runs of PEAT. "
            'Defaults to "peat_results" in the current directory.',
        )
        group.add_argument(
            "--run-dir",
            type=validate_filepath_arg,
            metavar="PATH",
            default=None,
            help="Directory to use for output for this run. "
            "Defaults to a directory in peat_results with either a "
            "auto-generated name or the value of --run-name.",
        )
        group.add_argument(
            "-R",
            "--run-name",
            type=str,
            metavar="NAME",
            default=None,
            help="Name of the run to use for creating the run directory, "
            "instead of auto-generating the name",
        )
        group.add_argument(
            "-q",
            "--quiet",
            "--silent",
            action="store_true",
            default=None,
            help="Do not output logging messages to the terminal (stdout)",
        )
        # TODO: delete in a future release (probably in 2025)
        group.add_argument(
            "-Q",
            "--no-print-results",
            action="store_true",
            default=None,
            help="DEPRECATED. Setting this no longer has any effect, "
            "as it's now the default behavior.",
        )
        group.add_argument(
            "-E",
            "--print-results",
            # Per CLIG: "Display output as formatted JSON if --json is passed"
            # https://clig.dev/#output
            "--json",
            action="store_true",
            default=None,
            help="Print JSON-formatted results from the operation to "
            "the terminal (stdout). Note that log messages will still "
            "be printed unless '--quiet' is specified.",
        )
        group.add_argument(
            "-v",
            "--verbose",
            action="store_true",
            default=None,
            help="Print DEBUG-level messages to terminal (they are still "
            "logged to a file even if this option isn't enabled)",
        )
        group.add_argument(
            "-V",
            "--debug",
            action="count",
            default=None,
            help="Enable debugging mode. Verbosity can be "
            'increased by adding more V\'s, e.g. "-VVV". '
            'Detailed protocol output generally starts at level 2 ("-VV").',
        )
        group.add_argument(
            "--dry-run",
            action="store_true",
            default=None,
            help="Dry run with no actions executed (e.g. scanning for peat scan)",
        )

        dev_group = subp.add_argument_group("development/debugging arguments")
        dev_group.add_argument(
            "--pdb",
            "--launch-debugger",
            action="store_true",
            default=None,
            help="Launch the Python debugger (pdb) after initialization and "
            "before executing commands. A REPL interface can also be "
            'accessed by running "interact" after launching pdb. '
            "(WARNING: this will NOT exit cleanly or safely!)",
        )
        dev_group.add_argument(
            "--repl",
            "--launch-interpreter",
            action="store_true",
            default=None,
            help="Launch the Python interactive interpreter, aka the "
            "Read-Eval-Print-Loop (REPL). Note that this will not "
            "necessarily include all of the global state. If you need "
            'to do in-depth debugging, use "--pdb", and run "interact".',
        )

        elastic_group = subp.add_argument_group("elasticsearch arguments")
        elastic_group.add_argument(
            "-e",
            "--elastic-server",
            "--opensearch-server",
            type=str,
            metavar="URL",
            default=None,
            nargs="?",
            const="http://localhost:9200/",
            help="Save results to an Elasticsearch or OpenSearch server. "
            "PEAT will automatically determine the server type. URL format: "
            "http://user:password@hostname-or-ip:9200/",
        )
        elastic_group.add_argument(
            "--elastic-timeout",
            type=float,
            default=None,
            help="Timeout to connect to the Elasticsearch or OpenSearch server",
        )
        elastic_group.add_argument(
            "--elastic-save-blobs",
            action="store_true",
            default=None,
            help="Save large binary objects (e.g. firmware image) to Elasticsearch or OpenSearch",
        )

    # Parse command arguments
    parse_parser.add_argument(
        "-d",
        "--device",
        "--device-types",
        "--peat-modules",
        type=str,
        required=False,
        metavar="TYPES",
        action="append",
        default=None,
        dest="device_types",
        help="The type of the device(s) to parse using from. These can be the "
        'name of a PEAT module, device vendor, device type (e.g. "plc"), '
        "or other aliases. This can be a single string or a space-separated list of strings. "
        "Input from stdin (pipe/redirect) must be a single device type.",
    )

    # HEAT: High-fidelity Extraction of Artifacts from Traffic
    add_list_module_args(heat_parser)  # Hack to add "--list-*" commands
    heat_group = heat_parser.add_argument_group("HEAT arguments")
    heat_group.add_argument(
        "--list-heat-protocols",
        action="store_true",
        default=None,
        help="List the available HEAT protocol extractors",
    )
    heat_group.add_argument(
        "--heat-elastic-server",
        type=str,
        metavar="ELASTIC_URL",
        default=None,
        help="Elasticsearch server to query for Packetbeat data for use with "
        "artifact extraction (HEAT). If this argument isn't specified, "
        "then the value of --elastic-server will be used instead. This "
        "argument is distinct from --elastic-server and the values of "
        "the two are allowed to differ, e.g. extract from data on one "
        "server and put the results into a different server. "
        "URL format: http://user:password@hostname-or-ip:9200/",
    )
    heat_group.add_argument(
        "--heat-index-names",
        type=str,
        metavar="INDEX_NAMES",
        default=None,
        help="Elasticsearch index names or patterns with the Packetbeat data"
        "to use for extraction. This can be multiple index names and/or "
        "patterns, comma-separated. Same format as Elasticsearch's API. "
        'Example: "packetbeat-2021.05.03,packetbeat-2021.05.04,'
        'packetbeat-2021.04.*"',
    )
    heat_group.add_argument(
        "--heat-date-range",
        type=str,
        metavar="DATE_RANGE",
        default=None,
        help="Date range to limit extraction to. Format: "
        '"<timestamp> - <timestamp>". Example: '
        '"2021-07-15T00:00:00.000 - 2021-07-16T12:34:12.143"',
    )
    heat_group.add_argument(
        "--heat-exclude-ips",
        type=str,
        nargs="+",
        metavar="IP_ADDRESSES",
        default=None,
        help="IP addresses or subnets to exclude from search (source and/or "
        "destination IP). Example: 192.0.2.33 192.0.0.0/24",
    )
    heat_group.add_argument(
        "--heat-only-ips",
        type=str,
        nargs="+",
        metavar="IP_ADDRESSES",
        default=None,
        help="IP addresses or subnets to limit search to (source and/or "
        "destination IP). Example: 192.0.2.33 192.0.0.0/24",
    )
    heat_group.add_argument(
        "--heat-file-only",
        action="store_true",
        default=None,
        help="Skip parsing of extracted files using PEAT (just extract the files)",
    )
    heat_group.add_argument(
        "--heat-artifacts-dir",
        type=validate_filepath_arg,
        metavar="PATH",
        default=None,
        help="Output directory for artifacts extracted by HEAT. "
        'Defaults to "./peat_results/<run-dir>/heat_artifacts/".',
    )
    heat_group.add_argument(
        "--heat-protocols",
        type=str,
        nargs="+",
        metavar="PROTOCOLS",
        default=None,
        help="Protocols for HEAT to use. Defaults to All",
    )
    heat_group.add_argument(
        "--pcaps",
        type=validate_filepath_arg,
        metavar="PCAPS",
        default=None,
        help="Filepath to folder containing PCAPs for processing",
    )
    heat_group.add_argument(
        "--no-run-zeek",
        action="store_true",
        default=False,
        help="Flag to tell PEAT not to run zeek and instead run on "
        "existing Zeek output (on the directory specified with "
        "--zeek-dir)",
    )
    heat_group.add_argument(
        "--zeek-dir",
        type=validate_filepath_arg,
        metavar="ZEEKDIR",
        default=None,
        help="Filepath to direct PEAT to a zeek output directory",
    )

    # Pull command arguments
    pull_parser.add_argument(
        "-d",
        "--device",
        "--device-types",
        "--peat-modules",
        type=str,
        required=False,
        metavar="TYPE",
        nargs="+",
        default=["all"],
        dest="device_types",
        help="The type of the device(s) to pull from. This can be the name "
        'of a PEAT module, device vendor, device type (e.g. "plc"), '
        "or other aliases. This can be a single string or a space-separated list of strings.",
    )

    # !! NOTE !!
    # input_source is duplicated between parse and push because the order they are
    # added to the parser matters. DO NOT CHANGE unless you know what you're doing.
    # NOTE: glob args, like "./dir/*.rdb", result in a list of filenames in the
    # value returned by argparse. PEAT doesn't get the "*.rdb" value, it gets a bunch
    # of .rdb filenames, e.g. [file1.rdb, file2.rdb, ...]
    parse_parser.add_argument(
        "input_source",
        type=str,
        default=["-"],
        nargs="*",
        help="Paths of files and/or directories to parse. If nothing "
        'or a "-" is specified, then stdin (piped input) is used.',
    )
    add_list_module_args(parse_parser)  # Hack to add "--list-*" commands

    # Scan command arguments
    scan_parser.add_argument(
        "-d",
        "--device",
        "--device-types",
        "--peat-modules",
        type=str,
        required=False,
        metavar="TYPES",
        nargs="+",
        default=["all"],
        dest="device_types",
        help="Limit scan to a specific device type. This can "
        "be the name of a PEAT module, device vendor, "
        'device type (e.g. "plc"), or other aliases. '
        "This can be a single string or a space-separated list of strings.",
    )
    scan_parser.add_argument(
        "--sweep",
        "--enumerate",
        action="store_true",
        dest="scan_sweep",
        help="Check what hosts are online using the standard methods (TCP "
        "SYN, ARP, or ICMP) and exit. If serial ports are targeted, "
        "this will enumerate the active serial ports on the host.",
    )

    for subp in [pull_parser, scan_parser, push_parser]:
        subp.add_argument(
            "-T",
            "--timeout",
            type=float,
            default=None,
            dest="default_timeout",
            help="Number of seconds to wait for responses. WARNING: if using a "
            "YAML config file, setting this argument will override ANY AND ALL "
            "timeouts configured in that file, including protocol-specific timeouts!",
        )
        subp.add_argument(
            "--baudrates",
            type=str,
            default=["9600-115200"],
            nargs="+",
            help="Serial baud rate(s) to try. Use a single number to specify a "
            "single rate, or dash-separated numbers to specify a range of "
            "rates.",
        )
        subp.add_argument(
            "-Y",
            "--assume-online",
            action="store_true",
            default=None,
            help="Assume all hosts are online. Skips the host online "
            "status checks (TCP SYN, ICMP, or ARP requests).",
        )
        subp.add_argument(
            "--intensive-scan",
            action="store_true",
            default=None,
            dest="intensive_scan",
            help="Force identification checks of all ports during scanning. "
            "Normally PEAT will only perform identification on ports "
            "that are open. This option overrides that behavior and "
            "forces every potential service be checked. The services "
            "and ports checked vary based on the imported modules "
            "and other information sources, such as imported scan "
            "results.",
        )
        host_group = subp.add_mutually_exclusive_group(required=True)
        host_group.add_argument(
            "-i",
            "--ip",
            "--hosts",
            type=str,
            metavar="HOSTS",
            default=None,
            nargs="+",
            dest="host_list",
            help="Network hosts to target or filenames with hosts to target. "
            "IPv4 addresses and hostnames can be used, as well as CIDR "
            '"/" notation to specify subnet ranges. Nmap-style host and '
            'network ranges are accepted, e.g. "192.0.2.20-40" or '
            '"192.168.0-4.0". If a file or set of files is specified, '
            "they will be read and the hosts will be added to the list "
            "Host strings in files can be space, tab, or newline-separated. "
            "Basically, PEAT will call .split() on whatever is in the file.",
        )
        host_group.add_argument(
            "-s",
            "--serial-ports",
            type=str,
            metavar="PORTS",
            default=None,
            nargs="+",
            dest="port_list",
            help="Serial port(s) to target. Use a single number to specify a "
            "single port (0), or numbers separated by a - to specify a "
            "range of ports (e.g. 0-4). Alternatively, platform-specific "
            "port names can be used (e.g. /dev/ttyUSB0).",
        )
        host_group.add_argument(
            "-f",
            "--host-file",
            type=str,
            metavar="FILE",
            default=None,
            help="JSON PEAT scan result file with hosts to scan/pull. "
            "This will override the --hosts argument.",
        )
        host_group.add_argument(
            "-b",
            "--broadcast-targets",
            type=str,
            metavar="TARGETS",
            default=None,
            nargs="+",
            dest="broadcast_list",
            help="Network broadcast targets to use for scanning. Targets can "
            'be IP subnet broadcast addresses ("192.0.2.255"), MAC '
            'broadcast addresses ("ff:ff:ff:ff:ff:ff") or local system '
            'network interfaces ("eth0").',
        )
        add_list_module_args(host_group)  # Hack to add "--list-*" commands

    # Push command
    push_parser.add_argument(
        "-d",
        "--device",
        "--device-types",
        "--peat-modules",
        type=str,
        required=False,
        metavar="DEVICE",
        nargs="+",
        dest="device_types",
        help="The type of device to push to",
    )
    push_parser.add_argument(
        "-t",
        "--push-type",
        type=str,
        metavar="PUSH-TYPE",
        default="config",
        help="What type of information to push, either 'config' or 'firmware'",
        choices=["config", "firmware"],
    )
    push_parser.add_argument(
        "--push-skip-scan",
        action="store_true",
        default=None,
        help="Skip scanning and verification of hosts being pushed to, "
        "and assume all hosts are online and valid devices. NOTE: "
        "this requires a single device type to be specified.",
    )
    push_parser.add_argument(
        "input_source",
        type=str,
        default="-",
        nargs="?",
        help="Path to file or a directory containing files to "
        'push to the device. If nothing or a "-" is '
        "specified, then stdin (piped input) is used.",
    )

    # Pillage Commands
    # TODO: make this positional
    pillage_parser.add_argument(
        "-P",
        "--pillage-source",
        type=str,
        required=False,
        metavar="SOURCE",
        dest="pillage_source",
        help="Source to pillage either a raw image file or directory "
        "location. Defaults to local directory if nothing "
        'specified. If the source is a "split" VMware VMDK disk '
        "(e.g. multiple VMDK files that make up a single disk), "
        'use the file without the "-sXXX" in the name as the source.',
    )
    add_list_module_args(pillage_parser)  # Hack to add "--list-*" commands

    # Encrypt command
    encrypt_parser.add_argument(
        "-f",
        "--file-path",
        type=str,
        metavar="FILE",
        default=None,
        dest="filepath",
        help="File path for config file to encrypt",
    )

    encrypt_parser.add_argument(
        "-p",
        "--password",
        type=str,
        metavar="USER_PASS",
        default=None,
        dest="user-password",
        help="Specify password to use to encrypt/decrypt file",
    )
    add_list_module_args(encrypt_parser)  # Hack to add "--list-*" commands

    decrypt_parser.add_argument(
        "-f",
        "--file-path",
        type=str,
        metavar="FILE",
        default=None,
        dest="filepath",
        help="File path for config file to decrypt",
    )
    decrypt_parser.add_argument(
        "-w",
        "--write-file",
        type=str,
        metavar="DIR",
        default=None,
        dest="write-path",
        help="File path to save decrypted file to",
    )

    decrypt_parser.add_argument(
        "-p",
        "--password",
        type=str,
        metavar="USER_PASS",
        default=None,
        dest="user-password",
        help="Specify password to use to encrypt/decrypt file",
    )
    add_list_module_args(decrypt_parser)  # Hack to add "--list-*" commands

    return parser


def parse_peat_arguments(version: str = "ERROR") -> argparse.Namespace:
    """Parses command line arguments."""
    parser = build_argument_parser(version=version)

    # Print the help message if no arguments were passed
    if len(sys.argv) == 1:
        parser.print_help()
        parser.exit()
    # sub-command help with no args
    elif len(sys.argv) == 2 and sys.argv[1] != "config-builder":
        sys.argv.append("--help")

    # Parse the arguments
    args = parser.parse_args()
    return args


def add_list_module_args(
    parser_or_group: argparse._ArgumentGroup | argparse.ArgumentParser,
) -> None:
    """
    Hack to add the module listing arguments to parsers with
    mutually-exclusive groups that require one argument (scan/pull/push)
    and normal parsers (parse/pillage/heat).

    This also adds the --examples and --all-examples arguments.
    """
    parser_or_group.add_argument(
        "--list-all",
        action="store_true",
        default=None,
        help="List the currently imported device modules, their aliases, "
        "and alias mappings, then exit. This includes modules "
        'imported with "-I". WARNING: this has a LOT of output, do not run '
        "if you are using a screen reader.",
    )
    parser_or_group.add_argument(
        "--list-modules",
        action="store_true",
        default=None,
        help="Print the currently imported device modules, then exit. "
        'This includes modules imported with "-I".',
    )
    parser_or_group.add_argument(
        "--list-aliases",
        action="store_true",
        default=None,
        help="Print aliases for the currently imported device modules, "
        'then exit. This includes modules imported with "-I".',
    )
    parser_or_group.add_argument(
        "--list-alias-mappings",
        action="store_true",
        default=None,
        help="Print alias mappings for the currently imported device "
        'modules, then exit. This includes modules imported with "-I". '
        "WARNING: this has a LOT of output, do not run if you are using a screen reader.",
    )
    parser_or_group.add_argument(
        "--examples",
        action="store_true",
        default=None,
        help="Print examples for the current command, then exit.",
    )
    parser_or_group.add_argument(
        "--all-examples",
        action="store_true",
        default=None,
        help="Print examples for all commands, then exit.",
    )

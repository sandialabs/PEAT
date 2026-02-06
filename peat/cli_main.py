import code
import json
import pdb  # noqa: T100
import sys
import timeit
from pathlib import Path
from pprint import pformat
from typing import Any, get_args

from humanfriendly.text import pluralize

from peat import (
    PeatError,
    cli_args,
    config,
    consts,
    datastore,
    decrypt,
    encrypt,
    exit_handler,
    heat_main,
    initialize_peat,
    log,
    module_api,
    parse,
    pillage,
    pull,
    push,
    scan,
    state,
    utils,
)
from peat.config_builder import launch_builder
from peat.heat import HEAT_EXTRACTORS

TargetsType = tuple[list[str], consts.AllowedCommTypes, list[str]]


def run_peat(args: dict[str, Any], start_time: float) -> None:
    """
    CLI main (note: the entrypoint that calls this is in ``__main__.py``).
    """

    try:
        initialize_peat(conf=args, entrypoint="CLI")
    except Exception as ex:
        log.error(f"Failed to initialize peat: {ex}")
        sys.exit(1)

    log.trace4(f"** Raw CLI arguments **\n{pformat(args, indent=4)}\n")

    # Print imported modules and aliases, then exit
    if args.get("list_modules"):
        print(json.dumps(module_api.names), flush=True)  # noqa: T201
        sys.exit(0)

    if args.get("list_aliases"):
        print(  # noqa: T201
            json.dumps(list(module_api.module_aliases.keys())), flush=True
        )
        sys.exit(0)

    if args.get("list_alias_mappings"):
        print(json.dumps(module_api.alias_mappings), flush=True)  # noqa: T201
        sys.exit(0)

    if args.get("list_all"):
        print(  # noqa: T201
            f"** Modules **\n"
            f"{pformat(module_api.names, compact=True)}"
            f"\n\n** Aliases **\n"
            f"{pformat(list(module_api.module_aliases.keys()), compact=True)}"
            f"\n\n** Alias Mappings **\n"
            f"{pformat(module_api.alias_mappings, compact=True)}",
            flush=True,
        )
        sys.exit(0)

    # Print examples for the current sub-command, e.g. "scan"
    if args.get("examples"):
        print(cli_args.ALL_EXAMPLES[args["func"]].strip(), flush=True)  # noqa: T201
        sys.exit(0)

    # Print examples for all commands, then exit
    if args.get("all_examples"):
        all_examples = ""
        for cmd, examples in cli_args.ALL_EXAMPLES.items():
            all_examples += f"** {cmd} examples **\n{examples}\n\n"
        print(all_examples.strip(), flush=True)  # noqa: T201
        sys.exit(0)

    if args.get("list_heat_protocols"):
        print(  # noqa: T201
            ", ".join(plugin.__name__ for plugin in HEAT_EXTRACTORS), flush=True
        )
        sys.exit(0)

    # Run configuration builder Textual interface
    if args["func"] == "config-builder":
        launch_builder()
        sys.exit(0)

    # Drop into pdb (Python debugger)
    if args["pdb"]:
        pdb.set_trace()  # noqa: T100

    # Drop into interactive interpreter (the "REPL")
    if args["repl"]:
        code.interact(local=globals())

    # Execute CLI commands
    # NOTE: in the future, this will execute continuous
    # monitoring and/or the standard "one-shot" CLI commands.
    if not oneshot_main(args):
        state.error = True

    # Dump config to Elasticsearch
    if state.elastic and config.ELASTIC_SAVE_CONFIG:
        log.info(
            f"Saving configuration to {state.elastic.type} "
            f"(index basename: {config.ELASTIC_CONFIG_INDEX})"
        )
        raw_config = config.export()

        # BUGFIX: remove raw options from PEAT config pushed to Elasticsearch
        # The dynamic mappings generated for these fields can vary and cause pushes to fail
        for opt in ["DEVICE_OPTIONS", "HOSTS"]:
            if raw_config.get(opt):
                del raw_config[opt]

        if not state.elastic.push(config.ELASTIC_CONFIG_INDEX, raw_config):
            log.warning(f"Failed to save configuration to {state.elastic.type}")

    # Dump state to Elasticsearch
    if state.elastic and config.ELASTIC_SAVE_STATE:
        log.info(
            f"Saving state to {state.elastic.type} (index basename: {config.ELASTIC_STATE_INDEX})"
        )

        if not state.elastic.push(config.ELASTIC_STATE_INDEX, state.export()):
            log.warning(f"Failed to save state to {state.elastic.type}")

    # Record end time and duration in the log
    duration = timeit.default_timer() - start_time
    log.info(f"Finished run in {utils.fmt_duration(duration)} at {utils.utc_now()} UTC")

    # Cleanup all empty directories on exit
    if config.OUT_DIR and config.RUN_DIR.exists():
        utils.clean_empty_dirs(config.RUN_DIR)
    elif config.OUT_DIR and config.OUT_DIR.exists():
        utils.clean_empty_dirs(config.OUT_DIR)

    # Fix ownership of peat_results to be actual user instead of "root".
    # Only gets executed if running as root on a POSIX system.
    # exit_handler.register() here to run on exit after other atexit
    # handlers run (e.g. config/state dumps).
    if consts.POSIX and state.superuser_privs and config.OUT_DIR and config.RUN_DIR.exists():
        exit_handler.register(utils.fix_file_owners, "FILE", args=(config.RUN_DIR,))

    # Write the README.md file to OUT_DIR (e.g., ./peat_results/README.md)
    if config.OUT_DIR and config.OUT_DIR.exists():
        write_readme()

    # Exit with exit code 1 if failure, 0 if successful
    if state.error:
        log.warning("PEAT run failed! See logs for details.")
        sys.exit(1)
    else:
        log.debug("PEAT run finished successfully (no major errors)")
        sys.exit(0)


def oneshot_main(args: dict[str, Any]) -> bool:
    """
    Main logic when running a regular PEAT command, e.g. ``peat scan``.

    This is distinct from the other current and future capabilities,
    such as monitoring or the PEAT HTTP server. "oneshot" refers to
    the "run and done" (in "one shot") and non-persistent nature of
    the traditional PEAT CLI commands.
    """

    if args["func"] == "heat":
        return heat_main()

    if args["func"] == "encrypt":
        result = encrypt(args["filepath"], args["user-password"])
        if result:
            log.info("Done encrypting file, exiting...")
            sys.exit(0)
        else:
            log.critical("Error encountered while encrypting file, exiting...")
            sys.exit(1)

    if args["func"] == "decrypt":
        result = decrypt(
            config_path=args["filepath"],
            output_path=args["write-path"],
            user_password=args["user-password"],
        )
        if result:
            log.info("Done decrypting file, exiting...")
            sys.exit(0)
        else:
            log.critical("Error encountered while decrypting file, exiting...")
            sys.exit(1)

    targets = []  # type: list[str]
    device_types = set()  # type: set[str]

    # Include any imported third-party modules
    device_types.update(module_api.runtime_imports)

    # Populate the list of devices to use (will be resolved to PEAT modules)
    if args["func"] in ["scan", "pull", "push"]:
        try:
            targets, comm_type, module_names = get_targets(args)
        except PeatError as err:
            log.critical(err)
            return False

        state.comm_type = comm_type  # set the global value

        device_types.update(module_names)

        log.info(
            f"Running {args['func']} of {pluralize(len(targets), 'target')} using "
            f"{pluralize(len(device_types), 'module')} (comm_type: {comm_type})"
        )
        log.debug(f"{args['func']} targets: {targets}")
        log.debug(f"{args['func']} modules: {list(device_types)}")

    elif args["func"] == "parse":
        if args["device_types"] is None and not device_types:
            device_types.add("all")
        elif args["device_types"] is not None:
            device_types.update(args["device_types"])

    # Ensure inputs are deterministic (consistent order every run)
    sorted_device_types: list[str] = sorted(device_types)

    if config.DRY_RUN:
        log.warning("Dry run enabled, skipping calling command functions")
        return True

    # Call the appropriate PEAT function for the command specified
    try:
        if args["func"] == "parse":
            parse_results = parse(args["input_source"], sorted_device_types)

            if not parse_results:
                return False

            if config.PRINT_RESULTS:
                print(  # noqa: T201
                    json.dumps(consts.convert(parse_results), indent=4), flush=True
                )

            return True

        elif args["func"] == "pull":
            pull_results = pull(targets, comm_type, sorted_device_types)

            if not pull_results:
                return False

            success = export_device_data(args)

            if config.PRINT_RESULTS:
                print_results = consts.convert(pull_results.get("pull_results", {}))
                print(json.dumps(print_results, indent=4), flush=True)  # noqa: T201

            return success

        elif args["func"] == "scan":
            scan_summary = scan(targets, comm_type, sorted_device_types)

            if not scan_summary:
                return False

            success = export_device_data(args)

            if config.PRINT_RESULTS:
                print(json.dumps(scan_summary, indent=4), flush=True)  # noqa: T201

            return success

        elif args["func"] == "push":
            if not push(
                targets,
                comm_type,
                sorted_device_types,
                args["input_source"],
                args["push_type"],
                skip_scan=config.PUSH_SKIP_SCAN,
            ):
                return False

            return export_device_data(args)

        elif args["func"] == "pillage":
            return pillage(args["pillage_source"])

        else:
            log.critical(f"Unknown func: {args['func']}")
    except PeatError as ex:
        log.error(f"{args['func']} failed: {ex}")
    except Exception:
        log.exception(f"{args['func']} failed due to unhandled exception")

    return False


def export_device_data(args: dict[str, Any]) -> bool:
    """
    Export data from all devices in the datastore to files and/or Elasticsearch.
    """

    # Combine any duplicate devices before exporting
    datastore.deduplicate(prune_inactive=args["func"] in ["scan", "pull", "push"])

    devices = [d for d in datastore.objects if d._is_verified or (d._is_active and d._module)]
    success = True

    if not devices:
        log.warning("No device results, skipping export")
        return True

    if config.DEVICE_DIR:
        log.info(f"Exporting data from {pluralize(len(devices), 'host')} to files...")

        for dev in devices:
            if not dev.export_to_files(overwrite_existing=True):
                success = False

    # pull and parse already export
    if state.elastic and args["func"] not in ["pull", "parse"]:
        log.info(
            f"Exporting data from {pluralize(len(devices), 'host')} to {state.elastic.type}..."
        )

        for dev in devices:
            try:
                if not dev.export_to_elastic():
                    success = False
            except Exception:
                log.exception(
                    f"Failed to export data to {state.elastic.type} for device '{dev.get_id()}'"
                )
                success = False

    return success


def get_targets(args: dict[str, Any]) -> TargetsType:
    """
    Collect targets and module names from a file or CLI argument.
    """
    # Read from JSON host file (not to be confused with the YAML config)
    if args.get("host_file"):
        file_data = read_host_file(args["host_file"])

        if file_data is None:
            raise PeatError("Bad host file")

        try:
            targets, comm_type, module_names = parse_scan_summary(file_data)
        except Exception as ex:
            raise PeatError(f"Failed to parse host file (scan summary) : {ex}") from ex

    # Read from CLI args
    else:
        module_set = set(args["device_types"])  # type: set[str]

        id_key = "ip"
        if args.get("host_list"):
            comm_type = "unicast_ip"
            targets = args["host_list"]  # type: list[str]
        elif args.get("broadcast_list"):
            comm_type = "broadcast_ip"
            targets = args["broadcast_list"]  # type: list[str]
        elif args.get("port_list"):
            comm_type = "serial"
            id_key = "serial_port"
            targets = args["port_list"]  # type: list[str]
        else:
            raise PeatError("Bad target arguments")

        if config.DEBUG >= 2:
            log.debug(
                f"Raw targets before doing lookup of hosts in YAML config"
                f"\ncomm_type: {comm_type}\ntargets: {targets}"
                f"\nmodule_set: {module_set}"
            )

        # Use the hosts in the YAML config to populate the targets list
        if len(targets) == 1 and targets[0] == "all":
            log.info(
                "Attempting to use ALL of the hosts in the YAML config as targets, "
                "since 'all' was specified as the target"
            )

            if not config.HOSTS:
                raise PeatError("No hosts in YAML config to use with the 'all' target")
            if comm_type not in ["unicast_ip", "serial"]:
                raise PeatError("The 'all' target only works with IP or serial hosts")

            targets = []

            for host in config.HOSTS:
                if not host.get("identifiers"):
                    log.warning(
                        f"For 'all' target, skipping host with missing 'identifiers' field: {host}"
                    )
                    continue

                if not host["identifiers"].get(id_key):
                    continue

                # Get 'ip' or 'serial_port' field
                targets.append(host["identifiers"][id_key])

                if host.get("peat_module"):
                    module_set.add(host["peat_module"])

        # Allow labels from hosts in a YAML config to be used as targets
        # Case-insensitive matching of labels, however full string must match
        elif config.HOSTS and comm_type in ["unicast_ip", "serial"]:
            # Build lookup table mapping host labels to identifiers
            # e.g. {"host1": "192.0.2.2"}
            lookup_id = {}  # type: dict[str, str]
            lookup_mod = {}  # type: dict[str, str]

            for host in config.HOSTS:
                # Skip hosts without a label since this is for label lookups only
                if not host.get("label"):
                    continue

                # Get 'ip' or 'serial_port' field and add to lookup table
                if host.get("identifiers", {}).get(id_key):
                    lookup_id[host["label"].lower()] = host["identifiers"][id_key]

                # Add the host's PEAT module to lookup table of modules
                if host.get("peat_module"):
                    lookup_mod[host["label"].lower()] = host["peat_module"]

            # Replace any targets that match the label of a
            # host in the YAML config with that host's identifier.
            targets = [lookup_id.get(target.lower(), target) for target in targets]

            # Add peat modules from hosts in YAML to the set of modules to use
            module_set.update(lookup_mod[t] for t in targets if t in lookup_mod)

        module_names = list(module_set)  # type: list[str]

    module_names = module_api.lookup_names(module_names)

    return targets, comm_type, module_names


def parse_scan_summary(summary: dict[str, Any]) -> TargetsType:
    """
    Extract targets, communication method, and PEAT modules from a scan summary.
    """

    if not summary:
        raise PeatError("Empty scan summary passed to parse_scan_summary()")

    module_names = summary.get("scan_modules", [])

    # Minor hack to make results from a sweep scan usable in a future scan
    if "scan_sweep" in module_names:
        config.SCAN_SWEEP = True
        module_names.remove("scan_sweep")

    comm_type = summary.get("scan_type", "")

    if not comm_type:
        raise PeatError("No 'scan_type' variable found in host file")

    if comm_type not in get_args(consts.AllowedCommTypes):
        raise PeatError(
            f"Unknown scan_type value '{comm_type}' in host file, expected "
            f"one of {get_args(consts.AllowedCommTypes)}"
        )

    if comm_type == "broadcast_ip" and not summary.get("hosts_verified"):
        targets = summary["scan_targets"]
    else:
        if summary.get("hosts_verified"):
            # If there were results from a broadcast IP scan, then use unicast IP
            # to the verified devices, since we now know their addresses.
            if comm_type == "broadcast_ip":
                comm_type = "unicast_ip"

            module_names = set()  # Use a set to prevent duplicates
            targets = []

            # Note: "hosts_verified" is a list of dict
            for dev in summary["hosts_verified"]:
                if dev.get("peat_module"):
                    module_names.add(dev["peat_module"])

                for comm_id in ["ip", "serial_port", "mac", "hostname"]:
                    if dev.get(comm_id):
                        targets.append(dev[comm_id])
                        break

            module_names = list(module_names)
        elif summary.get("hosts_online"):
            targets = summary["hosts_online"]
        else:
            targets = summary.get("scan_targets", [])

    return targets, comm_type, module_names


def read_host_file(host_file: Path | str) -> dict[str, Any] | None:
    """
    Parse a scan summary from a file or STDIN into a scan summary dict.
    """

    file = utils.check_file(host_file, ext=".json")

    if file is None:
        log.critical(f"Failed to parse host file '{str(host_file)}'")
        return None

    elif str(file) == "-":
        log.info("Parsing device information from standard input")
        return json.loads(str(sys.stdin.read()))

    else:
        file = Path(file)
        log.info(f"Parsing device information from file {file.name}")

        if file.suffix == ".json":
            with file.open(encoding="utf-8") as h_file:
                return json.load(h_file)
        else:
            log.error(
                f"Invalid file extension {file.suffix} for host "
                f"file {file.name}. Must be .json for scan results."
            )
            return None


def write_readme() -> bool:
    """
    Generate a README describing the output from PEAT.

    This file gets written in ``./peat_results/``
    (or whatever is configured for ``OUT_DIR``).

    Returns:
        If the file was written successfully (or if the file already exists)
    """

    readme_text = """
Process Extraction and Analysis Tool (PEAT).

Refer to the PEAT documentation for details on usage and any other information.
The documentation should've been provided to you via other channels.
If you don't have access to the documentation, please reach out to
your point of contact from which you acquired this release or any of
the contacts listed below.

If you have questions, feedback, find a bug, or have suggestions for
improvements, please get in touch!

PEAT team: peat@sandia.gov


# Output files and folders

## PEAT results directory (OUT_DIR)

By default, all PEAT runs are saved into `./peat_results/`, which is a
directory in the same directory you were in when running PEAT.


## Description of folders in output

- `devices/` : All data collected from OT devices and/or parsed out of files.
- `elastic_data/` : Copies of documents pushed to Elasticsearch. These can be used to rebuild the Elasticsearch data if you only have the files or don't have a Elasticsearch server available when running PEAT.
    - `mappings/` : Elasticsearch type mappings for the PEAT indices
- `heat_artifacts/` : Output from HEAT ("peat heat <args>")
- `logs/` : PEAT's log files, including the main log file, JSON-formatted log files, and protocol- and module-specific log files (e.g. Telnet logs, ENIP logs).
- `peat_metadata/` : JSON and YAML-formatted dumps of PEAT's configuration and internal state.
- `summaries/` : Summary results of a command, e.g. scan-summary, pull-summary, or parse-summary. These include metadata about the operation (e.g., how many files were parsed), as well as a combined set of device summaries (most of the data, but some fields are excluded, like events, memory, blobs, etc.). To view the complete results for devices, look in the "devices/" directory.
- `temp/` : Temporary files, used by PEAT during a run to put files temporarily before being moved elsewhere.


## Run directory (RUN_DIR)

Every time PEAT is run, a new sub-directory of `./peat_results/`
is created. This is the "run dir" or `RUN_DIR`.
The name of this directory is auto-generated, with the following format:
`<command>_<config-name>_<timestamp>_<run-id>`

- `<command>` : PEAT command, e.g. "scan", "pull", "parse", etc.
- `<config-name>` : name of YAML config file, set in `metadata: name: "name"`.
    If no config name is specified, then the string "default-config" is used.
- `<timestamp>` : start time of the PEAT run, e.g. `2022-06-15_13-08-59`.
- `<run-id>` : Run ID, aka `agent.id`, e.g. `165532013980`.

Run dir examples:

- pull_sceptre-test-config_2022-06-17_165532013980
- scan_default-config_2022-09-27_165532013980


## Output file structure

NOTE: the file structure below will differ if any of the `_DIR`
variables were configured, e.g. `OUT_DIR`, `ELASTIC_DIR` or `LOG_DIR`.

`...` represents "miscellaneous files".

```
./peat_results/
    README.md
    <command>_<config-name>_<timestamp>_<run_id>/
        devices/
            <device-id>/
                device-data-summary.json
                device-data-full.json
                ...
        elastic_data/
            mappings/
                ...
            ...
        heat_artifacts/
            ...
        logs/
            enip/
                ...
            elasticsearch.log
            debug-info.txt
            json-log.jsonl
            peat.log
            telnet.log
            ...
        peat_metadata/
            peat_configuration.yaml
            peat_configuration.json
            peat_state.json
        summaries/
            scan-summary.json
            pull-summary.json
            parse-summary.json
        temp/
            ...
```
    """.strip()  # noqa: E501

    readme_path = config.OUT_DIR / "README.md"

    if not readme_path.is_file():
        log.debug(f"Writing README to {readme_path.as_posix()}")
        return utils.write_file(readme_text, readme_path)

    return True

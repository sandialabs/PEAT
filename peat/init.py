import sys
from copy import deepcopy
from pathlib import Path
from pprint import pformat

from peat import (
    DeviceData,
    Elastic,
    PeatError,
    config,
    config_crypto,
    consts,
    datastore,
    exit_handler,
    log,
    module_api,
    protocols,
    state,
    utils,
)
from peat.data.default_options import DEFAULT_OPTIONS

from .log_utils import print_logo, setup_logging


def initialize_peat(conf: dict, entrypoint: consts.EntrypointType = "Package") -> None:
    """
    Various initialization steps for most PEAT use cases.

    .. note::
       If loading from the CLI, ``conf`` will contain the raw values of arguments,
       e.g. an argument that stores ``args.func`` would be in ``conf`` as
       ``conf["func"]``.

    Args:
        conf: Configuration values to set at runtime, if any
        entrypoint: How PEAT is being used. If you're using PEAT
            as a package/library, do NOT set this argument.
            Must be either "CLI" or "Package".
    """
    state.entrypoint = entrypoint

    # Convert top-level keys to lowercase. This makes it easier to use
    # this function directly from testing scripts or the REPL, e.g.
    # initialize_peat({"DEBUG": 1, "OUT_DIR": None})
    conf = consts.lower_dict(conf, children=False)

    # Minor hack to handle case where someone accidentally disables RUN_DIR
    # without disabling OUT_DIR as well, since they're mutually dependent.
    if (
        entrypoint == "Package"
        and "run_dir" in conf
        and conf["run_dir"] is None
        and "out_dir" not in conf
    ):
        conf["out_dir"] = None

    # If config file is specified, load those values
    # NOTE: non-None values in 'conf' will override any file values!
    try:
        if conf.get("config_file"):
            config_path = Path(conf["config_file"]).resolve()
            config.load_from_file(config_path)
    except AttributeError:
        # This is likely an encrypted config, check to see if it is and unencrypt
        # need to decrypt file then load yaml (safe_load) or json (load)
        decrypted_str = config_crypto.decrypt_config(config_path)
        if decrypted_str:
            decrypted_dict = config_crypto.convert_to_dict(decrypted_str)
            if decrypted_dict:
                config._load_values(decrypted_dict, load_to="file_configs")
        else:
            # If above failed, there is likely a problem with the config file
            log.error(
                "PEAT encountered an error while attempting to read config file, "
                "check to ensure your config file is formatted correctly "
                "and the filepath is valid"
            )
            sys.exit(1)

    # Load runtime configurations (CLI arguments, program-specified, etc.)
    # This magically populates Configuration options from same-named CLI arguments
    config.load_from_dict(conf)

    # Import third-party device modules
    # The module API handles lists of file paths already
    if config.ADDITIONAL_MODULES:
        config.ADDITIONAL_MODULES = [  # Save as absolute paths
            str(Path(x).resolve()) for x in config.ADDITIONAL_MODULES
        ]

        if not module_api.import_module(config.ADDITIONAL_MODULES):
            raise PeatError(
                f"No additional device modules were valid. "
                f"Module paths: {config.ADDITIONAL_MODULES}"
            )

    # Minor hack to make "--list-modules" work with minimal fuss
    for list_arg in [
        "list_all",
        "list_modules",
        "list_aliases",
        "list_alias_mappings",
        "examples",
        "all_examples",
        "list_heat_protocols",
    ]:
        if conf.get(list_arg):
            return

    # Hack to configure output directories
    if conf.get("out_dir"):
        config.fixup_dirs(config.OUT_DIR, "OUT_DIR", override_all=True)
    elif entrypoint == "Package" and "out_dir" in conf and conf["out_dir"] is None:
        config.OUT_DIR = None
        config.fixup_dirs(None, "OUT_DIR", override_all=True)

    # Set RUN_DIR if manually configured
    if conf.get("run_dir") and "default_run_dir" not in conf["run_dir"]:
        config.fixup_dirs(config.RUN_DIR, "RUN_DIR", override_all=True)
    elif entrypoint == "Package" and "run_dir" in conf and conf["run_dir"] is None:
        config.RUN_DIR = None
        config.fixup_dirs(None, "RUN_DIR", override_all=True)

    # Auto-generate RUN_DIR if not manually configured
    if config.OUT_DIR and (
        not conf.get("run_dir") or "default_run_dir" in conf.get("run_dir", "")
    ):
        # If --run-name is set, use that value for the run name
        if conf.get("run_name"):
            run_name = conf["run_name"]
        else:
            config_name = "default-config"
            if config.METADATA.get("name"):
                config_name = config.METADATA["name"]
            elif conf.get("config_file"):
                # if there's no metadata, fallback to using config file name
                # for example, for a file "peat-config.yaml", config name would
                # be "peat-config".
                config_name = Path(conf["config_file"]).stem

            cmd_name = "unknown-command"
            if conf.get("func"):
                cmd_name = conf["func"]

            # Format: <command>_<config-name>_<timestamp>_<run-id>
            run_name = f"{cmd_name}_{config_name}_{consts.START_TIME}_{consts.RUN_ID}"

        config.RUN_DIR = config.OUT_DIR / run_name
        config.fixup_dirs(config.RUN_DIR, "RUN_DIR", override_all=True)

    # Fancy startup logo, printed to stderr
    if state.entrypoint == "CLI" and not (config.QUIET or config.NO_LOGO):
        print_logo()

    # Configure logging across PEAT (globally)
    log_file = None
    json_file = None
    debug_info_file = None
    if config.LOG_DIR:
        log_file = config.LOG_DIR / "peat.log"
        json_file = config.LOG_DIR / "json-log.jsonl"
        debug_info_file = config.LOG_DIR / "debug-info.txt"

    setup_logging(
        file=log_file,
        json_file=json_file,
        debug_info_file=debug_info_file,
    )

    # Copy original config file
    if conf.get("config_file") and config.META_DIR:
        config_path = Path(conf["config_file"]).resolve()
        utils.copy_file(config_path, config.META_DIR / config_path.name)

    # Output messages to user now that logging is configured
    config_name = ""
    if config.METADATA.get("name"):
        config_name = f"'{config.METADATA['name']}' "
    if conf.get("config_file"):  # Log so the user sees config was loaded
        log.info(f"Configuration {config_name}loaded from '{conf['config_file']}'")

    if config.RUN_DIR:
        log.info(f"Run directory: {config.RUN_DIR.name}")

    if config.DEBUG:
        log.warning(f"Debugging mode is ENABLED. DEBUG level: {config.DEBUG}")
        log.debug(f"Running using Python {consts.SYSINFO['python_version']}")

    if config.DRY_RUN:
        log.warning(
            "Dry run mode is enabled! Actions won't be executed, but logs and "
            "state will still be written to files and saved to Elasticsearch "
            "(if enabled)."
        )

    if (
        not state.peat_initialized
        and not entrypoint == "Package"
        and (
            conf.get("func", "") not in ["parse", "pillage"]  # Skip passive
            and not conf.get("ports")  # Skip serial
        )
    ):
        # Suggest user run as Administrator on Windows
        if consts.WINDOWS and not state.raw_socket_capable:
            log.warning(
                "PEAT is unable to use RAW sockets, which may impact "
                "scanning performance. To fix this, re-run PEAT from "
                "an Administrator-level command prompt (right click -> "
                "'Run as Administrator')"
            )

        # Check if default interface is promiscuous (e.g Netmeld didn't reset it)
        if consts.POSIX and protocols.is_promiscuous(state.default_interface_name):
            log.warning(
                f"Default interface '{state.default_interface_name}' is "
                f"in promiscuous mode, this may cause the run to fail."
            )
            # TODO: check the default(s) for the specified hosts

        if not consts.WINDOWS and not consts.SYSINFO["tcpdump"]:
            if state.raw_socket_capable:
                log.warning(
                    "RAW sockets are available, however tcpdump is not installed. "
                    "You may run into issues during host discovery. If so, "
                    "try re-running peat with '--assume-online'."
                )
            else:
                log.warning("tcpdump is not installed, your mileage may vary")

    # Add serial baudrates to the global options if doing serial operations
    if (conf.get("ports") or conf.get("port_list")) and conf.get("baudrates"):
        baudrates = protocols.parse_baudrates(conf["baudrates"])
        datastore.global_options["baudrates"] = baudrates

    # Set the global timeout if user sets it
    if conf.get("default_timeout"):
        datastore.global_options["timeout"] = conf["default_timeout"]
        # !! hack to inject default timeout to individual protocols !!
        for v in DEFAULT_OPTIONS.values():
            if isinstance(v, dict) and "timeout" in v:
                v["timeout"] = conf["default_timeout"]

    # Load global configuration options that are applied to all devices
    if config.DEVICE_OPTIONS:
        # NOTE: do these minor hacks before updating global options so we don't override CLI args
        if config.DEVICE_OPTIONS.get("baudrates") and not datastore.global_options.get(
            "baudrates"
        ):
            baudrates = protocols.parse_baudrates(config.DEVICE_OPTIONS["baudrates"])
            datastore.global_options["baudrates"] = baudrates

        if config.DEVICE_OPTIONS.get("timeout") and not datastore.global_options.get("timeout"):
            # !! hack to inject default timeout to individual protocols !!
            for v in DEFAULT_OPTIONS.values():
                if isinstance(v, dict) and "timeout" in v:
                    v["timeout"] = config.DEVICE_OPTIONS["timeout"]

        datastore.global_options.update(config.DEVICE_OPTIONS)

    # Load host-specific options
    if config.HOSTS:
        for host in config.HOSTS:
            # Set identifying attributes, e.g. data.ip, data.mac, etc.
            opt_dev = DeviceData(**host["identifiers"])

            # Apply options specific to this host
            if host.get("options"):
                opt_dev._host_option_overrides.update(deepcopy(host["options"]))

            if host.get("peat_module"):
                opt_dev._module = module_api.get_module(host["peat_module"])

            datastore.objects.append(opt_dev)

    # Save the current state and configuration to files upon termination.
    # This won't happen if running as a library/Python package.
    if state.entrypoint == "CLI":

        def _save_on_exit():
            if config.META_DIR:
                config.save_to_file(outdir=config.META_DIR, save_json=False)
                state.save_to_file(outdir=config.META_DIR, save_json=False)

        exit_handler.register(_save_on_exit, "FILE")

    # Configure Elasticsearch. If a server is specified,
    # create an Elastic instance and attempt to connect.
    # If elastic server in conf, and elastic already initialized,
    # only reconnect if the server URL is different.
    if (config.ELASTIC_SERVER and not state.elastic) or (
        conf.get("elastic_server")
        and state.elastic
        and conf["elastic_server"] not in state.elastic.unsafe_url
    ):
        try:
            # NOTE: don't log ELASTIC_SERVER value as it may have sensitive login creds
            log.trace2("Setting up global Elastic instance...")
            elastic = Elastic(config.ELASTIC_SERVER)
            elastic.ping()  # Force the connection to be created
        except Exception as ex:
            log.error(
                f"Failed to initialize Elasticsearch/OpenSearch. Data "
                f"from this run will not be pushed to the database. "
                f"Exception: {ex}"
            )
        else:
            if config.ELASTIC_DISABLE_DATED_INDICES:
                log.warning(
                    "Dated index names are disabled, data will be pushed "
                    "to plain index names without a date appended"
                )

            if state.elastic:
                state.elastic.disconnect()

            state.elastic = elastic  # Set the global Elastic instance

    # Record the fact that timezone data may be wonky
    try:
        import tzlocal  # noqa: F401
    except Exception:
        log.warning("Failed to import 'tzlocal'. Timezone names will be non-standard.")

    # Initialize value of state.superuser_privs
    if not state.peat_initialized:
        utils.are_we_superuser()
        if state.superuser_privs:
            log.warning(
                "PEAT is running with superuser privileges (root or "
                "Administrator). This means we can use raw sockets and "
                "do more serial stuff. Just a friendly heads up :)"
            )

        if config.NO_PRINT_RESULTS:
            log.error(
                "The '-Q' argument (--no-print-results) and 'no_print_results' setting "
                "is deprecated, and will be "
                "removed in a future version of PEAT. It's old behavior is now the "
                "default, results are no longer printed by default. If you need to "
                "explicitly enable output, use --print-results. This is not an error, "
                "but leaving the arg enabled will cause your commands to no longer "
                "work in a future release (probably in 2025)."
            )

    # Log the arguments for debugging
    log.trace4(f"initialize_peat conf\n{pformat(conf, indent=4)}\n")
    log.trace2(f"global_options\n{pformat(datastore.global_options, indent=4)}")

    state.peat_initialized = True

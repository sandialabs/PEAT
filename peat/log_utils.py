from __future__ import annotations

import json
import logging
import os
import sys
from datetime import UTC
from pathlib import Path
from pprint import pformat
from traceback import format_tb

import loguru
from loguru import logger

from peat import (
    DEBUG_LEVELS,
    Elastic,
    PeatError,
    __version__,
    config,
    consts,
    state,
    utils,
)


class ElasticLogSink:
    def __init__(self, server_url: str, index: str = "vedar-logs") -> None:
        """
        Special logging sink for exporting logs to Elasticsearch.

        Args:
            server_url: Elasticsearch host to connect to, including credentials
            index: Name (prefix) of the elasticsearch index to log to. Date
                will be added in format ``<name>-<YYYY>.<MM>.<DD>``.

        Raises:
            PeatError: Failure to initialize the handler
        """
        self.index = index
        logger.info(
            f"Connecting to Elasticsearch or OpenSearch for logging (index basename: {index})"
        )

        try:
            self.es = Elastic(server_url)
            self.es.ping()
        except Exception as ex:
            if self.es:
                self.es.disconnect()
            raise PeatError(
                f"Failed to connect to Elasticsearch server '{self.es.safe_url}' for logging: {ex}"
            ) from None

    def emit(self, message: loguru.Message) -> None:
        self.es.push(
            index=self.index,
            content=json.loads(message.record["extra"]["json_log_string"]),
        )


def generate_log_dict(record: loguru.Record) -> dict[str, dict | str | None]:
    """
    Generate a dict with detailed metadata about the log event, for use in
    Elasticsearch and in JSON-formatted logs.

    This information gets used in record["extra"]["json_log_string"]
    """

    # Limit "message" field to 80 character length
    message_field = record["message"]
    if len(record["message"]) > 80:
        message_field = f"{record['message'][:77]}..."

    content = {
        "@timestamp": Elastic.convert_tstamp(record["time"].astimezone(UTC)),
        "message": message_field,
        "event": {
            "dataset": "peat",
            "kind": "event",
            "original": record["message"],
            "provider": "peat",
            "severity": record["level"].no,
        },
        "log": {
            "level": record["level"].name,
            "logger": record["name"],
            "origin": {
                "function": record["function"],
                "file": {
                    "line": record["line"],
                    "name": record["file"].name,
                },
            },
        },
        # Metadata about this PEAT instance (the "observer")
        "observer": {
            "geo": {"timezone": consts.TIMEZONE},
            "hostname": consts.SYSINFO["hostname"],
            "interface": {"name": state.local_interface_names},
            "ip": state.local_interface_ips,
            "mac": state.local_interface_macs,
            "os": {
                "family": consts.SYSINFO["os_family"],
                "full": consts.SYSINFO["os_full"],
                "name": consts.SYSINFO["os_name"],
                "version": consts.SYSINFO["os_ver"],
            },
            "user": {
                "name": consts.SYSINFO["username"],
            },
        },
        "peat": {
            "containerized": consts.SYSINFO["containerized"],
            "debug_level": config.DEBUG,
            "entrypoint": state.entrypoint,
            "podman": consts.SYSINFO["podman"],
            "python_version": consts.SYSINFO["python_version"],
        },
        "process": {
            "args_count": len(sys.argv),
            "executable": consts.SYSINFO["python_exe"],
            "name": record["process"].name,
            "parent": {
                "process": {
                    # NOTE: pid may not be accurate if the log message
                    # came from a sub-process, but in most cases it's
                    # correct, and useful for associating when looking
                    # at data in top/htop or from Metricbeat.
                    "pid": consts.SYSINFO["ppid"]
                }
            },
            "pid": record["process"].id,
            "start": Elastic.convert_tstamp(consts.START_TIME_UTC),
            "thread": {
                "id": record["thread"].id,
                "name": record["thread"].name,
            },
            "working_directory": Path.cwd().as_posix(),
        },
        "tags": ["log", "peat"],
    }

    # Don't store CLI args if being used in third-party code
    # to avoid leaking sensitive arguments e.g. credentials
    if state.entrypoint == "CLI":
        content["process"]["args"] = list(sys.argv)
        content["process"]["command_line"] = " ".join(sys.argv)

    # Record data from exceptions in error.{type,message,stack_trace} fields
    if record["exception"]:
        content["error"] = {
            "type": record["exception"].type.__name__,
            "message": str(record["exception"].value),
            "stack_trace": "".join(format_tb(record["exception"].traceback)),
        }

    return content


def terminal_formatter(record: loguru.Record) -> str:
    # Per the CLIG:
    #   "Don't treat stderr like a log file, at least not by default.
    #   Don't print log level labels (ERR, WARN, etc.) or extraneous
    #   contextual information, unless in verbose mode."
    fmt = "<green>{time:HH:mm:ss.SSS}</green> | "

    # Don't bother with the level. While the colors communicate this,
    # users don't care about levels below WARNING, which is why later
    # on in this function we prepend the text of the level to the message.
    # A lot of users are colorblind or can't see colors. Colors are a
    # "nice to have", but should NOT be used as sole means of communicating
    # information (e.g. importance).
    if "peat_module" in record["extra"]:
        fmt += "{extra[peat_module]: <9} | "
    elif config.VERBOSE and "classname" in record["extra"]:
        fmt += "{extra[classname]: <9} | "
    elif config.VERBOSE:
        fmt += "{module: <9} | "

    if "target" in record["extra"]:
        fmt += "<bold>{extra[target]: <12}</bold> | "

    if record["level"].name in ["WARNING", "ERROR", "CRITICAL"]:
        fmt += "<level>{level}: {message}\n{exception}</level>"
    else:
        fmt += "<level>{message}\n{exception}</level>"

    return fmt


def file_formatter(record: loguru.Record) -> str:
    # file message format:
    # - Timestamp includes date (y/m/d) and millisecond
    # - Timestamp is in UTC timezone
    # - Includes more info about the source module, function, and line
    # - No colors
    fmt = "{time:YYYY-MM-DD HH:mm:ss.SSS!UTC} | {level: <7} | "

    if "classname" in record["extra"]:
        fmt += "{name}.{extra[classname]} -> {function}:{line} | "
    else:
        fmt += "{name} -> {function}:{line} | "

    if "target" in record["extra"]:
        fmt += "Target: {extra[target]} | "

    fmt += "{message}\n{exception}"
    return fmt


def use_colors() -> bool:
    """
    If colorized terminal output should be used.

    Disable colored terminal output if ``NO_COLOR`` environment variable
    is set, per the Command Line Interface Guidelines (CLIG).

    - https://clig.dev/#output
    - https://no-color.org/

    ``config.NO_COLOR`` is True if user has disabled via:

    - CLI arg ``--no-color``
    - YAML config ``no_color: true``
    - Environment variable ``PEAT_NO_COLOR``
    """
    return not (
        config.NO_COLOR or os.environ.get("NO_COLOR") or os.environ.get("TERM", "") == "dumb"
    )


def patch_json_string(record: loguru.Record) -> None:
    # NOTE: if we need to read values out of this, just use json.loads(...)
    record["extra"]["json_log_string"] = json.dumps(
        generate_log_dict(record), separators=(",", ":")
    )


def setup_logging(
    file: Path | None = None,
    json_file: Path | None = None,
    debug_info_file: Path | None = None,
) -> None:
    """
    Configures the logging interface used by everything for output.
    The third-party package ``loguru`` is used for logging.

    Verbosity can be configured via ``config.VERBOSE``.
    Terminal output can be disabled via ``config.QUIET``.

    Args:
        file: File path to write human-readable logs. If a :class:`~pathlib.Path`
            object is provided, it is used as an absolute path. If :obj:`None`,
            standard log file output will be disabled.
        json_file: Store JSON formatted logs to a file, in JSON Lines (jsonl) format.
            These share the same format as Elasticsearch logging, and can be used to
            reconstruct the ``vedar-logs`` Elasticsearch index. If :obj:`None`,
            JSON logging will be disabled.
        debug_info_file: Text file with system info, configuration values,
            dumps of scapy internal state, and other info that may be helpful
            for debugging or troubleshooting customer issues.
    """
    logger.remove()  # Remove default sink(s)

    # !! TODO: ensure duplicate sinks are not added !!

    # TODO: only add this if doing json file or elastic output?
    # One nice effect of this is the JSON dict is only generated once if
    # JSON file and Elasticsearch output is enabled, reducing overhead.
    logger.configure(
        patcher=patch_json_string,
    )

    # What level sinks should handle, based on configured DEBUG level
    log_level = DEBUG_LEVELS.get(config.DEBUG, "TRACE4")

    # terminal output sink (to stderr)
    # If QUIET is set, don't log to stderr
    if not config.QUIET:
        logger.add(
            sink=sys.stderr,
            level="INFO" if not config.VERBOSE else log_level,  # TODO: SUCCESS?
            format=terminal_formatter,
            colorize=use_colors(),
            backtrace=bool(config.VERBOSE or config.DEBUG),
            diagnose=bool(config.DEBUG),  # TODO
            enqueue=True,  # multiprocessing
            filter=lambda r: (
                not r["extra"].get("es_logger") and not r["extra"].get("is_telnetlib")
            ),
        )

    # log file sink, human-readable log file
    if file:
        log_path = Path(os.path.realpath(os.path.expanduser(file)))
        logger.add(
            sink=log_path,
            level=log_level,
            format=file_formatter,
            colorize=False,
            backtrace=True,
            diagnose=bool(config.DEBUG),
            catch=True,
            enqueue=True,  # multiprocessing
            filter=lambda r: (
                not r["extra"].get("es_logger") and not r["extra"].get("is_telnetlib")
            ),
        )
        state.written_files.add(log_path.as_posix())
        logger.info(f"Log file: {utils.short_pth_str(log_path)}")

    # JSON-formatted logs (for rebuilding the vedar-logs Elasticsearch index)
    # https://betterstack.com/community/guides/logging/loguru/
    if json_file:
        json_path = Path(os.path.realpath(os.path.expanduser(json_file)))
        logger.add(
            sink=json_path,
            level=log_level,
            # lambda to prevent loguru appending exception to message string
            format=lambda x: "{extra[json_log_string]}\n",  # noqa: ARG005
            colorize=False,
            backtrace=False,
            diagnose=False,
            catch=True,
            enqueue=True,  # multiprocessing
            filter=lambda r: (
                not r["extra"].get("es_logger") and not r["extra"].get("is_telnetlib")
            ),
        )
        state.written_files.add(json_path.as_posix())
        logger.trace(f"JSON Log file: {utils.short_pth_str(json_path)}")

    # telnetlib-fork log file
    #
    # telnetlib's logging output is useful, but excessive.
    # If log file output is enabled, write Telnet protocol messages to a
    # separate file. We do this even if debugging isn't enabled since.
    #
    # Note: since there is a log of logging logic that would otherwise
    # have to be jammed into the telnetlib class, we put logic here.
    if config.LOG_DIR:
        tn_path = config.LOG_DIR / "telnet.log"
        logger.add(
            sink=tn_path,
            level="TRACE4",
            format=file_formatter,
            colorize=False,
            backtrace=False,
            diagnose=False,
            catch=True,
            enqueue=True,  # multiprocessing
            filter=lambda r: bool(r["extra"].get("is_telnetlib")),
        )
        state.written_files.add(tn_path.as_posix())
        logger.debug(f"Telnet debug log: {utils.short_pth_str(tn_path)}")

    # set color for INFO-level messages
    logger.level(
        "INFO", color="<light-green><bold>"
    )  # TODO: remove bold from INFO, only use for SUCCESS?
    logger.level("SUCCESS", color="<light-green><bold>")
    logger.level("DEBUG", color="<white>")
    logger.level("TRACE", color="<white>")

    # debug info file
    # File with metadata about the system and dumps of scapy's internal state
    if debug_info_file:
        df = Path(os.path.realpath(os.path.expanduser(debug_info_file)))
        if not df.parent.exists():
            df.parent.mkdir(parents=True, exist_ok=True)

        info = ""
        info += utils.get_formatted_platform_str()  # platform info
        info += utils.get_debug_string()  # debugging info

        # Dump scapy's internal state
        if config.DEBUG:
            from scapy.all import conf as scapy_conf

            info += f"\n\n*** scapy.conf str() ***\n\n{str(scapy_conf)}\n"
            info += f"\n\n*** scapy.conf formatted ***\n\n{pformat(scapy_conf.__dict__)}\n"

        # Raw config dump only when debugging internals
        if config.DEBUG >= 3:
            info += (
                f"\n\n** raw config dump ***\n\n{json.dumps(consts.convert(config), indent=2)}\n"
            )

        df.write_text(info, encoding="utf-8")
        state.written_files.add(df.as_posix())

    # Suppress logging messages from various third-party modules
    for name in ["urllib3", "elasticsearch", "requests"]:
        if config.DEBUG:
            logging.getLogger(name).setLevel(logging.WARNING)
        else:
            logging.getLogger(name).setLevel(logging.ERROR)

    # https://github.com/secdev/scapy/blob/master/scapy/error.py
    for name in ["scapy", "scapy.runtime", "scapy.loading", "scapy.interactive"]:
        scapy_level = logging.ERROR
        if config.DEBUG == 1:
            scapy_level = logging.WARNING
        elif config.DEBUG == 2:
            scapy_level = logging.INFO
        elif config.DEBUG >= 3:
            scapy_level = logging.DEBUG
        logging.getLogger(name).setLevel(scapy_level)

    # Configure logging to Elasticsearch
    if config.ELASTIC_SERVER and config.ELASTIC_SAVE_LOGS:
        # TODO: add as handler for:
        #   logging.getLogger("elasticsearch"),
        #   logging.getLogger("urllib3"),
        if config.LOG_DIR:
            es_lp = config.LOG_DIR / "elasticsearch.log"
            logger.add(
                sink=es_lp,
                level=log_level,
                format=file_formatter,
                colorize=False,
                backtrace=True,
                catch=True,
                enqueue=True,  # multiprocessing
                filter=lambda r: bool(r["extra"].get("es_logger")),
            )
            state.written_files.add(es_lp.as_posix())

        es_handler = ElasticLogSink(
            server_url=config.ELASTIC_SERVER,
            index=config.ELASTIC_LOG_INDEX,
        )

        logger.add(
            sink=es_handler.emit,
            level=log_level,
            colorize=False,
            backtrace=False,
            diagnose=False,
            catch=True,
            enqueue=True,
            filter=lambda r: not r["extra"].get("es_logger"),
        )


def print_logo() -> None:
    """
    Print the logo and Run ID to stderr, colorized if colors are enabled.
    """

    if use_colors():
        logo_str = (
            f"{consts.LOGO}\n\033[34m\033[1mPEAT {__version__}\33[0m\n"
            f"\033[34m\033[1mRun ID (agent.id): {consts.RUN_ID}\33[0m\n"
        )
    else:
        logo_str = (
            f"{consts.NO_COLOR_LOGO}\nPEAT {__version__}\nRun ID (agent.id): {consts.RUN_ID}\n"
        )

    print(logo_str, file=sys.stderr, flush=True)  # noqa: T201


__all__ = ["ElasticLogSink", "print_logo", "setup_logging", "use_colors"]

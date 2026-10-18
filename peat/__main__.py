#!/usr/bin/env python3

import sys
import timeit

# Sample here to capture how long the imports take
START_TIME = timeit.default_timer()

from peat import __version__, cli_args, cli_main, consts  # noqa: E402


def _fix_windows_console_encoding() -> None:
    """
    Prevent crashes when printing characters the console can't encode on Windows.

    When output is redirected to a file or pipe on Windows (e.g. ``peat.exe ... > out.txt``),
    Python uses the legacy code page (usually cp1252), and printing data from a device
    with characters outside of that code page raises :class:`UnicodeEncodeError`.
    Escape those characters instead of crashing.
    """
    if not consts.WINDOWS:
        return

    for stream in (sys.stdout, sys.stderr):
        if stream is not None and hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(errors="backslashreplace")
            except Exception:
                pass


def main():
    """Command line entry point for PEAT."""
    _fix_windows_console_encoding()
    try:
        args = cli_args.parse_peat_arguments(__version__)
        args_dict: dict = vars(args)  # Convert argparse Namespace object to a dict
        cli_main.run_peat(args_dict, START_TIME)
    except KeyboardInterrupt:
        print(  # noqa: T201
            "\n** USER TERMINATED EXECUTION **", file=sys.stderr, flush=True
        )
        sys.exit(1)


if __name__ == "__main__":
    main()

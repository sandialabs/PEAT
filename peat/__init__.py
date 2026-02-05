import logging
import inspect
from typing import Union
import warnings
from functools import partialmethod

from loguru import logger as log  # convenience

# reset loguru's pre-configured handlers
log.remove()

# Add custom logging levels
# NOTE: loguru's built-in "TRACE" level is level 5
# NOTE: guard to prevent re-initialization of loggers
if not hasattr(log.__class__, "trace2"):
    TRACE2 = log.level(name="TRACE2", no=4, color="<white>")
    TRACE3 = log.level(name="TRACE3", no=3, color="<white>")
    TRACE4 = log.level(name="TRACE4", no=2, color="<white>")

    # Add helper functions for custom logging levels
    # Per: https://loguru.readthedocs.io/en/stable/resources/recipes.html
    log.__class__.trace2 = partialmethod(log.__class__.log, TRACE2.name)
    log.__class__.trace3 = partialmethod(log.__class__.log, TRACE3.name)
    log.__class__.trace4 = partialmethod(log.__class__.log, TRACE4.name)
else:
    TRACE2 = log.level(name="TRACE2")
    TRACE3 = log.level(name="TRACE3")
    TRACE4 = log.level(name="TRACE4")

DEBUG_LEVELS = {
    0: "DEBUG",
    1: "TRACE",
    2: "TRACE2",
    3: "TRACE3",
    4: "TRACE4",
}


# Capture warnings that modules and Python use (e.g. deprecation warnings)
# Replaces "logging.captureWarnings(True)""
showwarning_ = warnings.showwarning

def showwarning(message, *args, **kwargs):
    log.warning(message)
    showwarning_(message, *args, **kwargs)

warnings.showwarning = showwarning


class InterceptHandler(logging.Handler):
    def emit(self, record: logging.LogRecord) -> None:
        # Get corresponding Loguru level if it exists.
        level: str | int
        try:
            level = log.level(record.levelname).name
        except ValueError:
            level = record.levelno

        # Find caller from where originated the logged message.
        frame, depth = inspect.currentframe(), 0
        while frame and (depth == 0 or frame.f_code.co_filename == logging.__file__):
            frame = frame.f_back
            depth += 1

        log.opt(depth=depth, exception=record.exc_info).log(level, record.getMessage())


# NOTE (cegoes, 12/12/2022): suppresses libpcap warning when running on a Windows
# system without libpcap installed, which breaks --quiet output.
for logger_name in [
    "scapy",
    "scapy.runtime",
    "scapy.loading",
    "scapy.interactive",
    "urllib3",
    "requests",
    "elasticsearch",
]:
    tp_logger = logging.getLogger(logger_name)

    # Set at error level for now. When peat.log_utils.setup_logging() is called,
    # these levels will be changed.
    tp_logger.setLevel(logging.ERROR)

    # Add the intercept handler.
    # NOTE: if some other code that's using peat has also mutated the handlers
    # for these loggers, then peat will over-write them.
    tp_logger.handlers = [InterceptHandler()]

from importlib.metadata import version as importlib_get_version
RAW_PEAT_VERSION = importlib_get_version("PEAT")
__version__ = RAW_PEAT_VERSION.split(".dev")[0]

from . import consts
from .consts import CommError, DeviceError, ParseError, PeatError
from .settings import config, state
from .elastic import Elastic
from .data import *
from .api.identify_methods import IdentifyMethod, IPMethod, SerialMethod
from .device import DeviceModule
from .modules import *
from .module_manager import module_api
from .init import setup_logging, initialize_peat
from .api.scan_api import scan
from .api.parse_api import parse
from .api.pillage_api import pillage
from .api.pull_api import pull
from .api.push_api import push
from .api.heat_api import heat_main
from .api.config_builder_api import generate_simple_config, generate_full_config
from .api.crypto_api import encrypt, decrypt

from .ftp_extractor import FTPExtractor
from .heat_classes import HeatProtocol
from .telnet_extractor import TelnetExtractor
from .umas_extractor import UmasExtractor

HEAT_EXTRACTORS: list[type[HeatProtocol]] = [
    UmasExtractor,
    FTPExtractor,
    TelnetExtractor,
]

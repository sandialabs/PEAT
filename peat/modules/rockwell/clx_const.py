"""
Constants for the ControlLogix ("clx") and other Rockwell devices.
"""

from typing import Final

LOGIC_LANGUAGE: Final[dict[str, int]] = {
    "Relay Ladder": 0x07FF,  # 2047
    "Structured Text": 0x07FC,  # 2044
    "Sequential Function Chart": 0x1FFE,  # 8190
    "Function Block Diagram": 0x07FD,  # 2045
}

LOGIC_LANGUAGE_BY_INT: Final[dict[int, str]] = {v: k for k, v in LOGIC_LANGUAGE.items()}

LANG_RLL: Final[int] = LOGIC_LANGUAGE["Relay Ladder"]
LANG_STL: Final[int] = LOGIC_LANGUAGE["Structured Text"]
LANG_SFC: Final[int] = LOGIC_LANGUAGE["Sequential Function Chart"]
LANG_FBD: Final[int] = LOGIC_LANGUAGE["Function Block Diagram"]

# TODO: properly figure these out using Electronic Data Sheet (EDS) files
# What the code means can vary by device
# For example, product code 11 can mean 1756-IB16/A (prod type 7, digital I/O)
# or PLC-5/20C (prod type 14, PLC).
# The proper implementation of this lookup would take product type
# and product code into account (and potentially major/min revision).
#
# AB_PRODUCT_TABLE: dict[int, str] = {
#     1: "1756-IF6I/A",            # 0x01
#     11: "1756-IB16/A",           # 0x0B
#     12: "1756-IB32/B DCIN",      # 0x0C
#     30: "1756-OW16I/A",          # 0x1E
#     58: "1756-ENBT/A",           # 0x3A
#     95: "1756-L74/B LOGIX5574",  # 0x5F
#     125: "1756-EWEB",            # 0x7D
#     164: "1756-L81E/B",          # 0xA4
#     166: "1756-EN2T/D",          # 0xA6
#     185: "Micrologix",           # 0xB9
#     200: "1756-EN2TR/C",         # 0xC8
# }

CLX_PRODUCT_CODES: Final[tuple] = (
    1,  # 1756-IF6I/A
    6,  # 1756-IF16/A
    8,  # 1756-OB16I/A DCOUT ISOL
    10,
    11,  # 1756-IB16/A
    12,  # 1756-IB32/B DCIN
    30,  # 1756-OW16I/A
    58,  # 1756-ENBT/A
    95,  # 1756-L74/B LOGIX5574
    115,  # 1756-OF8H/A HART Analog Out
    125,  # 1756-EWEB
    164,  # 1756-L81E/B
    166,  # 1756-EN2T/D
    200,  # 1756-EN2TR/C
    258,  # 1756-EN4TR/A
)

MLX_PRODUCT_CODES: Final[tuple] = (
    # MicroLogix 1400 PLC
    # NOTE: this can also be 1794-AENT FLEX I/O Ethernet Adapter
    90,
    # MicroLogix 1100 PLC
    185,
)

PANELVIEW_PRODUCT_CODES: Final[tuple] = (183,)  # PanelView Plus 7 Standard 700


def get_brand(product_code: int) -> str:
    """
    Determine brand of the device using a product code.
    """
    if product_code in CLX_PRODUCT_CODES:
        return "ControlLogix"
    elif product_code in MLX_PRODUCT_CODES:
        return "MicroLogix"
    elif product_code in PANELVIEW_PRODUCT_CODES:
        return "PanelView"
    else:
        return "Unknown brand (refer to product_name)"

from typing import Final

PCCC_DATA_TYPE: Final[dict[str, bytes]] = {
    "N": b"\x89",
    "B": b"\x85",
    "T": b"\x86",
    "C": b"\x87",
    "S": b"\x84",
    "F": b"\x8a",
    "ST": b"\x8d",
    "A": b"\x8e",
    "R": b"\x88",
    "O": b"\x8b",
    "I": b"\x8c",
}

PCCC_DATA_SIZE: Final[dict[str, int]] = {
    "N": 2,
    "B": 2,
    "T": 6,
    "C": 6,
    "S": 2,
    "F": 4,
    "ST": 84,
    "A": 2,
    "R": 6,
    "O": 2,
    "I": 2,
}

PCCC_CT: Final[dict[str, int]] = {
    "PRE": 1,
    "ACC": 2,
    "EN": 15,
    "TT": 14,
    "DN": 13,
    "CU": 15,
    "CD": 14,
    "OV": 12,
    "UN": 11,
    "UA": 10,
}

PCCC_ERROR_CODE: Final[dict[int, str]] = {
    -2: "Not Acknowledged (NAK)",
    -3: "No Response, Check COM Settings",
    -4: "Unknown Message from DataLink Layer",
    -5: "Invalid Address",
    -6: "Could Not Open Com Port",
    -7: "No data specified to data link layer",
    -8: "No data returned from PLC",
    -20: "No Data Returned",
    16: "Illegal Command or Format, Address may not exist or not enough elements in data file",
    32: "PLC Has a Problem and Will Not Communicate",
    48: "Remote Node Host is Missing, Disconnected, or Shut Down",
    64: "Host Could Not Complete Function Due To Hardware Fault",
    80: "Addressing problem or Memory Protect Rungs",
    96: "Function not allows due to command protection selection",
    112: "Processor is in Program mode",
    128: "Compatibility mode file missing or communication zone problem",
    144: "Remote node cannot buffer command",
    240: "Error code in EXT STS Byte",
}

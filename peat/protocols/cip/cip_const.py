"""
Constants for the Common Industrial Protocol (CIP).

Sources for various constants

- Allen-Bradley documentation
- github.com/ruscito/pycomm
- github.com/wireshark/wireshark/epan/dissectors/packet-cip.c
- github.com/dark-lbp/isf
- github.com/dmroeder/pylogix
"""

# TODO: use enums or dataclasses instead of dicts

from typing import Final

SUCCESS: Final[int] = 0
CIP_PORT: Final[int] = 44818

ELEMENT_ID: Final[dict[str, bytes]] = {
    "8-bit": b"\x28",
    "16-bit": b"\x29",
    "32-bit": b"\x2a",
}

CLASS_ID: Final[dict[str, bytes]] = {
    "8-bit": b"\x20",
    "16-bit": b"\x21",
}

INSTANCE_ID: Final[dict[str, bytes]] = {
    "8-bit": b"\x24",
    "16-bit": b"\x25",
}

ATTRIBUTE_ID: Final[dict[str, bytes]] = {
    "8-bit": b"\x30",
    "16-bit": b"\x31",
}

# Path are combined as:
# CLASS_ID + PATHS
# For example PCCC path is CLASS_ID["8-bit"]+PATH["PCCC"] -> 0x20, 0x67, 0x24, 0x01.
PATH: Final[dict[str, bytes]] = {
    "Connection Manager": b"\x06\x24\x01",
    "Router": b"\x02\x24\x01",
    "Backplane Data Type": b"\x66\x24\x01",
    "PCCC": b"\x67\x24\x01",
    "DHCP Channel A": b"\xa6\x24\x01\x01\x2c\x01",
    "DHCP Channel B": b"\xa6\x24\x01\x02\x2c\x01",
}


# When a tag is created, an instance of the Symbol Object (Class ID 0x6B) is created
# inside the controller.
#
# When a UDT is created, an instance of the Template object (Class ID 0x6C) is
# created to hold information about the structure makeup.
CLASS_CODE: Final[dict[str, int]] = {
    "Message Router": 0x02,  # Volume 1: 5-1
    "Symbol Object": 0x6B,
    "Template Object": 0x6C,
    "Connection Manager": 0x06,  # Volume 1: 3-5
    "Time Sync Object": 0x43,
    "Project Object": 0x64,
    "Program Object": 0x68,
    "Map Object": 0x69,
    "IO Module Object": 0x6A,
    "Routine Object": 0x6D,
    "Task Object": 0x70,
    "DateTime Object": 0x8B,
    "Cxn Object": 0x7E,
    "Unknown 66": 0x66,
    "Unknown 67": 0x67,
    "Unknown 6e": 0x6E,
    "Unknown 6f": 0x6F,
    "Unknown 71": 0x71,
    "Unknown 72": 0x72,
    "Unknown 73": 0x73,
    "Unknown 74": 0x74,
    "Unknown 77": 0x77,
    "Unknown 7f": 0x7F,
    "Unknown 8b": 0x8B,
    "Unknown 8c": 0x8C,
    "Unknown 8d": 0x8D,
    "Unknown 8e": 0x8E,
    "Unknown a2": 0xA2,
    "Unknown a3": 0xA3,
    "Unknown b0": 0xB0,
    "Unknown b1": 0xB1,
    "Unknown 032b": 0x032B,
    "Unknown 032d": 0x032D,
    "Unknown 0331": 0x0331,
    "Unknown 0332": 0x0332,
    "Unknown 0338": 0x0338,
    "Unknown 036a": 0x036A,
    "Unknown 036e": 0x036E,
}


CLASS_ATTRIBUTE_INFO: Final[dict[int, dict[int, dict[str, str]]]] = {
    CLASS_CODE["Symbol Object"]: {
        0x01: {"name": "tag_name", "type": "STRING:2"},
        0x02: {"name": "symbol_type", "type": "UINT"},
        0x03: {"name": "register_addr", "type": "DINT"},
        0x05: {"name": "", "type": "DINT"},
        0x06: {"name": "", "type": "DINT"},
        0x07: {"name": "tag_size", "type": "UINT"},
        0x08: {"name": "", "type": "RAW:12"},
        0x0A: {"name": "", "type": "SINT"},
        0x0B: {"name": "", "type": "SINT"},
    },
    CLASS_CODE["Template Object"]: {
        0x01: {"name": "Structure Handle", "type": "UINT"},
        0x02: {"name": "Member Count", "type": "UINT"},
        0x04: {"name": "Template Object Definition Size", "type": "DINT"},
        0x05: {"name": "Template Structure Size", "type": "DINT"},
        0x06: {"name": "", "type": "UINT"},
        0x07: {"name": "memory_addr", "type": "DINT"},
        0x08: {"name": "", "type": "SINT"},
    },
    CLASS_CODE["Time Sync Object"]: {
        0x01: {"name": "PTP Enable", "type": "SINT"},
        0x02: {"name": "Is Synchronized", "type": "SINT"},
        0x03: {"name": "System Time (Microseconds)", "type": "LWORD"},
        0x04: {"name": "System Time (Nanoseconds)", "type": "LWORD"},
        0x05: {"name": "Offset from Master", "type": "LWORD"},
        0x06: {"name": "Max Offset from Master", "type": "LWORD"},
        0x07: {"name": "Mean Path Delay to Master", "type": "LWORD"},
        0x08: {"name": "Grand Master Clock Info", "type": "RAW:24"},
        0x09: {"name": "Parent Clock Info", "type": "RAW:16"},
        0x0A: {"name": "Local Clock Info", "type": "RAW:20"},
        0x0B: {"name": "Number of Ports", "type": "UINT"},
        0x0C: {"name": "Port State Info", "type": "RAW:6"},
        0x0D: {"name": "Port Enable Cfg", "type": "RAW:6"},
        0x0E: {"name": "Port Log Announcement Interval Cfg", "type": "RAW:6"},
        0x0F: {"name": "Port Log Sync Interval Cfg", "type": "RAW:6"},
        0x10: {"name": "Priority 1", "type": "SINT"},
        0x11: {"name": "Priority 2", "type": "SINT"},
        0x12: {"name": "Domain Number", "type": "SINT"},
        0x13: {"name": "Clock Type", "type": "UINT"},
        0x14: {"name": "Manufacture Identity", "type": "DINT"},
        0x15: {"name": "Product Description", "type": "STRING:4"},
        0x16: {"name": "Revision Data", "type": "STRING:4"},
        0x17: {"name": "User Description", "type": "STRING:4"},
        0x18: {"name": "Port Profile Identity Info", "type": "RAW:12"},
        0x19: {"name": "Port Physical Address Info", "type": "RAW:38"},
        0x1A: {"name": "Port Protocol Address Info", "type": "RAW:24"},
        0x1B: {"name": "Steps Removed", "type": "UINT"},
        0x1C: {"name": "System Time and Offset", "type": "RAW:16"},
        0x66: {"name": "", "type": "RAW:10"},
        0x67: {"name": "", "type": "RAW:26"},
        0x68: {"name": "", "type": "RAW:33"},
        0x69: {"name": "", "type": "RAW:10"},
    },
    CLASS_CODE["Project Object"]: {
        0x01: {"name": "", "type": "STRING:2"},
        0x02: {"name": "", "type": "UINT"},
        0x03: {"name": "", "type": "UINT"},
        0x04: {"name": "", "type": "RAW:10"},
        0x06: {"name": "", "type": "UINT"},
        0x07: {"name": "", "type": "UINT"},
        0x08: {"name": "", "type": "DINT"},
    },
    CLASS_CODE["Program Object"]: {
        0x01: {"name": "", "type": "UINT"},
        0x02: {"name": "", "type": "DINT"},
        0x03: {"name": "", "type": "DINT"},
        0x05: {"name": "memory_addr", "type": "DINT"},
        0x07: {"name": "", "type": "DINT"},
        0x08: {"name": "", "type": "DINT"},
        0x09: {"name": "", "type": "DINT"},
        0x0A: {"name": "", "type": "UINT"},
        0x0B: {"name": "", "type": "UINT"},
        0x0D: {"name": "", "type": "DINT"},
        0x0F: {"name": "", "type": "UINT"},
        0x10: {"name": "symbol_addr", "type": "DINT"},
        0x11: {"name": "", "type": "DINT"},
        0x12: {"name": "", "type": "DINT"},
        0x13: {"name": "", "type": "SINT"},
        0x14: {"name": "", "type": "RAW:44"},
        0x15: {"name": "", "type": "RAW:44"},
        0x16: {"name": "", "type": "DINT"},
        0x18: {"name": "", "type": "DINT"},
        0x19: {"name": "", "type": "DINT"},
        0x1A: {"name": "", "type": "UINT"},
        0x1B: {"name": "", "type": "DINT"},
        0x1D: {"name": "", "type": "SINT"},
    },
    CLASS_CODE["Map Object"]: {
        0x01: {"name": "", "type": "UINT"},
        0x02: {"name": "", "type": "LWORD"},
        0x03: {"name": "", "type": "UINT"},
        0x07: {"name": "", "type": "UINT"},
        0x08: {"name": "", "type": "DINT"},
        0x09: {"name": "", "type": "UINT"},
        0x0A: {"name": "", "type": "DINT"},
        0x0B: {"name": "", "type": "DINT"},
        0x0C: {"name": "", "type": "DINT"},
        0x0D: {"name": "symbol_addr", "type": "DINT"},
        0x0E: {"name": "", "type": "DINT"},
        0x0F: {"name": "", "type": "SINT"},
        0x12: {"name": "", "type": "UINT"},
        0x17: {"name": "", "type": "RAW:10"},
        0x18: {"name": "", "type": "RAW:36"},
        0x19: {"name": "", "type": "SINT"},
        0x1B: {"name": "", "type": "DINT"},
        0x1C: {"name": "", "type": "DINT"},
    },
    CLASS_CODE["IO Module Object"]: {
        0x01: {"name": "Type Dimensions", "type": "RAW:12"},
        0x02: {"name": "Type", "type": "UINT"},
        0x03: {"name": "", "type": "DINT"},
        0x06: {"name": "", "type": "UINT"},
        0x07: {"name": "", "type": "DINT"},
    },
    CLASS_CODE["Routine Object"]: {
        0x01: {"name": "logic_language", "type": "UINT"},
        0x02: {"name": "routine_addr", "type": "DINT"},
        0x04: {"name": "", "type": "DINT"},
        0x05: {"name": "", "type": "UINT"},
        0x08: {"name": "symbol_addr", "type": "DINT"},
        0x09: {"name": "routine_id", "type": "DINT"},
        0x0A: {"name": "", "type": "DINT"},
        0x0B: {"name": "", "type": "DINT"},
        0x0C: {"name": "", "type": "DINT"},
        0x0D: {"name": "", "type": "DINT"},
        0x0E: {"name": "", "type": "DINT"},
        0x0F: {"name": "", "type": "DINT"},
        0x10: {"name": "", "type": "DINT"},
        0x11: {"name": "", "type": "DINT"},
        0x12: {"name": "", "type": "DINT"},
        0x13: {"name": "", "type": "DINT"},
        0x14: {"name": "", "type": "DINT"},
        0x15: {"name": "", "type": "DINT"},
        0x16: {"name": "", "type": "STRING:2"},
        0x17: {"name": "", "type": "SINT"},
        0x18: {"name": "", "type": "DINT"},
        0x1A: {"name": "", "type": "SINT"},
        0x1B: {"name": "", "type": "SINT"},
    },
    CLASS_CODE["Task Object"]: {
        0x01: {"name": "", "type": "RAW:6"},
        0x02: {"name": "", "type": "DINT"},
        0x03: {"name": "", "type": "DINT"},
        0x04: {"name": "", "type": "RAW:7"},
        0x05: {"name": "", "type": "UINT"},
        0x06: {"name": "", "type": "UINT"},
        0x07: {"name": "", "type": "DINT"},
        0x08: {"name": "", "type": "DINT"},
        0x09: {"name": "", "type": "DINT"},
        0x0A: {"name": "", "type": "UINT"},
        0x0B: {"name": "", "type": "DINT"},
        0x0C: {"name": "", "type": "DINT"},
        0x0D: {"name": "", "type": "LWORD"},
        0x0E: {"name": "", "type": "LWORD"},
        0x0F: {"name": "", "type": "LWORD"},
        0x10: {"name": "", "type": "DINT"},
        0x11: {"name": "", "type": "DINT"},
        0x12: {"name": "", "type": "DINT"},
        0x13: {"name": "", "type": "DINT"},
        0x14: {"name": "", "type": "UINT"},
        0x15: {"name": "", "type": "UINT"},
        0x16: {"name": "", "type": "DINT"},
        0x17: {"name": "", "type": "DINT"},
    },
    CLASS_CODE["DateTime Object"]: {
        0x01: {"name": "", "type": "LWORD"},
        0x02: {"name": "", "type": "UINT"},
        0x03: {"name": "", "type": "LWORD"},
        0x04: {"name": "", "type": "UINT"},
        0x05: {"name": "", "type": "RAW:28"},
        0x06: {"name": "", "type": "LWORD"},
        0x07: {"name": "", "type": "RAW:28"},
        0x08: {"name": "", "type": "RAW:13"},
        0x09: {"name": "", "type": "UINT"},
        0x0A: {"name": "", "type": "SINT"},
        0x0B: {"name": "", "type": "LWORD"},
    },
    CLASS_CODE["Cxn Object"]: {
        0x01: {"name": "", "type": "UINT"},
        0x02: {"name": "", "type": "DINT"},
        0x03: {"name": "", "type": "UINT"},
        0x04: {"name": "sw_input_addr", "type": "DINT"},
        0x05: {"name": "", "type": "DINT"},
        0x06: {"name": "memory_addr", "type": "DINT"},
        0x07: {"name": "", "type": "UINT"},
        0x08: {"name": "", "type": "DINT"},
        0x09: {"name": "", "type": "DINT"},
        0x0A: {"name": "", "type": "DINT"},
        0x0B: {"name": "", "type": "UINT"},
        0x0C: {"name": "", "type": "DINT"},
        0x0D: {"name": "", "type": "DINT"},
        0x0E: {"name": "", "type": "DINT"},
        0x0F: {"name": "", "type": "UINT"},
        0x10: {"name": "hw_input_addr", "type": "DINT"},
        0x11: {"name": "", "type": "DINT"},
        0x1C: {"name": "", "type": "UINT"},
        0x1D: {"name": "", "type": "UINT"},
        0x1E: {"name": "", "type": "SINT"},
        0x1F: {"name": "", "type": "UINT"},
        0x20: {"name": "", "type": "UINT"},
        0x21: {"name": "", "type": "UINT"},
        0x22: {"name": "", "type": "SINT"},
        0x23: {"name": "", "type": "SINT"},
        0x24: {"name": "", "type": "SINT"},
        0x25: {"name": "", "type": "UINT"},
        0x26: {"name": "", "type": "UINT"},
        0x27: {"name": "", "type": "RAW:7"},
        0x28: {"name": "", "type": "UINT"},
        0x29: {"name": "", "type": "SINT"},
        0x2A: {"name": "", "type": "SINT"},
        0x2B: {"name": "", "type": "SINT"},
        0x2C: {"name": "", "type": "SINT"},
        0x2D: {"name": "", "type": "SINT"},
        0x2E: {"name": "", "type": "DINT"},
        0x2F: {"name": "", "type": "SINT"},
        0x30: {"name": "", "type": "SINT"},
        0x31: {"name": "", "type": "SINT"},
        0x32: {"name": "", "type": "SINT"},
        0x33: {"name": "", "type": "SINT"},
        0x34: {"name": "", "type": "SINT"},
        0x35: {"name": "", "type": "SINT"},
        0x36: {"name": "", "type": "SINT"},
        0x37: {"name": "", "type": "UINT"},
        0x38: {"name": "", "type": "DINT"},
        0x39: {"name": "", "type": "DINT"},
        0x3A: {"name": "", "type": "DINT"},
        0x3B: {"name": "", "type": "DINT"},
    },
    CLASS_CODE["Unknown 66"]: {
        0x01: {"name": "", "type": "UINT"},
    },
    CLASS_CODE["Unknown 67"]: {
        0x01: {"name": "", "type": "UINT"},
        0x02: {"name": "", "type": "DINT"},
    },
    CLASS_CODE["Unknown 6e"]: {
        0x01: {"name": "", "type": "UINT"},
        0x02: {"name": "", "type": "DINT"},
        0x03: {"name": "", "type": "UINT"},
    },
    CLASS_CODE["Unknown 6f"]: {
        0x01: {"name": "", "type": "UINT"},
        0x02: {"name": "", "type": "DINT"},
        0x03: {"name": "", "type": "SINT"},
        0x04: {"name": "", "type": "SINT"},
        0x05: {"name": "", "type": "SINT"},
        0x06: {"name": "", "type": "SINT"},
        0x07: {"name": "", "type": "SINT"},
        0x08: {"name": "", "type": "UINT"},
        0x09: {"name": "", "type": "UINT"},
        0x0A: {"name": "", "type": "SINT"},
        0x0D: {"name": "", "type": "SINT"},
        0x0E: {"name": "", "type": "SINT"},
        0x0F: {"name": "", "type": "SINT"},
        0x10: {"name": "", "type": "SINT"},
        0x11: {"name": "", "type": "UINT"},
        0x66: {"name": "", "type": "DINT"},
        0x67: {"name": "", "type": "SINT"},
        0x68: {"name": "", "type": "SINT"},
        0x69: {"name": "", "type": "SINT"},
        0x6A: {"name": "", "type": "SINT"},
        0x6C: {"name": "", "type": "UINT"},
        0x6D: {"name": "", "type": "UINT"},
        0x6E: {"name": "", "type": "SINT"},
        0x71: {"name": "", "type": "SINT"},
        0x72: {"name": "", "type": "SINT"},
        0x73: {"name": "", "type": "SINT"},
        0x74: {"name": "", "type": "SINT"},
        0x75: {"name": "", "type": "UINT"},
    },
    CLASS_CODE["Unknown 71"]: {
        0x01: {"name": "", "type": "UINT"},
    },
    CLASS_CODE["Unknown 72"]: {
        0x01: {"name": "", "type": "UINT"},
        0x0F: {"name": "", "type": "RAW:18"},
        0x11: {"name": "", "type": "RAW:18"},
    },
    CLASS_CODE["Unknown 73"]: {
        0x01: {"name": "", "type": "UINT"},
    },
    CLASS_CODE["Unknown 74"]: {
        0x01: {"name": "", "type": "UINT"},
    },
    CLASS_CODE["Unknown 77"]: {
        0x01: {"name": "", "type": "UINT"},
    },
    CLASS_CODE["Unknown 7f"]: {
        0x01: {"name": "", "type": "UINT"},
    },
    CLASS_CODE["Unknown 8b"]: {
        0x01: {"name": "", "type": "UINT"},
    },
    CLASS_CODE["Unknown 8c"]: {
        0x01: {"name": "", "type": "UINT"},
    },
    CLASS_CODE["Unknown 8d"]: {
        0x01: {"name": "", "type": "UINT"},
    },
    CLASS_CODE["Unknown 8e"]: {
        0x01: {"name": "", "type": "DINT"},
        0x03: {"name": "", "type": "UINT"},
        0x06: {"name": "", "type": "DINT"},
        0x07: {"name": "", "type": "UINT"},
        0x09: {"name": "", "type": "SINT"},
        0x0A: {"name": "", "type": "SINT"},
        0x0B: {"name": "", "type": "UINT"},
        0x0C: {"name": "", "type": "UINT"},
        0x0D: {"name": "", "type": "DINT"},
        0x0F: {"name": "", "type": "SINT"},
        0x10: {"name": "", "type": "UINT"},
        0x11: {"name": "", "type": "SINT"},
        0x17: {"name": "", "type": "SINT"},
        0x19: {"name": "", "type": "DINT"},
        0x1A: {"name": "", "type": "DINT"},
        0x1B: {"name": "", "type": "LWORD"},
        0x1C: {"name": "", "type": "LWORD"},
    },
    CLASS_CODE["Unknown a2"]: {
        0x01: {"name": "", "type": "SINT"},
        0x02: {"name": "", "type": "SINT"},
        0x03: {"name": "", "type": "SINT"},
        0x04: {"name": "", "type": "RAW:38"},
        0x05: {"name": "", "type": "SINT"},
        0x06: {"name": "", "type": "DINT"},
        0x08: {"name": "", "type": "SINT"},
        0x09: {"name": "", "type": "SINT"},
        0x0A: {"name": "", "type": "SINT"},
        0x0B: {"name": "", "type": "UINT"},
        0x0C: {"name": "", "type": "DINT"},
        0x0D: {"name": "", "type": "SINT"},
        0x0E: {"name": "", "type": "SINT"},
        0x0F: {"name": "", "type": "DINT"},
        0x10: {"name": "", "type": "UINT"},
        0x11: {"name": "", "type": "DINT"},
        0x12: {"name": "", "type": "DINT"},
        0x13: {"name": "", "type": "DINT"},
        0x14: {"name": "", "type": "SINT"},
        0x15: {"name": "", "type": "SINT"},
        0x16: {"name": "", "type": "SINT"},
        0x18: {"name": "", "type": "DINT"},
        0x19: {"name": "", "type": "SINT"},
        0x65: {"name": "", "type": "SINT"},
        0x66: {"name": "", "type": "SINT"},
        0x67: {"name": "", "type": "SINT"},
        0x68: {"name": "", "type": "SINT"},
        0x69: {"name": "", "type": "DINT"},
        0x6B: {"name": "", "type": "SINT"},
        0x6C: {"name": "", "type": "SINT"},
        0x6D: {"name": "", "type": "SINT"},
        0x6E: {"name": "", "type": "UINT"},
        0x6F: {"name": "", "type": "DINT"},
        0x70: {"name": "", "type": "SINT"},
        0x71: {"name": "", "type": "SINT"},
        0x72: {"name": "", "type": "DINT"},
        0x73: {"name": "", "type": "UINT"},
        0x74: {"name": "", "type": "DINT"},
        0x75: {"name": "", "type": "DINT"},
        0x76: {"name": "", "type": "DINT"},
        0x77: {"name": "", "type": "SINT"},
        0x78: {"name": "", "type": "SINT"},
        0x79: {"name": "", "type": "SINT"},
        0x7B: {"name": "", "type": "DINT"},
        0x7C: {"name": "", "type": "SINT"},
    },
    CLASS_CODE["Unknown a3"]: {
        0x01: {"name": "", "type": "SINT"},
        0x02: {"name": "", "type": "SINT"},
        0x03: {"name": "", "type": "SINT"},
        0x04: {"name": "", "type": "SINT"},
        0x05: {"name": "", "type": "UINT"},
        0x06: {"name": "", "type": "SINT"},
        0x07: {"name": "", "type": "UINT"},
        0x08: {"name": "", "type": "RAW:38"},
        0x09: {"name": "", "type": "UINT"},
        0x65: {"name": "", "type": "SINT"},
        0x66: {"name": "", "type": "SINT"},
        0x67: {"name": "", "type": "SINT"},
        0x68: {"name": "", "type": "SINT"},
        0x69: {"name": "", "type": "UINT"},
        0x6A: {"name": "", "type": "SINT"},
        0x6B: {"name": "", "type": "UINT"},
        0x6D: {"name": "", "type": "UINT"},
    },
    CLASS_CODE["Unknown b0"]: {},
    CLASS_CODE["Unknown b1"]: {},
    CLASS_CODE["Unknown 032b"]: {},
    CLASS_CODE["Unknown 032d"]: {},
    CLASS_CODE["Unknown 0331"]: {},
    CLASS_CODE["Unknown 0332"]: {},
    CLASS_CODE["Unknown 0338"]: {},
    CLASS_CODE["Unknown 036a"]: {},
    CLASS_CODE["Unknown 036e"]: {},
}

INDEX_HASH: Final[dict[int, int]] = {
    0x2420: 0,
    0xB723: 1,
    0x1BFA: 2,
    0xBFD5: 3,
    0x5924: 4,
    0x8A97: 5,
    0xDA1E: 6,
    0x2BE9: 7,
    0x3168: 8,
    0x7C4B: 9,
    0x2582: 10,
    0x383D: 11,
    0x50EC: 12,
    0x203F: 13,
    0xC226: 14,
    0x18D1: 15,
    0x9BB0: 16,
}


CONNECTION_MANAGER_INSTANCE: Final[dict[str, bytes]] = {
    "Open Request": b"\x01",
    "Open Format Rejected": b"\x02",
    "Open Resource  Rejected": b"\x03",
    "Open Other Rejected": b"\x04",
    "Close Request": b"\x05",
    "Close Format Request": b"\x06",
    "Close Other Request": b"\x07",
    "Connection Timeout": b"\x08",
}


TAG_SERVICES_REQUEST: Final[dict[str, int]] = {
    "Read Tag": 0x4C,
    "Read Tag Fragmented": 0x52,
    "Write Tag": 0x4D,
    "Write Tag Fragmented": 0x53,
    "Read Modify Write Tag": 0x4E,
    "Multiple Service Packet": 0x0A,
    "Get Instance Attributes List": 0x55,
    "Get Attributes": 0x03,
    "Read Template": 0x4C,  # This is what we need to be able to send
    "Get Instance List": 0x4B,
    "Read Tag With Size": 0x4F,
}


# TODO: duplicate keys (0xcc), marked with noqa for now
TAG_SERVICES_REPLY: Final[dict[int, str]] = {
    0xCC: "Read Tag",
    0xD2: "Read Tag Fragmented",
    0xCD: "Write Tag",
    0xD3: "Write Tag Fragmented",
    0xCE: "Read Modify Write Tag",
    0x8A: "Multiple Service Packet",
    0xD5: "Get Instance Attributes List",
    0x83: "Get Attributes",
    0xCC: "Read Template",  # This is probably what we need # noqa: F601
    0xCB: "Get Instance List",
    0xCF: "Read Tag With Size",
}


I_TAG_SERVICES_REPLY: Final[dict[str, int]] = {
    "Read Tag": 0xCC,
    "Read Tag Fragmented": 0xD2,
    "Write Tag": 0xCD,
    "Write Tag Fragmented": 0xD3,
    "Read Modify Write Tag": 0xCE,
    "Multiple Service Packet": 0x8A,
    "Get Instance Attributes List": 0xD5,
    "Get Attributes": 0x83,
    "Read Template": 0xCC,
    "Get Instance List": 0xCB,
    "Read Tag With Size": 0xCF,
}


# MSG Error Codes:
#
# The following error codes have been taken from:
#
# Rockwell Automation Publication
# 1756-RM003P-EN-P - December 2014
SERVICE_STATUS: Final[dict[int, str]] = {
    0x01: "Connection failure (see extended status)",
    0x02: "Insufficient resource",
    0x03: "Invalid value",
    0x04: "IOI syntax error. A syntax error was detected "
    "decoding the Request Path (see extended status)",
    0x05: "Destination unknown, class unsupported, instance \nundefined "
    "or structure element undefined (see extended status)",
    0x06: "Insufficient Packet Space",
    0x07: "Connection lost",
    0x08: "Service not supported",
    0x09: "Error in data segment or invalid attribute value",
    0x0A: "Attribute list error",
    0x0B: "State already exist",
    0x0C: "Object state conflict",
    0x0D: "Object already exist",
    0x0E: "Attribute not settable",
    0x0F: "Permission denied",
    0x10: "Device state conflict",
    0x11: "Reply data too large",
    0x12: "Fragmentation of a primitive value",
    0x13: "Insufficient command data",
    0x14: "Attribute not supported",
    0x15: "Too much data",
    0x1A: "Bridge request too large",
    0x1B: "Bridge response too large",
    0x1C: "Attribute list shortage",
    0x1D: "Invalid attribute list",
    0x1E: "Request service error",
    0x1F: "Connection related failure (see extended status)",
    0x22: "Invalid reply received",
    0x25: "Key segment error",
    0x26: "Invalid IOI error",
    0x27: "Unexpected attribute in list",
    0x28: "DeviceNet error - invalid member ID",
    0x29: "DeviceNet error - member not settable",
    0xD1: "Module not in run state",
    0xFB: "Message port not supported",
    0xFC: "Message unsupported data type",
    0xFD: "Message uninitialized",
    0xFE: "Message timeout",
    0xFF: "General Error (see extended status)",
}

EXTEND_CODES: Final[dict[int, dict[int, str]]] = {
    0x01: {
        0x0100: "Connection in use",
        0x0103: "Transport not supported",
        0x0106: "Ownership conflict",
        0x0107: "Connection not found",
        0x0108: "Invalid connection type",
        0x0109: "Invalid connection size",
        0x0110: "Module not configured",
        0x0111: "EPR not supported",
        0x0114: "Wrong module",
        0x0115: "Wrong device type",
        0x0116: "Wrong revision",
        0x0118: "Invalid configuration format",
        0x011A: "Application out of connections",
        0x0203: "Connection timeout",
        0x0204: "Unconnected message timeout",
        0x0205: "Unconnected send parameter error",
        0x0206: "Message too large",
        0x0301: "No buffer memory",
        0x0302: "Bandwidth not available",
        0x0303: "No screeners available",
        0x0305: "Signature match",
        0x0311: "Port not available",
        0x0312: "Link address not available",
        0x0315: "Invalid segment type",
        0x0317: "Connection not scheduled",
    },
    0x04: {
        0x0000: "Extended status out of memory",
        0x0001: "Extended status out of instances",
    },
    0x05: {
        0x0000: "Extended status out of memory",
        0x0001: "Extended status out of instances",
    },
    0x1F: {0x0203: "Connection timeout"},
    0xFF: {
        0x7: "Wrong data type",
        0x2001: "Excessive IOI",
        0x2002: "Bad parameter value",
        0x2018: "Semaphore reject",
        0x201B: "Size too small",
        0x201C: "Invalid size",
        0x2100: "Privilege failure",
        0x2101: "Invalid keyswitch position",
        0x2102: "Password invalid",
        0x2103: "No password issued",
        0x2104: "Address out of range",
        0x2105: "Address and how many out of range",
        0x2106: "Data in use",
        0x2107: "Type is invalid or not supported",
        0x2108: "Controller in upload or download mode",
        0x2109: "Attempt to change number of array dimensions",
        0x210A: "Invalid symbol name",
        0x210B: "Symbol does not exist",
        0x210E: "Search failed",
        0x210F: "Task cannot start",
        0x2110: "Unable to write",
        0x2111: "Unable to read",
        0x2112: "Shared routine not editable",
        0x2113: "Controller in faulted mode",
        0x2114: "Run mode inhibited",
    },
}


UCMM: Final[dict[str, int]] = {
    "Interface Handle": 0,
    "Item Count": 2,
    "Address Type ID": 0,
    "Address Length": 0,
    "Data Type ID": 0x00B2,
}


# Atomic Data Type:
#
#           Bit = Bool
#      Bit array = DWORD (32-bit boolean aray)
#  8-bit integer = SINT
# 16-bit integer = UINT
# 32-bit integer = DINT
#   32-bit float = REAL
# 64-bit integer = LINT
#
# From Rockwell Automation Publication 1756-PM020C-EN-P November 2012:
# When reading a BOOL tag, the values returned for 0 and 1 are 0 and 0xff, respectively.
I_DATA_TYPE: Final[dict[int, str]] = {
    0xC1: "BOOL",
    0xC2: "SINT",  # Signed 8-bit integer
    0xC3: "INT",  # Signed 16-bit integer
    0xC4: "DINT",  # Signed 32-bit integer
    0xC5: "LINT",  # Signed 64-bit integer
    0xC6: "USINT",  # Unsigned 8-bit integer
    0xC7: "UINT",  # Unsigned 16-bit integer
    0xC8: "UDINT",  # Unsigned 32-bit integer
    0xC9: "ULINT",  # Unsigned 64-bit integer
    0xCA: "REAL",  # 32-bit floating point
    0xCB: "LREAL",  # 64-bit floating point
    0xCC: "STIME",  # Synchronous time
    0xCD: "DATE",
    0xCE: "TIME_OF_DAY",
    0xCF: "DATE_AND_TIME",
    0xD0: "STRING",  # character string (1 byte per character)
    0xD1: "BYTE",  # byte string 8-bits
    0xD2: "WORD",  # byte string 16-bits
    0xD3: "DWORD",  # byte string 32-bits
    0xD4: "LWORD",  # byte string 64-bits
    0xD5: "STRING2",  # character string (2 byte per character)
    0xD6: "FTIME",  # Duration high resolution
    0xD7: "LTIME",  # Duration long
    0xD8: "ITIME",  # Duration short
    0xD9: "STRINGN",  # character string (n byte per character)
    0xDA: "SHORT_STRING",  # character string (1 byte per character, 1 byte length indicator)
    0xDB: "TIME",  # Duration in milliseconds
    0xDC: "EPATH",  # CIP Path segment
    0xDD: "ENGUNIT",  # Engineering Units
    0xDE: "STRINGI",  # International character string
}

# Same as above, but inverted (keyed by string instead of integer ID)
S_DATA_TYPE: Final[dict[str, int]] = {v: k for k, v in I_DATA_TYPE.items()}

# https://gitlab.com/wireshark/wireshark/-/blob/master/epan/dissectors/packet-cip.h
# In Wireshark, these are "SC_*" in packet-cip.h
CIP_SERVICE_CODES: Final[dict[int, str]] = {
    0x01: "GET_ATTRIBUTE_ALL",
    0x02: "SET_ATTRIBUTE_ALL",
    0x03: "GET_ATTRIBUTE_LIST",
    0x04: "SET_ATTRIBUTE_LIST",
    0x05: "RESET",
    0x06: "START",
    0x07: "STOP",
    0x08: "CREATE",
    0x09: "DELETE",
    0x0A: "MULTIPLE_SERVICE_PACKET",
    0x0B: "RESERVED",
    0x0C: "RESERVED",
    0x0D: "APPLY_ATTRIBUTES",
    0x0E: "GET_ATTRIBUTE_SINGLE",
    0x0F: "RESERVED",
    0x10: "SET_ATTRIBUTE_SINGLE",
    0x11: "FIND_NEXT_OBJECT_INSTANCE",
    0x12: "RESERVED",
    0x13: "RESERVED",
    0x14: "RESERVED",
    0x15: "RESTORE",
    0x16: "SAVE",
    0x17: "NOP",
    0x18: "RESERVED",
    0x19: "RESERVED",
    0x1A: "RESERVED",
    0x1B: "RESERVED",
    0x1C: "GROUP_SYNC",
    0x1D: "RESERVED",
    0x1E: "RESERVED",
    0x1F: "RESERVED",
    0x20: "RESERVED",
    0x21: "RESERVED",
    0x22: "RESERVED",
    0x23: "RESERVED",
    0x24: "RESERVED",
    0x25: "RESERVED",
    0x26: "RESERVED",
    0x27: "RESERVED",
    0x28: "RESERVED",
    0x29: "RESERVED",
    0x2A: "RESERVED",
    0x2B: "RESERVED",
    0x2C: "RESERVED",
    0x2D: "RESERVED",
    0x2E: "RESERVED",
    0x2F: "RESERVED",
    0x30: "RESERVED",
    0x31: "RESERVED",
    0x32: "RESERVED",
    0x33: "RESERVED",
    0x34: "RESERVED",
    0x35: "RESERVED",
    0x36: "RESERVED",
    0x37: "RESERVED",
    0x38: "RESERVED",
    0x39: "RESERVED",
    0x3A: "RESERVED",
    0x3B: "RESERVED",
    0x3C: "RESERVED",
    0x3D: "RESERVED",
    0x3E: "RESERVED",
    0x3F: "RESERVED",
    0x40: "RESERVED",
    0x41: "RESERVED",
    0x42: "RESERVED",
    0x43: "RESERVED",
    0x44: "RESERVED",
    0x45: "RESERVED",
    0x46: "RESERVED",
    0x47: "RESERVED",
    0x48: "RESERVED",
    0x49: "RESERVED",
    0x4A: "RESERVED",
    0x4B: "RESERVED",
    0x4C: "RESERVED",
    0x4D: "RESERVED_0X4D",
    0x4E: "FORWARD_CLOSE",  # CCM (CIP Connection Manager)
    0x4F: "RESERVED",
    0x50: "RESERVED",
    0x51: "RESERVED_0X51",
    0x52: "UNCONNECTED_SEND",  # CCM (CIP Connection Manager)
    0x54: "FORWARD_OPEN",  # CCM (CIP Connection Manager)
    0x56: "GET_CONNECTION_DATA",  # CCM (CIP Connection Manager)
    0x57: "SEARCH_CONNECTION_DATA",  # CCM (CIP Connection Manager)
    0x5A: "GET_CONNECTION_OWNER",  # CCM (CIP Connection Manager)
    0x5B: "LARGE_FORWARD_OPEN",  # CCM (CIP Connection Manager)
    0x81: "GET_ATTRIBUTE_ALL_RESPONSE",
    0x82: "SET_ATTRIBUTE_ALL_RESPONSE",
    0x83: "GET_ATTRIBUTE_LIST_RESPONSE",
    0x84: "SET_ATTRIBUTE_LIST_RESPONSE",
    0x85: "RESET_RESPONSE",
    0x86: "START_RESPONSE",
    0x87: "STOP_RESPONSE",
    0x88: "CREATE_RESPONSE",
    0x89: "DELETE_RESPONSE",
    0x8A: "MULTIPLE_SERVICE_PACKET_RESPONSE",
    0x8B: "RESERVED",
    0x8C: "RESERVED",
    0x8D: "APPLY_ATTRIBUTES_RESPONSE",
    0x8E: "GET_ATTRIBUTE_SINGLE_RESPONSE",
    0x8F: "RESERVED",
    0x90: "SET_ATTRIBUTE_SINGLE_RESPONSE",
    0x91: "FIND_NEXT_OBJECT_INSTANCE_RESPONSE",
    0x92: "RESERVED",
    0x93: "RESERVED",
    0x94: "RESERVED",
    0x95: "RESTORE_RESPONSE",
    0x96: "SAVE_RESPONSE",
    0x97: "NOP_RESPONSE",
    0x98: "RESERVED",
    0x99: "RESERVED",
    0x9A: "RESERVED",
    0x9B: "RESERVED",
    0x9C: "GROUP_SYNC_RESPONSE",
    0x9D: "RESERVED",
    0x9E: "RESERVED",
    0x9F: "RESERVED",
    0xA0: "RESERVED",
    0xA1: "RESERVED",
    0xA2: "RESERVED",
    0xA3: "RESERVED",
    0xA4: "RESERVED",
    0xA5: "RESERVED",
    0xA6: "RESERVED",
    0xA7: "RESERVED",
    0xA8: "RESERVED",
    0xA9: "RESERVED",
    0xAA: "RESERVED",
    0xAB: "RESERVED",
    0xAC: "RESERVED",
    0xAD: "RESERVED",
    0xAE: "RESERVED",
    0xAF: "RESERVED",
    0xB0: "RESERVED",
    0xB1: "RESERVED",
    0xB2: "RESERVED",
    0xB3: "RESERVED",
    0xB4: "RESERVED",
    0xB5: "RESERVED",
    0xB6: "RESERVED",
    0xB7: "RESERVED",
    0xB8: "RESERVED",
    0xB9: "RESERVED",
    0xBA: "RESERVED",
    0xBB: "RESERVED",
    0xBC: "RESERVED",
    0xBD: "RESERVED",
    0xBE: "RESERVED",
    0xBF: "RESERVED",
    0xC0: "RESERVED",
    0xC1: "RESERVED",
    0xC2: "RESERVED",
    0xC3: "RESERVED",
    0xC4: "RESERVED",
    0xC5: "RESERVED",
    0xC6: "RESERVED",
    0xC7: "RESERVED",
    0xC8: "RESERVED",
    0xC9: "RESERVED",
    0xCA: "RESERVED",
    0xCB: "RESERVED",
    0xCC: "RESERVED",
    0xCD: "RESERVED_0X4D_RESPONSE",
    0xCE: "RESERVED",
    0xCF: "RESERVED",
    0xD0: "RESERVED",
    0xD1: "RESERVED_0X51_RESPONSE",
    0xD2: "UNCONNECTED_SEND_RESPONSE",  # CCM
}

# Above, but keyed by service name to resolve the code
CIP_SERVICE_TO_CODE: Final[dict[str, int]] = {
    value: key for key, value in CIP_SERVICE_CODES.items()
}

# Keys are service codes, values are bytestrings
# This replaces the old variables in enip_const.py
# "UNCONNECTED_SEND_RESPONSE": b'\xd2'
CIP_SC_BYTES: Final[dict[str, bytes]] = {
    val: key.to_bytes(1, "big") for key, val in CIP_SERVICE_CODES.items() if val != "RESERVED"
}

CIP_ERROR_CODES: Final[dict[int, str]] = {
    0x00: "Success",
    0x01: "Connection failure",
    0x02: "Resource unavailable",
    0x03: "Invalid parameter value",
    0x04: "Path segment error",
    0x05: "Path destination unknown",
    0x06: "Partial transfer",
    0x07: "Connection lost",
    0x08: "Service not supported",
    0x09: "Invalid attribute value",
    0x0A: "Attribute list error",
    0x0B: "Already in requested mode/state",
    0x0C: "Object state conflict",
    0x0D: "Object already exists",
    0x0E: "Attribute not settable",
    0x0F: "Privilege violation",
    0x10: "Device state conflict",
    0x11: "Reply data too large",
    0x12: "Fragmentation of a primitive value",
    0x13: "Not enough data",
    0x14: "Attribute not supported",
    0x15: "Too much data",
    0x16: "Object does not exist",
    0x17: "Service fragmentation sequence not in progress",
    0x18: "No stored attribute data",
    0x19: "Store operation failure",
    0x1A: "Routing failure, request packet too large",
    0x1B: "Routing failure, response packet too large",
    0x1C: "Missing attribute list entry data",
    0x1D: "Invalid attribute value list",
    0x1E: "Embedded service error",
    0x1F: "Vendor specific error",
    0x20: "Invalid parameter",
    0x21: "Write-once value or medium already written",
    0x22: "Invalid reply received",
    0x23: "Buffer overflow",
    0x24: "Invalid message format",
    0x25: "Key failure in path",
    0x26: "Path size invalid",
    0x27: "Unexpected attribute in list",
    0x28: "Invalid Member ID",
    0x29: "Member not settable",
    0x2A: "Group 2 only server general failure",
    0x2B: "Unknown Modbus error",
    0x2C: "Attribute not gettable",
}

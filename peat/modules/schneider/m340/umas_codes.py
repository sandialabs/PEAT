from typing import Final

UMAS_CODES: Final[dict[int, dict[str, str]]] = {
    0x01: {
        "name": "INIT_COMM",
        "desc": "Initialize a UMAS communication",
        "hex_rep": "0x01",
    },
    0x02: {"name": "READ_ID", "desc": "Request a PLC ID", "hex_rep": "0x02"},
    0x03: {
        "name": "READ_PROJECT_INFO",
        "desc": "Read Project information",
        "hex_rep": "0x03",
    },
    0x04: {"name": "READ_PLC_INFO", "desc": "Get internal PLC Info", "hex_rep": "0x04"},
    0x06: {
        "name": "READ_CARD_INFO",
        "desc": "Get internal PLC SD-Card Info",
        "hex_rep": "0x06",
    },
    0x0A: {
        "name": "REPEAT",
        "desc": "Sends back data sent to the PLC (used for synchronization)",
        "hex_rep": "0x0A",
    },
    0x10: {
        "name": "TAKE_PLC_RESERVATION",
        "desc": "Assign an 'owner' to the PLC",
        "hex_rep": "0x10",
    },
    0x11: {
        "name": "RELEASE_PLC_RESERVATION",
        "desc": "Release the reservation of a PLC",
        "hex_rep": "0x11",
    },
    0x12: {"name": "KEEP_ALIVE", "desc": "Keep alive message (???)", "hex_rep": "0x12"},
    0x20: {
        "name": "READ_MEMORY_BLOCK",
        "desc": "Read a memory block of the PLC",
        "hex_rep": "0x20",
    },
    0x22: {
        "name": "READ_VARIABLES",
        "desc": "Read System bits, System Words and Strategy variables",
        "hex_rep": "0x22",
    },
    0x23: {
        "name": "WRITE_VARIABLES",
        "desc": "Write System bits, System Words and Strategy variables",
        "hex_rep": "0x23",
    },
    0x24: {
        "name": "READ_COILS_REGISTERS",
        "desc": "Read coils and holding registers from PLC",
        "hex_rep": "0x24",
    },
    0x25: {
        "name": "WRITE_COILS_REGISTERS",
        "desc": "Write coils and holding registers into PLC",
        "hex_rep": "0x25",
    },
    0x30: {
        "name": "INITIALIZE_UPLOAD",
        "desc": "Initialize Strategy upload from PC to PLC",
        "hex_rep": "0x30",
    },
    0x31: {
        "name": "UPLOAD_BLOCK",
        "desc": "Upload a block to the PLC",
        "hex_rep": "0x31",
    },
    0x32: {
        "name": "END_UPLOAD",
        "desc": "Finish upload from PC to PLC",
        "hex_rep": "0x32",
    },
    0x33: {
        "name": "INITIALIZE_DOWNLOAD",
        "desc": "Initialize Strategy download from PLC to PC",
        "hex_rep": "0x33",
    },
    0x34: {
        "name": "DOWNLOAD_BLOCK",
        "desc": "Download a block from the PLC",
        "hex_rep": "0x34",
    },
    0x35: {
        "name": "END_DOWNLOAD",
        "desc": "Finish download from PLC to PC",
        "hex_rep": "0x35",
    },
    0x39: {
        "name": "READ_ETH_MASTER_DATA",
        "desc": "Read Ethernet Master Data",
        "hex_rep": "0x39",
    },
    0x40: {"name": "START_PLC", "desc": "Starts the PLC", "hex_rep": "0x40"},
    0x41: {"name": "STOP_PLC", "desc": "Stops the PLC", "hex_rep": "0x41"},
    0x50: {
        "name": "MONITOR_PLC",
        "desc": "Monitors variables, Systems bits and words",
        "hex_rep": "0x50",
    },
    0x58: {
        "name": "CHECK_PLC",
        "desc": "Check PLC Connection status",
        "hex_rep": "0x58",
    },
    0x70: {"name": "READ_IO_OBJECT", "desc": "Read IO Object", "hex_rep": "0x70"},
    0x71: {"name": "WRITE_IO_OBJECT", "desc": "WriteIO Object", "hex_rep": "0x71"},
    0x73: {"name": "GET_STATUS_MODULE", "desc": "Get Status Module", "hex_rep": "0x73"},
    0xFD: {"name": "RESPONSE_ERROR", "desc": "Reaponse ERROR", "hex_rep": "0xfd"},
    0xFE: {"name": "RESPONSE_OK", "desc": "Response OK", "hex_rep": "0xfe"},
}

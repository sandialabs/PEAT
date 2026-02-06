"""
ControlLogix Common Industrial Protocol (CIP) implementation.

Originally based on code from Agostino Ruscito's pycomm
library and heavily modified.

Authors

- Craig Buchanan
- Christopher Goes
"""

from __future__ import annotations

from typing import Any

from peat import config, log
from peat.protocols.cip import *
from peat.protocols.data_packing import *
from peat.protocols.enip import EnipDriver, EnipSocket

from .clx_const import *

PathType = tuple | tuple[int, Any]
TagData = int | bytes
DataListType = tuple[TagData, int]
FragListType = tuple[TagData, int, bytes]
TemplateType = dict[str, str | dict]
AttrTags = tuple[dict[int, dict], dict]
AttrsType = dict[int, int]  # ??

# TODO: figure out the tuple element types, annotate accordingly
# Some potential candidates (will need to determine with a debugger at runtime)
#   ClassPath: tuple[int, int]
#   InstancePath:
#   AttributeList:

# TODO: write debugging data to file (instead of to normal log at debug level 4)

# TODO: generalize response handling code, currently duplicated across multiple methods


class ClxCIP:
    """
    Common Industrial Protocol (CIP) implementation for
    Allen-Bradley ControlLogix devices.
    """

    def __init__(self, ip: str, port: int, timeout: float = 5.0, cpu_slot: int = 0):
        self.enip_socket = EnipSocket(ip, port, timeout)
        self.driver = EnipDriver(self.enip_socket, cpu_slot)
        self.log = log.bind(
            classname=self.__class__.__name__,
            target=f"{ip}[slot {cpu_slot}]",
        )
        self.log.trace(f"Initialized {repr(self)}")

    def __enter__(self) -> ClxCIP:
        if not self.open():
            raise ConnectionError(f"Failed to connect to {str(self)}")
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> bool:
        retval = self.close()
        if exc_type:
            self.log.debug(f"{exc_type.__name__}: {exc_val}")
        return retval

    def __str__(self) -> str:
        return f"{self.enip_socket.ip}:{self.enip_socket.port}"

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}({self.enip_socket.ip}, "
            f"{self.enip_socket.port}, {self.enip_socket.timeout}, "
            f"{self.driver.cpu_slot})"
        )

    def open(self) -> bool:
        """
        Prepares the driver for operation.
        """
        if self.driver.open():
            self.log.info("CIP connection SUCCESS")
            return True
        return False

    def close(self) -> bool:
        """
        Cleans up the driver when finished.
        """
        return self.driver.close()

    def get_all_data(self) -> dict[str, dict]:
        self.log.info("Pulling all data")

        # Template data
        temp_attrs, temp_tags = self.get_template_data()

        # IO Module Data
        io_mod_attrs, io_mod_tags = self.get_io_module_data()

        # Symbol Data
        symb_attrs = self.get_attributes_multi((CLASS_CODE["Symbol Object"],))

        # Program Data
        pr_attrs, p_sym_attrs, p_rou_attrs, p_rou_tags = self.get_program_data()

        # Map Data
        map_attrs, map_cxn_attrs = self.get_map_data()

        # Unknown 6e Data
        unk_6e_attrs, unk_6e_tags = self.get_unknown6e_data()

        # Task Data
        task_attrs = self.get_attributes_multi((CLASS_CODE["Task Object"],))

        # Consolidate all of the data for the slot
        slot_dict = {
            "template_attributes": temp_attrs,
            "template_tags": temp_tags,
            "io_module_attributes": io_mod_attrs,
            "io_module_tags": io_mod_tags,
            "symbol_attributes": symb_attrs,
            "program_attributes": pr_attrs,
            "program_symbol_attributes": p_sym_attrs,
            "program_routine_attributes": p_rou_attrs,
            "program_routine_tags": p_rou_tags,
            "map_attributes": map_attrs,
            "map_cxn_attributes": map_cxn_attrs,
            "unknown6e_attributes": unk_6e_attrs,
            "unknown6e_tags": unk_6e_tags,
            "task_attributes": task_attrs,
        }

        self.log.info("Finished pulling all data")
        return slot_dict

    def get_instance_list(self, class_path: PathType) -> list:
        """
        Returns the list of instance ids for a given class path.

        Args:
            class_path: The class to query

        Returns:
            ``[<instance_id>,..]``
        """
        tb = self.get_instance_list_tag_buffer(class_path)
        instance_list = b"".join(bytes([x]) for x in tb)
        return parse_get_instance_list(instance_list)

    def get_attributes(
        self, instance_path: PathType, attribute_list: list[int] | None = None
    ) -> dict:
        """
        Returns attributes for a single instance at a given instance path.

        Args:
            instance_path: The instance to query
            attribute_list: The instance attributes to query
                (default: all attributes)
        Returns:
            ``{<attribute_id>: <attribute_value>,..}``
        """
        class_code = instance_path[-2]

        if (not attribute_list) and (class_code in CLASS_ATTRIBUTE_INFO):
            attribute_list = list(CLASS_ATTRIBUTE_INFO[class_code])
        elif not attribute_list:
            attribute_list = []

        attributes = b"".join(
            bytes([x])
            for x in self.get_attributes_tag_buffer(
                instance_path=instance_path, attribute_list=attribute_list
            )
        )

        return parse_get_attributes(attributes, class_code)

    def get_attributes_multi(
        self,
        class_path: PathType,
        attribute_list: list | None = None,
        instance_list: list | None = None,
    ) -> dict[int, dict]:
        """
        Returns attributes for multiple instances at a given class path.

        Example: ``attr = self.get_attributes_multi((CLASS_CODE['X Object'],))``

        Args:
            class_path: The class path to query
            attribute_list: The instance attributes to query
                (default: all attributes)
            instance_list: The instances to query
                (default: all instances at class path)

        Returns:
            ``{<instance_id>: {<attribute_id>: <attribute_value>,..},..}``
        """
        class_code = class_path[-1]

        if (not attribute_list) and (class_code in CLASS_ATTRIBUTE_INFO):
            attribute_list = list(CLASS_ATTRIBUTE_INFO[class_code])
        elif not attribute_list:
            attribute_list = []

        if not instance_list:
            instance_list = self.get_instance_list(class_path)

        target_attributes = {}

        for instance_id in instance_list:
            instance_path = (*class_path, instance_id)
            target_attributes[instance_id] = self.get_attributes(
                instance_path=instance_path, attribute_list=attribute_list
            )

        return target_attributes

    def get_template_data(self, path: tuple = ()) -> AttrTags:
        """
        Returns a tuple (template_attributes, template_tags) for all
        template instances at the given path.

        Args:
            path: Path to the instance containing the template class

        Returns:
            (attr, tags)

            - attr = ``{<tem_id>:{<attr_id>:<attr_val>,..},..}``
            - tags = ``{<tem_id>:[tag_data],..}``
        """
        class_code = CLASS_CODE["Template Object"]
        template_attributes = self.get_attributes_multi((*path, class_code))
        template_tags = {}

        for instance_id in template_attributes:
            template_path = (*path, class_code, instance_id)
            template_size = template_attributes[instance_id][0x04] * 4 - 20
            template_tag_buffer = self.read_template(
                instance_path=template_path, size=template_size
            )
            template_tags[instance_id] = parse_template(
                cip_data=template_tag_buffer,
                member_count=template_attributes[instance_id][0x02],
            )

        return template_attributes, template_tags

    def get_io_module_data(self, path: tuple = ()) -> AttrTags:
        """
        Returns a tuple (io_module_attributes, io_module_tags) for all
        io_module instances at a given path.

        Args:
            path: Path to the instance containing the io module class

        Returns:
            (attr, tags)

            - attr = ``{<iom_id>:{<attr_id>:<attr_val>,..},..}``
            - tags = ``{<iom_id>:[tag_data],..}``
        """
        self.log.info("Getting module IO data")

        class_code = CLASS_CODE["IO Module Object"]
        io_module_attributes = self.get_attributes_multi((*path, class_code))
        io_module_tags = {}
        template_attributes = self.get_attributes_multi(
            class_path=(CLASS_CODE["Template Object"],)
        )

        for instance_id in io_module_attributes:
            io_module_path = (*path, class_code, instance_id)
            type_id = io_module_attributes[instance_id][0x02]
            type_size_d1 = unpack_dint(io_module_attributes[instance_id][1][:4])
            type_size_d2 = unpack_dint(io_module_attributes[instance_id][1][4:8])
            type_size_d3 = unpack_dint(io_module_attributes[instance_id][1][8:12])

            type_size = get_size_of_type(
                type_id, template_attributes, type_size_d1, type_size_d2, type_size_d3
            )

            # TODO: Always receives a privilege violation error. Why??
            io_module_tags[instance_id] = self.read_tag_with_size(
                instance_path=io_module_path, size=type_size
            )

        return io_module_attributes, io_module_tags

    def get_program_data(self, path: tuple = ()) -> tuple[dict, dict, dict, dict]:
        """
        Returns a tuple (program_attributes, program_symbol_attributes,
        program_routine_attributes, program_routine_tags) for all program
        instances at a given path.

        Args:
            path: Path to the instance containing the program class

        Returns:
            (attr, sym_attr, rout_attr, rout_tags)

            - attr      = ``{<prog_id>:{<attr_id>:<attr_value>,..},..}``
            - sym_attr  = ``{<prog_id>:{<sym_id>:{<attr_id>:<attr_val>,..},..},..}``
            - rout_attr = ``{<prog_id>:{<rout_id>:{<attr_id>:<attr_val>,..},..},..}``
            - rout_tags = ``{<prog_id>:{<rout_id>:[tag_data],..},..}``
        """
        self.log.info("Extracting Program Data....")

        class_code = CLASS_CODE["Program Object"]
        program_attributes = self.get_attributes_multi((*path, class_code))
        symbol_attributes = {}
        routine_attributes = {}
        routine_tags = {}

        for instance_id in program_attributes:
            program_path = (*path, class_code, instance_id)
            symbol_attributes[instance_id] = self.get_attributes_multi(
                class_path=(*program_path, CLASS_CODE["Symbol Object"])
            )
            (
                routine_attributes[instance_id],
                routine_tags[instance_id],
            ) = self.get_routine_data(program_path)

        self.log.info("Program extracted")
        return (program_attributes, symbol_attributes, routine_attributes, routine_tags)

    def get_routine_data(self, path: PathType = ()) -> AttrTags:
        """
        Returns a :class:`tuple` (routine_attributes, routine_tags)
        for all routine instances at a given path.

        Args:
            path: Path to the instance containing the routine class

        Returns:
            (attr, tags)

            - attr = ``{<rout_id>: {<attr_id>: <attr_value>,..},..}``
            - tags = ``{<rout_id>: [tag_data],..}``
        """
        class_code = CLASS_CODE["Routine Object"]
        routine_attributes = self.get_attributes_multi((*path, class_code))
        routine_tags = {}

        for instance_id in routine_attributes:
            routine_path = (*path, class_code, instance_id)
            lang = routine_attributes[instance_id][0x01]

            if lang == LANG_RLL:
                routine_tags[instance_id] = self.read_tag(routine_path)
            elif lang in [LANG_STL, LANG_SFC, LANG_FBD]:
                routine_tags[instance_id] = self.read_tag_fragmented(routine_path)
            else:
                self.log.warning(f"Invalid routine language: {lang}")

        return routine_attributes, routine_tags

    def get_map_data(self, path: PathType = ()) -> tuple[dict, dict]:
        """
        Returns a :class:`tuple` (map_attributes, map_cxn_attributes)
        for all map instances at a given path.

        Args:
            path: Path to the instance containing the map class

        Returns:
            (attr, cxn_attr)

            - attr = ``{<map_id>: {<attr_id>: <attr_val>,..},..}``
            - cxn_attr = ``{<map_id>: {<cxn_id>: {<attr_id>: <attr_val>,..},..},..}``
        """
        self.log.info("Memory Map extraction")
        class_code = CLASS_CODE["Map Object"]
        map_attributes = self.get_attributes_multi((*path, class_code))

        map_cxn_attributes = {}
        for instance_id in map_attributes:
            map_path = (*path, class_code, instance_id)
            map_cxn_attributes[instance_id] = self.get_attributes_multi(
                class_path=(*map_path, CLASS_CODE["Cxn Object"])
            )

        return map_attributes, map_cxn_attributes

    def get_unknown6e_data(self, path: tuple = ()) -> AttrTags:
        """
        Returns a :class:`tuple` (unknown6e_attributes, unknown6e_tags)
        for all ``unknown6e`` instances at a given path.

        Args:
            path: Path to the instance containing the unknown6e class

        Returns:
            (attr, tags)

            - attr = ``{<u6e_id>: {<attr_id>: <attr_val>,..},..},``
            - tags = ``{<u6e_id>: [tag_data],..}``
        """
        class_code = CLASS_CODE["Unknown 6e"]
        unknown6e_attributes = self.get_attributes_multi((*path, class_code))

        unknown6e_tags = {}
        for instance_id in unknown6e_attributes:
            unknown6e_path = (*path, class_code, instance_id)
            # TODO: fix tag request to get proper data
            unknown6e_tags[instance_id] = self.read_tag(unknown6e_path)

        return unknown6e_attributes, unknown6e_tags

    def get_instance_list_tag_buffer(self, class_path: PathType) -> list:
        """
        Returns a data buffer representing a :class:`list` of all
        instance IDs of a specified class path.

        Args:
            class_path: The class to query

        Returns:
            Data buffer representing a :class:`list` of all instance IDs of a
            specified class path
        """
        if config.DEBUG >= 4:
            self.log.debug(f"get_instance_list_tag_buffer({class_path})")

        service = TAG_SERVICES_REQUEST["Get Instance List"]
        tag_buffer = []
        next_instance = 0

        while next_instance != -1:
            path_string = path_to_string((*class_path, next_instance))
            reply = self.driver.send_connected_command(
                service=service, path=path_string, cmd_data=b""
            )
            reply_data, next_instance = get_instance_list_data_from_reply(reply)
            tag_buffer.extend(reply_data)

        if config.DEBUG >= 4:
            self.log.debug(f"get_instance_list_tag_buffer: DONE. tag_buffer:\n{tag_buffer}")
        return tag_buffer

    def get_attributes_tag_buffer(
        self, instance_path: PathType, attribute_list: list[int]
    ) -> list[TagData]:
        """
        Returns a data buffer representing the specified attributes of an
        instance at a specified path.

        Args:
            instance_path: The instance to query
            attribute_list: Attributes to query

        Returns:
            Data buffer (list(attribute_data)) representing the specified
            attributes of an instance
        """
        if config.DEBUG >= 4:
            self.log.debug(f"get_attributes_tag_buffer({instance_path}, {attribute_list})")

        service = TAG_SERVICES_REQUEST["Get Attributes"]
        tag_buffer = []
        attribute_reads = 0
        attribute_reads_total = 0
        path_string = path_to_string(instance_path)

        while attribute_reads != -1:
            attribute_reads_total += attribute_reads
            attribute_list_remaining = attribute_list[attribute_reads_total:]
            rp = [
                pack_uint(len(attribute_list_remaining)),
            ]
            rp.extend([pack_uint(attribute) for attribute in attribute_list_remaining])
            reply = self.driver.send_connected_command(
                service=service, path=path_string, cmd_data=b"".join(rp)
            )
            reply_data, attribute_reads = get_attributes_data_from_reply(reply)
            tag_buffer.extend(reply_data)

        if config.DEBUG >= 4:
            self.log.debug(f"get_attributes_tag_buffer: DONE. tag_buffer:\n{tag_buffer}")
        return tag_buffer

    def read_tag(self, instance_path: PathType, tag_offset: int = 0) -> list[int]:
        """
        Return a data buffer representing the tag data of an instance at a
        specified path (at a specified offset).

        Args:
            instance_path: The instance to query
            tag_offset: The tag offset to start reading

        Returns:
            Data buffer representing the tag data of an instance
        """
        if config.DEBUG >= 4:
            self.log.debug(f"read_tag({instance_path}, {hex(tag_offset)})")

        tag_buffer = []
        tag_size = 0
        path_string = path_to_string(instance_path)

        while tag_size != -1:
            reply = self.driver.send_connected_command(
                service=TAG_SERVICES_REQUEST["Read Tag"],
                path=path_string,
                cmd_data=b"\x00\x00\x00\x00" + pack_uint(tag_offset),
            )
            reply_data, tag_size = read_tag_data_from_reply(reply)
            tag_buffer.extend(reply_data)
            tag_offset += tag_size

        if config.DEBUG >= 4:
            self.log.debug(f"read_tag: DONE. tag_buffer:\n{tag_buffer}")
        return tag_buffer

    def read_tag_fragmented(self, instance_path: PathType, tag_offset: int = 0) -> list[int]:
        """
        Return a data buffer representing the tag data of an instance at a
        specified path (at a specified offset).

        Args:
            instance_path: The instance to query
            tag_offset: The tag offset to start reading

        Returns:
            Data buffer representing the tag data of an instance
        """
        if config.DEBUG >= 4:
            self.log.debug(f"read_tag_fragmented({instance_path}, {hex(tag_offset)})")

        tag_buffer = []
        tag_size = 0
        tag_address = b""
        path_string = path_to_string(instance_path)

        while tag_size != -1:
            reply = self.driver.send_connected_command(
                service=TAG_SERVICES_REQUEST["Read Tag Fragmented"],
                path=path_string,
                cmd_data=b"\x00\x00\x00\x00" + pack_uint(tag_offset) + b"\x00\x00\x00\x00",
            )
            reply_data, tag_size, tag_address = read_tag_fragmented_data_from_reply(reply)
            tag_buffer.extend(reply_data)
            tag_offset += tag_size

        ret = list(tag_address) + tag_buffer

        if config.DEBUG >= 4:
            self.log.debug(f"read_tag_fragmented: DONE. ret:\n{ret}")
        return ret

    def read_template(self, instance_path: PathType, size: int, offset: int = 0) -> list:
        """
        Return a data buffer representing the tag data of a template
        instance at a specified path (at a specified offset).

        Args:
            instance_path: The template instance to query
            size: The size of the template instance to query
            offset: The tag offset to start reading

        Returns:
            Data buffer representing the tag data of a template instance
        """
        if config.DEBUG >= 4:
            self.log.debug(f"read_template({instance_path}, {hex(size)}, {hex(offset)})")

        tag_buffer = []
        tag_offset = offset
        remaining_size = size
        tag_size = 0
        path_string = path_to_string(instance_path)

        while tag_size != -1:
            reply = self.driver.send_connected_command(
                service=TAG_SERVICES_REQUEST["Read Tag"],
                path=path_string,
                cmd_data=pack_dint(tag_offset) + pack_uint(remaining_size),
            )
            reply_data, tag_size = read_tag_data_from_reply(reply)
            tag_offset += tag_size
            tag_buffer.extend(reply_data)
            remaining_size = size - tag_offset

        if config.DEBUG >= 4:
            self.log.debug(f"read_template: DONE. tag_buffer:\n{tag_buffer}")
        return tag_buffer

    def read_tag_with_size(self, instance_path: PathType, size: int) -> list:
        """
        Return a data buffer representing the tag data of an instance at a
        specified path (with a specified size).

        Args:
            instance_path: The instance to query
            size: The size of the instance to query

        Returns:
            Data buffer representing the tag data of an instance
        """
        if config.DEBUG >= 4:
            self.log.debug(f"read_tag_with_size({instance_path}, {hex(size)})")

        tag_buffer = []
        path_string = path_to_string(instance_path)
        join_string = b"".join([b"\x00", b"\x00", pack_dint(size)])

        reply = self.driver.send_connected_command(
            service=TAG_SERVICES_REQUEST["Read Tag With Size"],
            path=path_string,
            cmd_data=join_string,
        )

        reply_data = read_tag_with_size_data_from_reply(reply)
        tag_buffer.extend(reply_data)

        if config.DEBUG >= 4:
            self.log.debug(f"read_tag_with_size: DONE. tag_buffer:\n{tag_buffer}")
        return tag_buffer


def get_size_of_type(
    type_id: int,
    template_attributes: dict,
    type_size_d1: int = 0,
    type_size_d2: int = 0,
    type_size_d3: int = 0,
) -> int:
    """
    Returns the size of the given type.

    Args:
        type_id: the ID of the type
        template_attributes: template object attributes
        type_size_d1: the size of the first dimension (if array)
        type_size_d2: the size of the second dimension (if array)
        type_size_d3: the size of the third dimension (if array)

    Returns:
        Integer value of the size of the type (in bytes)
    """
    structure_bit = (type_id & 0x8000) >> 15
    array_bits = (type_id & 0x6000) >> 13
    type_bits = type_id & 0x0FFF

    if structure_bit == 0:  # Atomic data
        if (type_bits in I_DATA_TYPE) and (I_DATA_TYPE[type_bits] in DATA_FUNCTION_SIZE):
            type_size = DATA_FUNCTION_SIZE[I_DATA_TYPE[type_bits]]
        else:
            log.warning(f"Something went wrong. Unseen type: {type_bits}")
            return 0
    elif type_bits in template_attributes:  # Structure data
        # TODO: rewrite the 0x5 to remove this comment block
        # template structure size
        type_size = template_attributes[type_bits][0x05]
    else:
        log.warning(f"Something went wrong. Unseen type: {type_bits}")
        return 0

    # TODO: Figure out why the below checks exist
    #   (they are all true if array_bits > 2)
    if array_bits > 0:
        type_size *= type_size_d1
    if array_bits > 1:
        type_size *= type_size_d2
    if array_bits > 2:
        type_size *= type_size_d3

    return type_size


def validate_reply_data(cip_data: bytes, service: int, min_size: int) -> bool:
    """
    Validates the reply data.

    Args:
        cip_data: The CIP data to verify
        service: The reply service code
        min_size: Used to check if the reply data is too short

    Returns:
        If validation was successful
    """
    if len(cip_data) < min_size:
        log.warning(f"CIP reply data too short ({len(cip_data)} < {min_size})")
        return False

    data_service = unpack_usint(cip_data[:1])
    if data_service != service:
        log.warning(
            f"Wrong service code for this method "
            f"(service_code: {hex(data_service)}, expected: {hex(service)})"
        )
        return False

    cip_status = unpack_usint(cip_data[2:3])
    if not ((cip_status == 0) or (cip_status in SERVICE_STATUS)):
        log.warning(f"Unknown CIP status {hex(cip_status)}")
        return False

    return True


def get_instance_list_data_from_reply(cip_data: bytes) -> DataListType:
    """
    Returns a tuple (instance_list_data, next_instance_id) from
    get_instance_list reply data.

    Args:
        cip_data: Reply data at the CIP layer

    Returns:
        (data, next_instance_id)

        - data = ``[instance_list_data]``
        - next_instance_id = instance id to read next if insufficient packet
        - space (-1 if complete or error)
    """
    if config.DEBUG >= 4:
        log.debug("get_instance_list: reading reply: starting...")

    # validate input data
    reply_service = I_TAG_SERVICES_REPLY["Get Instance List"]
    if not validate_reply_data(cip_data, reply_service, 4):
        return b"", -1

    # process input data
    cip_status = unpack_usint(cip_data[2:3])
    instance_list_data = cip_data[4:]

    # check status of input data
    if cip_status == SUCCESS:
        next_instance = -1
        if config.DEBUG >= 4:
            log.debug("get_instance_list: reading reply: SUCCESS")
    elif SERVICE_STATUS[cip_status] == "Insufficient Packet Space":
        next_instance = (
            max(
                unpack_dint(instance_list_data[i : i + 4])
                for i in range(0, len(instance_list_data), 4)
            )
            + 1
        )
        if config.DEBUG >= 4:
            log.debug(
                f"get_instance_list: reading reply: IN PROGRESS...: "
                f"next_index: {hex(next_instance)}"
            )
    else:
        next_instance = -1
        log.debug(
            f"get_instance_list reply: "
            f"error: {SERVICE_STATUS[cip_status]} (status = {hex(cip_status)})"
        )

    return instance_list_data, next_instance


def get_attributes_data_from_reply(cip_data: bytes) -> DataListType:
    """
    Returns the tuple (attribute_data, attribute_count) from
    get_attributes reply data.

    Args:
        cip_data: Reply data at the CIP layer

    Returns:
        (data, count)

        - data = ``[instance_attribute_data]``
        - count = number of attributes in the reply (-1 if complete or error)
    """
    if config.DEBUG >= 4:
        log.debug("get_attributes_data_from_reply: reading reply: starting...")

    # validate input data
    reply_service = I_TAG_SERVICES_REPLY["Get Attributes"]
    if not validate_reply_data(cip_data, reply_service, 6):
        return b"", -1

    # process input data
    cip_status = unpack_usint(cip_data[2:3])
    attribute_count = unpack_uint(cip_data[4:6])
    attribute_data = cip_data[6:]

    # check status of input data
    if cip_status == SUCCESS:
        attribute_count = -1
        if config.DEBUG >= 4:
            log.debug("get_attributes_data_from_reply: reading reply: SUCCESS")
    elif SERVICE_STATUS[cip_status] == "Insufficient Packet Space":
        if config.DEBUG >= 4:
            log.debug(
                f"get_attributes_data_from_reply: reading reply: IN "
                f"PROGRESS...: attribute_count: {hex(attribute_count)}"
            )
    else:
        log.debug(
            f"get_attributes_data_from_reply: reading reply: "
            f"error: {SERVICE_STATUS[cip_status]} (status = {hex(cip_status)})"
        )

    return attribute_data, attribute_count


def read_tag_data_from_reply(cip_data: bytes) -> DataListType:
    """
    Return the tuple (tag_data, tag_size) from read_tag reply data.

    Args:
        cip_data: Reply data at the CIP layer

    Returns:
        (data, offset)

        - data = ``[tag_data]``
        - size = size of the data in the reply (-1 if complete or error)
    """
    if config.DEBUG >= 4:
        log.debug("read_tag_data_from_reply reply: reading reply: starting...")

    # validate input data
    reply_service = I_TAG_SERVICES_REPLY["Read Tag"]
    if not validate_reply_data(cip_data, reply_service, 4):
        return b"", -1

    # process input data
    cip_status = unpack_usint(cip_data[2:3])
    tag_data = cip_data[8:]

    # check status of input data
    if cip_status == SUCCESS:
        tag_size = -1
        if config.DEBUG >= 4:
            log.debug("read_tag_data_from_reply: reading reply: SUCCESS")
    elif SERVICE_STATUS[cip_status] == "Insufficient Packet Space":
        tag_size = len(tag_data) // 4
        if config.DEBUG >= 4:
            log.debug(
                f"read_tag_data_from_reply: reading reply: IN PROGRESS...:"
                f"tag_size: {hex(tag_size)}"
            )
    else:
        tag_size = -1
        log.debug(
            f"read_tag_data_from_reply: reading reply: "
            f"error: {SERVICE_STATUS[cip_status]} (status = {hex(cip_status)})"
        )

    return tag_data, tag_size


def read_tag_fragmented_data_from_reply(cip_data: bytes) -> FragListType:
    """
    Return the tuple (tag_data, tag_size, tag_address) from
    read_tag_fragmented reply data.

    Args:
        cip_data: Reply data at the CIP layer

    Returns:
        (data, size, address)

        - data = ``[tag_data]``
        - size = size of the data in the reply (-1 if complete or error)
        - address = base memory address of the tag in the device
    """
    if config.DEBUG >= 4:
        log.debug("read_tag_fragmented: reading reply: starting...")

    # validate input data
    reply_service = I_TAG_SERVICES_REPLY["Read Tag Fragmented"]
    if not validate_reply_data(cip_data, reply_service, 12):
        return b"", -1, b"\x00\x00\x00\x00\xff\xff\xff\xff"

    # process input data
    cip_status = unpack_usint(cip_data[2:3])
    tag_address = cip_data[4:12]
    tag_data = cip_data[12:]
    tag_size = -1

    # check status of input data
    if cip_status == SUCCESS:
        if config.DEBUG >= 4:
            log.debug("read_tag_fragmented: reading reply: SUCCESS")
    elif SERVICE_STATUS[cip_status] == "Insufficient Packet Space":
        tag_size = len(tag_data) // 4
        if config.DEBUG >= 4:
            log.debug(
                f"read_tag_fragmented: reading reply: IN PROGRESS...:tag_size: {hex(tag_size)}"
            )
    else:
        log.debug(
            f"read_tag_fragmented: reading reply: "
            f"error: {SERVICE_STATUS[cip_status]} (status = {hex(cip_status)})"
        )

    return tag_data, tag_size, tag_address


def read_tag_with_size_data_from_reply(cip_data: bytes) -> TagData:
    """
    Return the tag_data from ``read_tag_with_size`` reply data.

    Args:
        cip_data: Reply data at the CIP layer

    Returns:
        ``[tag_data]``
    """
    if config.DEBUG >= 4:
        log.debug("read_tag_with_size: reading reply: starting...")

    # Validate input data
    reply_service = I_TAG_SERVICES_REPLY["Read Tag With Size"]
    if not validate_reply_data(cip_data, reply_service, 4):
        return b""

    # Process input data
    cip_status = unpack_usint(cip_data[2:3])
    tag_data = cip_data[4:]

    # Check status of input data
    if cip_status == SUCCESS:
        if config.DEBUG >= 4:
            log.debug("read_tag_with_size: reading reply: SUCCESS")
    else:
        log.debug(
            f"read_tag_with_size: reading reply: "
            f"error: {SERVICE_STATUS[cip_status]} (status = {hex(cip_status)})"
        )

    return tag_data


def path_to_string(path: PathType) -> bytes:
    """
    Returns a string representing the path from a tuple.

    Args:
        path: :class:`tuple` representation of the path

    Returns:
        Byte string representation of the path (:class:`bytes`)
    """
    path_string = b""

    for idx in range(0, len(path), 2):
        class_code = path[idx]
        instance_code = path[idx + 1]

        if class_code <= 0xFF:
            path_string += CLASS_ID["8-bit"]
            path_string += pack_usint(class_code)
        else:
            path_string += CLASS_ID["16-bit"] + b"\x00"
            path_string += pack_uint(class_code)

        if instance_code <= 0xFF:
            path_string += INSTANCE_ID["8-bit"]
            path_string += pack_usint(instance_code)
        else:
            path_string += INSTANCE_ID["16-bit"] + b"\x00"
            path_string += pack_uint(instance_code)

    full_path = (len(path_string) // 2).to_bytes(1, byteorder="big") + path_string
    return full_path


def parse_get_instance_list(cip_data: bytes) -> list[int]:
    """
    Returns a list of instance ids (int) from raw instance list CIP data.

    Args:
        cip_data: ``[<instance_list_data>]``

    Returns:
        ``[instance_id0, instance_id1, ...]``
    """
    if config.DEBUG >= 4:
        log.debug(f"parse_get_instance_list({cip_data})")

    if len(cip_data) % 4 == 0:
        instance_list = [unpack_dint(cip_data[i : i + 4]) for i in range(0, len(cip_data), 4)]
    else:
        log.debug("parse_get_instance_list: length of input data not multiple of 4")
        instance_list = []

    if config.DEBUG >= 4:
        log.debug(f"parse_get_instance_list: DONE. instance_list:\n{instance_list}")
    return instance_list


def parse_get_attributes(cip_data: bytes, cip_class: int) -> dict[int, int]:
    """
    Returns a dictionary of attributes from the raw :term:`CIP` data and the
    CIP class id (:class:`int`).

    Args:
        cip_data: ``[<attributes_data>]`` (Represented as :class:`bytes` currently)
        cip_class: CIP class of the data

    Returns:
        Dict with ``{<attr_id>:<attr_val>,..}``
    """
    if config.DEBUG >= 4:
        log.debug(f"parse_get_attributes({cip_data}, {cip_class})")

    instance_attributes = {}
    if cip_class not in CLASS_ATTRIBUTE_INFO:
        log.warning(f"parse_get_attributes: CIP class undefined (0x{cip_class:0>4x})")
        return instance_attributes

    class_attribute_info = CLASS_ATTRIBUTE_INFO[cip_class]
    idx = 0

    while idx < len(cip_data):
        if len(cip_data) < (idx + 4):
            log.warning(
                "parse_get_attributes: ID and status fields too small "
                f"(size: 0x{len(cip_data) - idx:0>4x})"
            )
            break

        attribute_id = unpack_uint(cip_data[idx : idx + 2])
        attribute_status = unpack_uint(cip_data[idx + 2 : idx + 4])
        if config.DEBUG >= 4:
            log.debug(
                f"parse_get_attributes: ID: 0x{attribute_id:0>4x} "
                f"Status: 0x{attribute_status:0>4x}"
            )

        if attribute_status != SUCCESS:
            idx += 4
            continue

        if attribute_id not in class_attribute_info:
            log.warning(
                f"parse_get_attributes: Cannot parse attribute "
                f"(undefined attribute id: 0x{attribute_id:0>4x} "
                f"for CIP class 0x{cip_class:0>4x})"
            )
            break

        attribute_type = class_attribute_info[attribute_id]["type"]
        if config.DEBUG >= 4:
            log.debug(f"parse_get_attributes: Type: {attribute_type}")

        if attribute_type.split(":")[0] == "STRING":
            string_size = int(attribute_type.split(":")[1])
            if string_size == 2:
                attribute_size = unpack_uint(cip_data[idx + 4 : idx + 4 + string_size])
            elif string_size == 4:
                attribute_size = unpack_dint(cip_data[idx + 4 : idx + 4 + string_size])
            else:
                log.warning(
                    f"parse_get_attributes: Cannot parse attribute "
                    f"(unknown string size: 0x{string_size:0>4x})"
                )
                break
            attribute_value = cip_data[
                idx + 4 + string_size : idx + 4 + string_size + attribute_size
            ]
            attribute_size += string_size

        elif attribute_type.split(":")[0] == "RAW":
            attribute_size = int(attribute_type.split(":")[1])
            attribute_value = cip_data[idx + 4 : idx + 4 + attribute_size]

        else:
            attribute_size = DATA_FUNCTION_SIZE[attribute_type]
            attribute_unpack_operation = UNPACK_DATA_FUNCTION[attribute_type]
            attribute_value = attribute_unpack_operation(
                cip_data[idx + 4 : idx + 4 + attribute_size]
            )

        if config.DEBUG >= 4:
            log.debug(f"parse_get_attributes: Value: {attribute_value}")

        instance_attributes[attribute_id] = attribute_value
        idx += 4 + attribute_size

    if config.DEBUG >= 4:
        log.debug(f"parse_get_attributes: DONE. instance_attributes:\n{instance_attributes}")
    return instance_attributes


def parse_template(cip_data: list, member_count: int) -> TemplateType:
    """
    Parses a template tag and returns a data structure
    representing the template.

    Args:
        cip_data: A buffer (list of bytes) of the template tag
        member_count: The number of members represented by the template

    Returns:
        .. code-block:: python

           {"Name":<template_name>,
           "Structure":{
              <member_offset1>:{
                  "Name":<member_name>,
                  "Type":<member_type>,
                  "Info":<member_info>,
                  }, ..
              }
           }

    """
    if config.DEBUG >= 4:
        log.debug(f"parse_template({cip_data}, {member_count})")

    name_data = cip_data[member_count * 8 :]
    name_list = bytes(name_data).split(b"\x00")
    template_name = name_list[0].split(b";")[0]
    member_name_list = name_list[1 : member_count + 1]

    template_struct = {
        "Name": template_name,
        "Structure": {},
    }

    for member_idx in range(member_count):
        if len(cip_data) < (member_idx * 8 + 8):
            log.warning(
                "parse_template: Malformed CIP data (data does "
                "not contain as many members as specified)"
            )
            break

        member_data = cip_data[(member_idx * 8) : (member_idx * 8) + 8]
        member_info = unpack_uint(bytes(member_data[:2]))
        member_type = unpack_uint(bytes(member_data[2:4]))
        member_offset = unpack_dint(bytes(member_data[4:8]))

        if len(member_name_list) > member_idx:
            member_name = member_name_list[member_idx]
        else:
            log.warning(
                f"parse_template: Malformed CIP data (data does not "
                f"contain name at index 0x{member_idx:0>4x})"
            )
            member_name = b""

        template_struct["Structure"][member_offset] = {
            "Name": member_name,
            "Type": member_type,
            "Info": member_info,
        }

    if config.DEBUG >= 4:
        log.debug(f"parse_template: DONE. template_struct:\n{template_struct}")
    return template_struct

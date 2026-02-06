"""
Functionality for pulling some interesting fields out of RSLogix L5X files.

Uses the ``l5x`` library for parsing, most functions return data structured
for PEAT.

Authors

- John Mulder
- Jennifer Trasti
- Christopher Goes
"""

import xml.etree.ElementTree as ET

import l5x

from peat import log

# TODO: cleanup this code to build PEAT data models directly, instead
# of returning dicts that then get used to build model objects...


def get_ip_address(project: l5x.Project) -> str:
    """
    Takes a ``l5x.Project`` object.
    Returns a string of the IP communication path.
    """
    comm_path = project.controller.comm_path

    if comm_path:
        ip_addr = comm_path.split("\\")[1]
    else:
        ip_addr = ""

    return ip_addr


def get_logic(project: l5x.Project) -> dict:
    """
    Return a logic dict created from the project object.
    """
    logic = {}

    logic["id"] = project.controller.element.attrib.get("ProjectSN", "")
    logic["author"] = project.doc.attrib.get("Owner", "")

    logic["created_date"] = project.controller.element.attrib.get("ProjectCreationDate", "")
    logic["last_modified_date"] = project.controller.element.attrib.get("LastModifiedDate", "")

    logic["major_rev"] = project.controller.element.attrib.get("MajorRev", "")
    logic["minor_rev"] = project.controller.element.attrib.get("MinorRev", "")

    logic["software_revision"] = project.doc.attrib.get("SoftwareRevision", "")
    logic["export_date"] = project.doc.attrib.get("ExportDate", "")

    programs = {}
    try:
        for name in project.programs.names:
            programs[name] = []
            routines_iter = project.programs[name].element.iter("Routine")

            for routine in routines_iter:
                xml_str = ET.tostring(routine, encoding="utf-8", method="xml")  # type: bytes

                # Remove the initial xml tag that ElementTree tacks on the beginning
                # start_index = xml_str.find(b"\n")  # + 1

                # Convert to proper string
                decoded_str = xml_str.decode("utf-8").strip()

                # programs[name].append(xml_str[start_index:])
                programs[name].append(decoded_str)
        logic["formats"] = {"routines": programs}
    except Exception as ex:
        log.warning(f"Failed to extract logic routines: {ex}")

    return logic


def get_modules_data(project: l5x.Project) -> list[dict]:
    """
    Gets module device data from an L5X project.
    """
    modules_data = []

    try:
        for name in project.modules.names:
            # look up the module in the l5x.Project structure
            module = project.modules[name]
            module_dict = {}
            module_dict["name"] = name
            module_dict["vendor"] = module.element.attrib.get("Vendor", "")
            module_dict["product_type"] = module.element.attrib.get("ProductType", "")
            module_dict["product_code"] = module.element.attrib.get("ProductCode", "")
            module_dict["part_number"] = module.element.attrib.get("CatalogNumber", "")
            module_dict["major"] = module.element.attrib.get("Major", "")
            module_dict["minor"] = module.element.attrib.get("Minor", "")
            module_dict["parent_module"] = module.element.attrib.get("ParentModule", "")

            ports = []
            for port_num in module.ports.names:
                port_obj = module.ports[port_num]
                ports.append(
                    {
                        "id": port_num,
                        "type": port_obj.type,
                        "address": port_obj.address,
                        "upstream": port_obj.element.get("Upstream", ""),
                        "slot": port_obj.element.get("Slot", ""),
                    }
                )
            module_dict["ports"] = ports

            modules_data.append(module_dict)
    except Exception as ex:
        log.warning(f"Failed to extract modules: {ex}")

    return modules_data


def get_programs(project: l5x.Project) -> dict:
    """
    Takes a ``l5x.Project`` object.
    Returns dict of programs where key is the program name and value is
    a dict of some known interesting attributes of the program.
    """
    programs = {}

    for program_name in project.programs.names:
        program = project.programs[program_name]
        if "MainRoutineName" in program.element.attrib:
            main_routine_name = program.element.attrib["MainRoutineName"]
            programs[program_name] = {"MainRoutineName": main_routine_name}

    return programs


def get_tags(project: l5x.Project) -> dict:
    """
    Takes a ``l5x.Project`` object.
    Returns dict of tags where key is the tag name and value is
    a dict of attributes of the tag
    """
    # TODO: Extract values from the raw ElemenTree object... the l5x library is messing these up.
    tags = {}
    controller = project.controller.element

    for tags_element in controller.iter("Tags"):
        for tag_element in tags_element.iter("Tag"):
            tag = {}
            tag["name"] = tag_element.attrib.get("Name", "")
            tag["tag_type"] = tag_element.attrib.get("TagType", "")
            tag["data_type"] = tag_element.attrib.get("DataType", "")
            tag["radix"] = tag_element.attrib.get("Radix", "")
            for description_element in tag_element.iter("Description"):
                for cdata_content_element in description_element.iter("CDATAContent"):
                    tag["description"] = cdata_content_element.text
            tags[tag["name"]] = tag

    return tags


def get_comm_ports(project: l5x.Project) -> list[dict]:
    comm_ports = []

    for comm_ports_tag in project.controller.element.iter("CommPorts"):
        for comm_port_tag in comm_ports_tag.iter("SerialPort"):
            comm_port_dict = {}
            comm_port_dict["baudrate"] = comm_port_tag.attrib.get("BaudRate", "")
            comm_port_dict["parity"] = comm_port_tag.attrib.get("Parity", "")
            comm_port_dict["stop_bits"] = comm_port_tag.attrib.get("StopBits", "")
            comm_port_dict["id"] = comm_port_tag.attrib.get("Channel", "")
            comm_port_dict["data_bits"] = comm_port_tag.attrib.get("DataBits", "")
            comm_port_dict["application"] = comm_port_tag.attrib.get("ComDriverId", "")
            comm_ports.append(comm_port_dict)

    return comm_ports


def get_project_description(project: l5x.Project) -> str:
    ele = project.controller.element.find("Description")
    if ele is None or not len(ele):
        return ""

    return next(iter(ele)).text.strip()

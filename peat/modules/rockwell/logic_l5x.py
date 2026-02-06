"""
PEAT module to consume L5X files that have been exported by a Rockwell IDE.
This could be RSLogix 50, 500, 5000, Studio 5000, or whatever it is/was called.
Only more recent versions of the Rockwell IDE can export/import L5X, and only
some of those can process "full L5X" as opposed to sections of the logic file.

The L5X format is documented by Rockwell. While the descriptions of fields is
not great, it can be helpful for figuring out what a field does.
The reference is available on the PEAT wiki (go to Allen-Bradley section).

Authors

- John Mulder
- Jennifer Trasti
- Christopher Goes
"""

from pathlib import Path

import l5x

from peat import DeviceData, DeviceModule, Interface, Tag, datastore, utils
from peat.modules.rockwell.l5x_parse import (
    get_comm_ports,
    get_ip_address,
    get_logic,
    get_modules_data,
    get_project_description,
    get_tags,
)
from peat.protocols.enip import VENDOR_NAMES


class L5X(DeviceModule):
    """
    Parser for consuming L5X files that have been exported by Rockwell IDE.
    """

    device_type = "Project"
    vendor_id = "Rockwell"  # Allen-Bradley is a brand name, not a vendor
    vendor_name = "Rockwell Automation/Allen-Bradley"
    filename_patterns = ["*.l5x", "*.L5X"]
    module_aliases = ["Logic_L5X", "L5X_logic", "l5x_logic", "Rockwell_l5x"]
    default_options = {}

    @classmethod
    def _parse(cls, file: Path, dev: DeviceData | None = None) -> DeviceData | None:
        """
        Parser for consuming L5X files that have been exported by RSLogix.

        Usage:
            ``peat parse -d L5X -- project_file.l5x``
        """
        # Pull/parse important info from the file into a project object
        # 'Project' is defined in the 3rd-party "l5x" library (not PEAT)
        project = l5x.Project(file)

        ip_address = get_ip_address(project)
        controller_name = project.controller.element.attrib.get("Name", "")
        project_name = project.doc.attrib.get("TargetName", "")

        if ip_address:
            dev = datastore.get(ip_address, "ip")
        elif controller_name:
            dev = datastore.get(controller_name, "name")
        elif project_name:
            dev = datastore.get(project_name, "id")
        else:
            tmp_id = f"l5x_unknown-project_{file.stem.lower()}"
            cls.log.warning(
                f"Failed to find controller/ip/project_name in file '{file}', "
                f"setting device ID to '{tmp_id}' as a fallback."
            )
            dev = datastore.get(tmp_id, "id")

        # TODO: generate logic using TC6
        #   Structured Text: "STContent"
        #   Ladder logic: "RLL"
        #   Sequential Function Chart: "SFC"
        #   Function Block Diagram: "FBD"

        # move data into a "DeviceData" object
        dev.name = controller_name
        dev.ip = ip_address
        dev.id = project_name

        # TODO: check TargetName and/or TargetType?
        proc_type = project.controller.element.attrib.get("ProcessorType", "")
        if proc_type:
            dev.type = "PLC"
            dev.description.product = proc_type

        logic_dict = get_logic(project)

        dev.logic.id = logic_dict.get("id", "")
        dev.logic.description = get_project_description(project)
        dev.logic.author = logic_dict["author"]
        dev.logic.formats.update(logic_dict.get("formats", {}))
        dev.logic.file.local_path = file

        if logic_dict["created_date"]:
            dev.logic.created = utils.parse_date(logic_dict["created_date"])
        if logic_dict["last_modified_date"]:
            dev.logic.last_updated = utils.parse_date(logic_dict["last_modified_date"])

        # set hardware.version and hardware.revision
        dev.hardware.version = logic_dict["major_rev"]
        dev.hardware.revision = logic_dict["minor_rev"]

        if logic_dict["software_revision"]:
            dev.extra["software_revision"] = logic_dict["software_revision"]

        if logic_dict["export_date"]:
            export_date = utils.parse_date(logic_dict["export_date"])
            if not export_date:  # handle case where date parsing fails
                dev.extra["export_date"] = logic_dict["export_date"]
            else:
                dev.extra["export_date"] = export_date

        for tag_name, tag_dict in get_tags(project).items():
            tag_obj = Tag(
                name=tag_name,
                description=tag_dict.get("description", ""),
                type=tag_dict.get("data_type", ""),
            )

            dev.store("tag", tag_obj)

        for module_dict in get_modules_data(project):
            if module_dict["name"] == "Controller":
                cls._annotate_module_values(dev, module_dict)

            module_dev = DeviceData()
            cls._annotate_module_values(module_dev, module_dict)
            dev.store("module", module_dev, lookup="name")

        for comm_port_dict in get_comm_ports(project):
            interface_obj = Interface(
                application=comm_port_dict["application"],
                baudrate=comm_port_dict["baudrate"],
                id=comm_port_dict["id"],
            )

            if comm_port_dict["parity"] == "No Parity":
                interface_obj.parity = "none"

            try:
                stop_bit = int(comm_port_dict["stop_bits"].split(" ")[0])
                interface_obj.stop_bits = stop_bit
            except Exception:
                pass

            try:
                data_bits = int(comm_port_dict["data_bits"].split(" ")[0])
                interface_obj.data_bits = data_bits
            except Exception:
                pass

            # NOTE: "lookup" parameter is used for deduplication/merging of data
            dev.store("interface", interface_obj, lookup="id")

        # TODO: fix Sub-module fields not being copied to parent
        #   related.ip (related.*)
        #   interfaces
        # This is a temporary hack to workaround this bug in PEAT
        for module_obj in dev.module:
            if module_obj.related.ip:
                dev.related.ip.update(module_obj.related.ip)
            if module_obj.interface:
                for interface in module_obj.interface:
                    dev.store("interface", interface, lookup="ip")
                    if not dev.ip and interface.ip:
                        dev.ip = interface.ip

        cls.update_dev(dev)

        return dev

    @classmethod
    def _annotate_module_values(cls, module_dev: DeviceData, module_dict: dict):
        """
        bit of a hack to add attributes from CPU to the parent module in peat model.
        """
        if not module_dev.name:
            module_dev.name = module_dict["name"]

        module_dev.description.product = module_dict["part_number"]

        vendor_id = module_dict["vendor"]
        try:
            module_dev.description.vendor.name = VENDOR_NAMES[int(vendor_id)]
            if "Rockwell" in module_dev.description.vendor.name:
                module_dev.description.vendor.id = "Rockwell"
        except Exception:
            cls.log.warning(f"Unknown vendor ID for module '{module_dev.name}': {vendor_id}")
            module_dev.extra["vendor_id"] = vendor_id

        if module_dict.get("major"):
            module_dev.hardware.version = module_dict["major"]

        if module_dict.get("minor"):
            module_dev.hardware.revision = module_dict["minor"]

        if module_dict.get("slot"):
            module_dev.slot = module_dict["slot"]

        ports_to_store = ["Ethernet"]
        for port_dict in module_dict["ports"]:
            if port_dict["type"] in ports_to_store:
                interface_obj = Interface(
                    id=port_dict["id"],
                    type=port_dict["type"],
                )

                if interface_obj.type.lower() == "ethernet" or utils.is_ip(
                    str(port_dict.get("address", ""))
                ):
                    interface_obj.ip = port_dict["address"]

                module_dev.store("interface", interface_obj)


__all__ = ["L5X"]

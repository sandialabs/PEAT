"""
Parsing of Schneider Electric Unity Pro/EcoStruxure Control Expert XEF files.

XEF files are XML exports of a complete project, created with
"File > Export Project" in Unity Pro or Control Expert. They're used for
Modicon M340, M580, Premium, Quantum and Momentum PLCs. ZEF files, a ZIP
archive containing the same XML, are also supported.

PEAT extracts the PLC and module hardware configuration, the variables
(as tags and I/O points), and project metadata. The program sections (in
all five IEC 61131-3 languages: ST, IL, FBD, LD and SFC), user-defined
function blocks (DFBs) and structure data types (DDTs) are converted to
TC6 XML and Structured Text, which can be compiled by OpenPLC. Each section
becomes a program, which runs in a task for its Unity task (MAST, FAST, AUX).

Limitations of the conversion:

- Structured Text and IL are copied as they are. Unity extensions that
  MatIEC doesn't support, such as bit access (``x.3``) and outputs in calls
  of functions, won't compile.
- Unity library blocks without an IEC 61131-3 equivalent become function
  blocks with the same interface that do nothing.
- Transition sections in LD or FBD, and references to the step flags of
  other SFC sections (e.g. ``S_1.x``), become ``FALSE``.
- Jumps in FBD and LD sections are ignored.
- Function block instances that more than one section uses stay global
  variables, which MatIEC can't call.
- I/O event sections are converted, but don't run.
- Logic that can't be converted to Structured Text is replaced with a comment
  explaining why.

Usage:
    ``peat parse -d XEF -- project.xef``

    ``peat parse -d XEF -- project.zef``

Authors

- Christopher Goes
"""

from pathlib import Path

from peat import IO, DeviceData, DeviceModule, Tag, config, datastore
from peat.file_signature import FileSignature
from peat.modules.schneider.m340 import M340

from . import xef_parse

# Prefixes of Schneider CPU part numbers, and the PLC family they belong to
PLC_FAMILIES: dict[str, str] = {
    "BMXP34": "M340",
    "BMEP58": "M580",
    "BMEH58": "M580",
    "BMEP56": "M580",
    "TSXP57": "Premium",
    "TSXH57": "Premium",
    "140CPU": "Quantum",
    "171CCC": "Momentum",
    "171CBU": "Momentum",
}


class XEF(DeviceModule):
    """
    Parser for XEF project files exported by Unity Pro/EcoStruxure Control Expert.
    """

    device_type = "PLC"
    vendor_id = "Schneider"
    vendor_name = "Schneider Electric"
    brand = "Modicon"
    filename_patterns = ["*.xef", "*.XEF", "*.zef", "*.ZEF"]
    file_signatures = [
        FileSignature(
            default_filename="project.xef",
            magic_number="3C3F786D6C20",  # <?xml
            xml_tags=("FEFExchangeFile",),
        ),
        # ZEF, a ZIP archive containing the XEF
        FileSignature(
            default_filename="project.zef",
            magic_number="504B0304",  # PK
            custom_check=xef_parse.is_zef_file,
        ),
    ]
    module_aliases = ["Unity_XEF", "schneider_xef", "control_expert_xef"]
    default_options = {}

    @classmethod
    def _parse(cls, file: Path, dev: DeviceData | None = None) -> DeviceData | None:
        data = file.read_bytes()
        if data[:2] == b"PK":  # ZEF
            data = xef_parse.extract_xef_from_zef(data)
        parsed = xef_parse.parse_xef(data)

        project_name = parsed["content_header"].get("name", "").strip()
        if dev is None:
            # "Project" is the default name of a new project
            if project_name and project_name != "Project":
                dev = datastore.get(project_name, "id")
            else:
                dev = datastore.get(f"xef_{file.stem}", "id")

        plc = parsed["plc"]
        if plc.get("part_number"):
            dev.description.product = plc["part_number"]
            for prefix, family in PLC_FAMILIES.items():
                if plc["part_number"].upper().startswith(prefix):
                    dev.description.model = family
                    break
        if plc.get("version"):
            # Version of the CPU firmware that the project is configured for
            dev.firmware.version = plc["version"]

        # Project metadata
        dev.logic.name = project_name
        dev.logic.file.local_path = file
        dev.logic.author = parsed["documentation"].get("author", "").strip()
        if dev.logic.author:
            dev.related.user.add(dev.logic.author)
        dev.logic.description = parsed["documentation"].get("general_info", "").strip()

        modified = xef_parse.parse_xef_date(parsed["content_header"].get("dateTime", ""))
        if modified:
            dev.logic.last_updated = modified

        exported = xef_parse.parse_xef_date(parsed["file_header"].get("dateTime", ""))
        if exported:
            dev.extra["export_date"] = exported
        if parsed["file_header"].get("product"):
            dev.extra["exported_by"] = parsed["file_header"]["product"]

        # Hardware modules
        for mod in parsed["modules"]:
            module = DeviceData()
            module.description.product = mod["part_number"]
            module.description.vendor = dev.description.vendor
            module.firmware.version = mod["version"]

            module.type = mod["family"]
            if module.type == "Micro Basic":
                module.type = "CPU"
            elif module.type in ["Analog", "Discrete"]:
                module.type += " I/O"

            # Racks and power supplies don't occupy a slot
            if module.type not in ["Rack", "Supply"] and mod.get("position", -1) >= 0:
                module.slot = str(mod["position"])
                module.populate_fields()
                dev.store("module", module, lookup="slot")
            else:
                module.populate_fields()
                dev.store("module", module)

        # Variables
        for var_name, var in parsed["variables"].items():
            tag = Tag(
                name=var_name,
                type=var["type"],
                address=var["address"],
                description=var.get("comment", ""),
            )
            dev.store("tag", tag, lookup="name")

            address = var["address"]
            if address.startswith(("%I", "%Q")):
                io_point = IO(
                    address=address,
                    description=var.get("comment", ""),
                    direction="input" if address.startswith("%I") else "output",
                    id=var_name,
                    name=var_name,
                    type=var["type"],
                )
                dev.store("io", io_point, lookup="id")

        # Generate TC6 XML and Structured Text
        product_version = parsed["file_header"].get("product", "")
        M340.generate_logic(
            dev,
            None,
            product_version,
            file,
            add_extra_logic=lambda tc6: xef_parse.add_project_to_tc6(parsed, tc6),
        )

        dev.extra["xef"] = {
            k: v
            for k, v in parsed.items()
            if k not in ["variables", "sections", "dfb_types", "ddt_types"]
        }
        dev.extra["xef"]["dfb_types"] = sorted(parsed["dfb_types"])
        dev.extra["xef"]["ddt_types"] = sorted(parsed["ddt_types"])

        cls.update_dev(dev)

        if config.DEVICE_DIR:
            dev.write_file(xef_parse.serializable(parsed), "parsed-config.json")

            if dev.logic.formats.get("structured_text"):
                dev.write_file(dev.logic.formats["structured_text"], "logic.st")

            if dev.logic.formats.get("tc6"):
                dev.write_file(dev.logic.formats["tc6"], "tc6.xml")

        return dev


__all__ = ["XEF"]

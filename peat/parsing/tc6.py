import copy
import io
from xml.dom import minidom
from xml.etree.ElementTree import Element, ElementTree, SubElement, tostring

from peat import config, consts, log, utils
from peat.parsing.logic_gen import tc6_to_st


class TC6:
    """
    Manages the creation and structure of a TC6 v2.01 XML tree.
    """

    def __init__(
        self,
        project_name: str = "PEAT-generated project",
        product_name: str = "",
        product_version: str = "",
        main_program_name: str = "main",
        creation_time: str = "",
        modification_time: str = "",
        company_name: str = "",
        author: str = "",
        content_description: str = "",
    ):
        """
        Args:
            project_name: Name of the project
            product_name: Name of the device
            product_version: Version of the device
            main_program_name: Name of program to use as the primary entrypoint
        """
        self.main_name = main_program_name

        # Project root
        self.root = Element(
            "project",
            {
                "xmlns": "http://www.plcopen.org/xml/tc6_0201",
                "xmlns:xsi": "http://www.w3.org/2001/XMLSchema-instance",
                "xmlns:xhtml": "http://www.w3.org/1999/xhtml",
                "xsi:schemaLocation": "http://www.plcopen.org/xml/tc6_0201",
            },
        )
        self.tree = ElementTree(element=self.root)

        # fileHeader -- REQUIRED -- metadata for the project
        file_header = {
            "companyName": company_name,
            "productName": product_name,
            "productVersion": product_version,
        }
        if not creation_time:
            creation_time = consts.START_TIME_UTC.strftime("%Y-%m-%dT%H:%M:%S")
        file_header["creationDateTime"] = creation_time
        if content_description:
            file_header["contentDescription"] = content_description
        SubElement(self.root, "fileHeader", file_header)

        # contentHeader -- REQUIRED -- metadata for the contents of the file
        # Per TC6 spec: "The 'contentHeader' element is used to provide overview
        # information concerning the actual content of the export / import file."
        content_header = {
            "name": project_name,
        }
        if author:
            content_header["author"] = author
        if not modification_time:
            modification_time = consts.START_TIME_UTC.strftime("%Y-%m-%dT%H:%M:%S")
        content_header["modificationDateTime"] = modification_time
        content_header["language"] = "en-US"
        self.content = SubElement(self.root, "contentHeader", content_header)

        # contentHeader - coordinateInfo -- REQUIRED -- used for graphical system
        self.cord_info = SubElement(self.content, "coordinateInfo")
        for t in ["fbd", "ld", "sfc"]:
            ele = SubElement(self.cord_info, t)  # fbd | ld | sfc
            SubElement(ele, "scaling", {"x": "0", "y": "0"})  # scaling

        # types -- REQUIRED -- consists of zero or more POUs
        self.types = SubElement(self.root, "types")

        # dataTypes -- REQUIRED -- Used for custom data types. Usually empty.
        SubElement(self.types, "dataTypes")

        # Program Organization Units (POUs)
        # These are chunks of logic, which in the GUI show up as elements in a tree
        # This consists of one or more POUs, each containing process logic
        self.pous = SubElement(self.types, "pous")  # POUs (This is most of the content)

        # Primary "program" POU
        self.main_pou = self.make_pou(pou_name=self.main_name)

        # Configurations (resources, global variables)
        # instances -- Contains a "configurations" element
        self.instances = SubElement(self.root, "instances")
        # configurations -- Contains 0+ "configuration" elements
        self.configs = SubElement(self.instances, "configurations")

    def __str__(self) -> str:
        return self.generate_st(sceptre=False)

    def __repr__(self) -> str:
        str_file = io.BytesIO()
        self.tree.write(str_file)
        str_file.seek(0)
        return str_file.read().decode()

    def make_pou(self, pou_name: str, pou_type: str = "program") -> SubElement:
        """
        Creates a POU instance and adds it to the tree.

        Args:
            pou_name: Name of the POU
            pou_type: Type of the pou

        Returns:
            The XML element of the POU
        """
        pou = Element("pou", {"name": pou_name, "pouType": pou_type})

        # interface -- Variable elements for the POU
        # These can be: localVars, tempVars, inputVars, outputVars, inOutVars,
        #               externalVars, globalVars, accessVars
        # Can also have the returnType if the POU is a function
        SubElement(pou, "interface")

        # body -- contains the logic block(s) for the POU
        # There are 5 types of logic blocks, corresponding to the 5 IEC 61131-3 languages:
        #   IL, ST, FBD, LD, SFC
        SubElement(pou, "body")

        self.add_pou(pou)  # Add the generated program to the list of programs
        return pou

    @staticmethod
    def add_st_content_to_pou(pou: Element, content: bytes | str):
        """
        Add a Structured Text content section to a POU.

        Args:
            pou: POU to add the content section to
            content: Structured Text that will go in the section
        """
        # Logic block element, contains the process logic
        logic_element = SubElement(pou.find("body"), "ST")

        # content -- Contains the content formatted as W3C XHTML, in this case raw ST code
        content_element = SubElement(logic_element, "xhtml:p")
        # NOTE(cegoes): this MUST be "str(..., 'utf-8')".
        # "str(...)" cannot be used here.
        content_element.text = str(content, "utf-8")

    def add_pou(self, pou: Element):
        """
        Adds a POU to the tree.

        Args:
            pou: POU to add
        """
        self.pous.append(pou)

    def generate_xml_string(self, sceptre: bool = False) -> str:
        """
        Generates TC6-XML compliant XML-formatted text from the tree.

        Args:
            sceptre: Ensure the XML is compatible with the SCEPTRE PLC (OpenPLC)

        Returns:
            XML-formatted text string of the tree
        """
        log.info("Generating string with formatted TC6 XML")
        root = self.root

        if sceptre:
            log.info(
                "The generated ST will be compatible with the SCEPTRE PLC (OpenPLC)"
            )

            # We don't want to contaminate the tree with modifications made for OpenPLC
            # This enables pure logic to still be generated separately,
            # with only a minor hit to performance
            log.debug(
                "Copying tree to prevent contamination "
                "by SCEPTRE compatibility modifications"
            )

            sceptre_root = copy.deepcopy(self.root)
            log.debug("Finished copying tree")
            configs = sceptre_root.find(".//configurations")
            if configs is not None:
                config_element = SubElement(
                    configs, "configuration", {"name": "Config0"}
                )
                resource = SubElement(config_element, "resource", {"name": "Res0"})
                task = SubElement(
                    resource,
                    "task",
                    {"name": "TaskMain", "priority": "0", "interval": "T#50ms"},
                )
                prog_name = None
                for pou in sceptre_root.find(".//pous"):
                    name = pou.get("name")
                    if name == self.main_name:
                        prog_name = name
                        break
                if prog_name is not None:
                    SubElement(
                        task,
                        "pouInstance",
                        {"name": "MainProgram", "typeName": prog_name},
                    )
                    root = sceptre_root
                else:
                    log.error("Could not find main program POU")
            else:
                log.error(
                    'Could not find the "configurations" element in '
                    "the tree. The ST will not be SCEPTRE-compatible."
                )

        # Convert XML to text and format it
        generated_xml = self.prettify_xml(root)

        log.debug("Finished generating formatted TC6 XML")
        return generated_xml

    def generate_st(
        self, generated_xml: str | None = None, sceptre: bool = False
    ) -> str:
        """
        Generates IEC 61131-3 compliant Structured Text logic.

        If a module wants to have the cache file itself,
        it should generate and pass the filepath.

        Args:
            generated_xml: Generated TC6 XMl string
            sceptre: Make the resulting logic compatible with the SCEPTRE PLC (OpenPLC)

        Returns:
            The generated Structured Text
        """
        log.info("Generating Structured Text")

        if generated_xml is None:
            generated_xml = self.generate_xml_string(sceptre=sceptre)

        # Convert to ST
        try:
            st = tc6_to_st(generated_xml.encode())
        except Exception:
            log.exception("Failed to convert TC6 XML to ST")
            return ""

        log.debug("Finished generation of Structured Text")
        return st

    def prettify_xml(self, elem: Element) -> str:
        """
        Return a pretty-printed XML string for the Element.

        Call this on your root node before writing to a file.

        Args:
            elem: XML element to prettify

        Returns:
            str with prettified XML, including header
        """
        try:
            rough_string = tostring(elem, "utf-8")
            reparsed = minidom.parseString(rough_string)
            # 4th paragraph: docs.python.org/3.5/library/stdtypes.html#str
            pretty = reparsed.toprettyxml(indent="  ", encoding="utf-8").decode()
            return pretty
        except Exception as ex:
            log.error(f"Error prettifying XML: {ex}")
            if config.LOG_DIR:
                f_path = config.LOG_DIR / "bad-prettify-xml-dump.txt"
                utils.write_file(repr(self), f_path)
            return ""

    def logic_is_empty(self) -> bool:
        """
        If there is no logic or variables present in main POU.
        """
        if not self.element_empty(self.main_pou.find("body")):
            return False

        for child in list(self.main_pou.find("interface")):
            # interface -> localVars
            if not self.element_empty(child):
                return False

        log.warning("TC6 logic is empty")
        return True

    @staticmethod
    def element_empty(ele: Element) -> bool:
        return not ele.attrib and not ele.text and not list(ele)

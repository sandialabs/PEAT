"""SEL RTAC parsing functions."""

import xml.etree.ElementTree as ET

ElasticType = None | int | bool | str | float


def convert_to_elastic(_input: str) -> ElasticType:
    """Cast input to inferred type (int, bool, None) for elasticDB."""
    try:
        return int(_input)
    except Exception:
        try:
            return float(_input)
        except Exception:
            if _input == "N" or _input == "False":
                return False
            elif _input == "Y" or _input == "True":
                return True
            elif _input == "None" or _input == "NONE":
                return None
            else:
                if (
                    isinstance(_input, str)
                    and len(_input) > 1
                    and _input[0] == "'"
                    and _input[-1] == "'"
                ):
                    _input = _input[1:-1]
                return _input


def parse_accesspointrouters(router: ET, device_info: dict) -> None:
    if "AccessPointRouters" not in device_info:
        device_info["AccessPointRouters"] = {}

    results: dict = {}
    name = router[0].find("Name").text
    results[name] = {}

    source = router[0].find("Source")
    dest = router[0].find("Destination")

    results[name]["Source"] = {
        "device_name": convert_to_elastic(source.find("DeviceName").text),
        "device_protocol": convert_to_elastic(source.find("DeviceProtocol").text),
        "type": convert_to_elastic(source.find("type")),
    }

    results[name]["Destination"] = {
        "device_name": convert_to_elastic(dest.find("DeviceName").text),
        "device_protocol": convert_to_elastic(dest.find("DeviceProtocol").text),
        "type": convert_to_elastic(dest.find("type")),
    }

    settings_terms = [
        ("Enable_Legacy_Port_Command", "Value"),
        ("Legacy_Port_Command_ID", "Value"),
    ]

    results[name]["Settings"] = parse_settings(router[0], settings_terms)

    device_info["AccessPointRouters"][name] = results[name]


def parse_devices(device: ET, device_info: dict) -> None:
    if "Devices" not in device_info:
        device_info["Devices"] = {}

    results: dict = {}
    name = device[0].find("Name").text
    results[name] = {}

    results[name]["Manufacturer"] = device[0].find("Manufacturer").text
    results[name]["Model"] = device[0].find("Model").text

    connection = device[0].find("Connection")
    results[name]["Protocol"] = connection.find("Protocol").text
    results[name]["Connection Type"] = connection.find("ConnectionType").text

    ######################
    # Parse out settings #
    ######################
    settings_terms = [
        ("Serial Communications Port", "Value"),
        ("Serial Communications Port Type", "Value"),
        ("Baud Rate", "Value"),
        ("Number of Data Bits", "Value"),
        ("Parity Bit", "Value"),
        ("Number of Stop Bits", "Value"),
        ("Network Connection Type", "Value"),
        ("Local Port Number", "Value"),
        ("SSH remote Username", "Value"),
        ("Remote Connected IED IP Address", "Value"),
        ("Remote Connection IED Logical Ethernet Port", "Value"),
        ("Serial Tunneling Mode", "Value"),
        ("Full Duplex", "Value"),
        ("Client DNP Address", "Value"),
        ("Server DNP Address", "Value"),
        ("Transport Protocol", "Value"),
        ("Client IP Port", "Value"),
        ("Client UDP Broadcast Port", "Value"),
        ("Server IP Address", "Value"),
        ("Server IP Port", "Value"),
        ("Server MODBUS Address", "Value"),
        ("Server DNP Address", "Value"),
    ]

    results[name]["Settings"] = parse_settings(connection, settings_terms)

    # Parse Binary Inputs
    results[name]["binary_inputs"] = parse_device_io_tags(connection, "Binary Inputs")

    # Parse Binary Outputs
    results[name]["binary_outputs"] = parse_device_io_tags(connection, "Binary Outputs")

    # Parse Analog Inputs
    results[name]["analog_inputs"] = parse_device_io_tags(connection, "Analog Inputs")

    # Parse Analog Outputs
    results[name]["analog_outputs"] = parse_device_io_tags(connection, "Analog Outputs")

    # Parse Coils
    results[name]["coils"] = parse_device_coils(connection, "Coils")

    # Parse Discrete Inputs
    results[name]["discrete_inputs"] = parse_device_discrete_inputs(
        connection, "Discrete Inputs"
    )

    # Parse Holding Registers
    results[name]["holding_registers"] = parse_device_modbus_registers(
        connection, "Holding Registers"
    )

    # Parse Input Registers
    results[name]["input_registers"] = parse_device_modbus_registers(
        connection, "Input Registers"
    )

    # remove empty dictionaries
    for key in list(results[name].keys()):
        if not results[name][key]:
            results[name].pop(key)

    device_info["Devices"][name] = results[name]


def parse_settings(start_element: ET.Element, terms: list[tuple]) -> dict:
    results = {}
    xpath = "./SettingPages/SettingPage/[Name='Settings']"
    for setting_page in start_element.findall(xpath):
        for term in terms:
            xpath = f"./Row/Setting/[Value='{term[0]}'].."
            for row in setting_page.findall(xpath):
                xpath = f"./Setting/[Column='{term[1]}']"
                for setting in row.findall(xpath):
                    value = setting.find("Value").text
                    results[term[0]] = convert_to_elastic(value)

    return results


# TODO: Figure out how to combine parse_device_io_tags, parse_device_coils,
# parse_device_discrete_inputs, parse_device_modbus_registers into a single function,
# there is a lot of duplicated code.
def parse_device_io_tags(start_element: ET.Element, page_name: str) -> dict:
    tags = {}
    xpath = f"./SettingPages/SettingPage/[Name='{page_name}']"
    for page in start_element.findall(xpath):
        for row in page.findall("Row"):
            tag_enable = None
            tag_name = None
            tag_point = None
            tag_type = None
            for setting in row.findall("Setting"):
                column_text = setting.find("Column").text
                value_text = setting.find("Value").text
                if column_text == "Enable":
                    tag_enable = value_text
                elif column_text == "Tag Name":
                    tag_name = value_text
                elif column_text == "Point Number":
                    tag_point = value_text
                elif column_text == "Tag Type":
                    tag_type = value_text

            if tag_name:
                tags[tag_name] = {
                    "enable": convert_to_elastic(tag_enable),
                    "point": convert_to_elastic(tag_point),
                    "type": convert_to_elastic(tag_type),
                }
    return tags


def parse_device_coils(start_element: ET.Element, page_name: str) -> dict:
    tags = {}
    xpath = f"./SettingPages/SettingPage/[Name='{page_name}']"
    for page in start_element.findall(xpath):
        for row in page.findall("Row"):
            tag_enable = None
            tag_name = None
            tag_address = None
            tag_type = None
            for setting in row.findall("Setting"):
                column_text = setting.find("Column").text
                value_text = setting.find("Value").text
                if column_text == "Enable":
                    tag_enable = value_text
                elif column_text == "Tag Name":
                    tag_name = value_text
                elif column_text == "Coil Address":
                    tag_address = value_text
                elif column_text == "Tag Type":
                    tag_type = value_text

            if tag_name:
                tags[tag_name] = {
                    "enable": convert_to_elastic(tag_enable),
                    "address": convert_to_elastic(tag_address),
                    "type": convert_to_elastic(tag_type),
                }
    return tags


def parse_device_discrete_inputs(start_element: ET.Element, page_name: str) -> dict:
    tags = {}
    xpath = f"./SettingPages/SettingPage/[Name='{page_name}']"
    for page in start_element.findall(xpath):
        for row in page.findall("Row"):
            tag_enable = None
            tag_name = None
            tag_address = None
            tag_type = None
            for setting in row.findall("Setting"):
                column_text = setting.find("Column").text
                value_text = setting.find("Value").text
                if column_text == "Enable":
                    tag_enable = value_text
                elif column_text == "Tag Name":
                    tag_name = value_text
                elif column_text == "Input Address":
                    tag_address = value_text
                elif column_text == "Tag Type":
                    tag_type = value_text

            if tag_name:
                tags[tag_name] = {
                    "enable": convert_to_elastic(tag_enable),
                    "address": convert_to_elastic(tag_address),
                    "type": convert_to_elastic(tag_type),
                }
    return tags


def parse_device_modbus_registers(start_element: ET.Element, page_name: str) -> dict:
    tags = {}
    xpath = f"./SettingPages/SettingPage/[Name='{page_name}']"
    for page in start_element.findall(xpath):
        for row in page.findall("Row"):
            tag_enable = None
            tag_name = None
            tag_type = None
            tag_reg_start = None
            tag_reg_stop = None
            for setting in row.findall("Setting"):
                column_text = setting.find("Column").text
                value_text = setting.find("Value").text
                if column_text == "Enable":
                    tag_enable = value_text
                elif column_text == "Tag Name":
                    tag_name = value_text
                elif column_text == "Tag Type":
                    tag_type = value_text
                elif column_text == "Register Address Start":
                    tag_reg_start = value_text
                elif column_text == "Register Address Stop":
                    tag_reg_stop = value_text

            if tag_name:
                tags[tag_name] = {
                    "enable": convert_to_elastic(tag_enable),
                    "type": convert_to_elastic(tag_type),
                    "register_start": convert_to_elastic(tag_reg_start),
                    "regsiter_stop": convert_to_elastic(tag_reg_stop),
                }
    return tags


def parse_maincontroller(maincontroller: ET, device_info: dict) -> None:
    results: dict = {}

    # parse Main Task
    for task in maincontroller[0]:
        if task.tag == "MainTask":
            name = task.tag
            results[name] = {}
            for line in task:
                results[name][line.tag] = convert_to_elastic(line.text)

    for task in maincontroller[0]:
        if task.tag == "Task":
            name = None
            for line in task:
                if line.tag == "Name":
                    name = line.text
                    results[name] = {}
            results[name] = {}
            for line in task:
                results[name][line.tag] = convert_to_elastic(line.text)

    device_info["MainController"] = results


def parse_contact_ios(contact: ET, device_info: dict) -> None:
    results: dict = {}

    for page in contact[0]:
        # Top level SettingPages, ignore ExportSource
        if page.tag == "SettingPages":
            # Each sub setting page
            for setting_page in page:
                for row in setting_page:
                    if row.tag == "Name":
                        name = row.text
                        results[row.text] = {}
                    else:
                        # get name of setting from entry in row
                        tag_val = tagname_from_ET(row, "Tag Name")
                        results[name][tag_val] = {}

                        for setting in row:
                            disabled = False
                            for i in setting.items():
                                if i[0] == "enabled" and i[1] == "false":
                                    disabled = True
                            if disabled is True:
                                continue
                            # pull label and value from columns 0 and 1
                            label = setting[0].text
                            results[name][tag_val][label] = convert_to_elastic(
                                setting[1].text
                            )

    device_info["ContactIO"] = results


def tagname_from_ET(row, identifier: str) -> str:
    for setting in row:
        if setting[0].text == identifier:
            return setting[1].text
    return ""


def parse_tagprocessor(tag: ET, device_info: dict) -> None:
    results: dict = {}

    for page in tag[0]:
        # Top level SettingPages, ignore ExportSource
        if page.tag == "SettingPages":
            # Each sub setting page
            for setting_page in page:
                for row in setting_page:
                    if row.tag == "Name":
                        name = row.text
                        results[row.text] = {}
                    else:
                        # get name of setting from entry in row
                        tag_val = f"SolveOrder_{tagname_from_ET(row, 'SolveOrder')}"
                        results[name][tag_val] = {}

                        for setting in row:
                            disabled = False
                            for i in setting.items():
                                if i[0] == "enabled" and i[1] == "false":
                                    disabled = True
                            if disabled is True:
                                continue
                            # pull label and value from columns 0 and 1
                            label = setting[0].text
                            body = convert_to_elastic(setting[1].text)
                            results[name][tag_val][label] = body

    device_info["TagProcessor"] = results


def parse_systemtags(tag: ET, device_info: dict) -> None:
    results: dict = {}

    for page in tag[0]:
        # Top level SettingPages, ignore ExportSource
        if page.tag == "SettingPages":
            # Each sub setting page
            for setting_page in page:
                for row in setting_page:
                    if row.tag == "Name":
                        name = row.text
                        results[row.text] = {}
                    else:
                        # get name of setting from entry in row
                        tag_val = tagname_from_ET(row, "Tag Name")
                        if (
                            tag_val
                            and len(tag_val) > 11
                            and tag_val[0:11] == "SystemTags."
                        ):
                            tag_val = tag_val[11:]
                        if tag_val is None:
                            tag_val = "None"
                        results[name][tag_val] = {}

                        for setting in row:
                            disabled = False
                            for i in setting.items():
                                if i[0] == "enabled" and i[1] == "false":
                                    disabled = True
                            if disabled is True:
                                continue
                            # pull label and value from columns 0 and 1
                            label = setting[0].text
                            results[name][tag_val][label] = setting[1].text

    device_info["SystemTags"] = results


def parse_pous(pou: ET, device_info: dict) -> None:
    """Offline parse programming logic."""
    if "POU" not in device_info:
        device_info["POU"] = {}

    results: dict = {}
    name = pou[0].find("Name").text
    results[name] = {}

    # parse program logic
    xml_root = ET.fromstring(pou[0].find("ArchivedContent").text)
    results[name]["functions"] = {}
    for i in xml_root:
        func_name = i.items()[0][1]
        results[name]["functions"][func_name] = {}
        for j in i.items():
            results[name]["functions"][func_name][j[0]] = j[1]

    device_info["POU"][name] = results[name]

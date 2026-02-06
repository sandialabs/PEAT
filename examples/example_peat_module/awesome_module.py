"""
Example PEAT module for a fictional device.

To test this example, run an HTTP server locally:

   python3 -m http.server 8090 --directory examples/example_peat_module/
   peat scan -d AwesomeTool -I examples/example_peat_module/awesome_module.py -i localhost

Authors

- Christopher Goes
"""

import json
from datetime import UTC
from pathlib import Path

from peat import (
    DeviceData,
    DeviceModule,
    Interface,
    IPMethod,
    Service,
    datastore,
    utils,
)
from peat.protocols import HTTP


class AwesomeTool(DeviceModule):
    """
    Example of a implementation of a PEAT device module.

    This class implements the PEAT API by overriding the necessary attributes
    and methods from the DeviceModule base class. The attributes tell PEAT what the
    module is, how it's configured, and what it's inputs and outputs are.
    The methods are the core functionality of the module, such as discovering
    devices on a network, or in this case parsing output from a fictional tool.
    """

    # What type of device the module is for (e.g. a PLC)
    device_type = "PLC"  # This populates "host.type"

    # Company/organization that manufactures the device(s)
    # id: short form, e.g. "SEL"
    # name: long form, e.g. "Schweitzer Engineering Laboratories"
    vendor_id = "ACME"  # This populates "host.vendor.id"
    vendor_name = "ACME, Inc."  # This populates "host.vendor.name"

    # The name and/or file extensions this module is able to parse.
    # Standard file globs are accepted, e.g. "*.txt" or "*awesome*.json",
    # as well as literal strings ("awesome_output.json").
    filename_patterns = ["awesome_output.json"]

    # "aliases" makes the module usable with different device arguments, e.g.
    # "-d middleware" to refer to this module and any others with an alias
    # of "middleware". These aliases are **OPTIONAL**, and don't have to be
    # defined.
    #
    # Example: peat parse -d middleware -I awesome_module.py -- awesome_output.json
    module_aliases = ["awesome", "middleware"]

    # Configuration options for the module. These can be set in the PEAT
    # config YAML file, either globally (all devices) or on a per-host
    # level (e.g. a particular device with a known IP).
    default_options = {
        "awesometool": {
            "option1": True,
            "another_option": "beep-boop",
            "pull_methods": [
                "http",
            ],
        }
    }

    @classmethod
    def _pull(cls, dev: DeviceData) -> bool:
        # Track if the pull was successful overall.
        # This example only uses one protocol, but in other modules with
        # multiple protocols, some of them may succeed while others may fail.
        # If any of the methods fail, then the pull should return false.
        http_successful = False

        # Check if HTTP is enabled in the "awesometool.pull_methods" option.
        # This example module only has one method (http), but other modules
        # have multiple, hence why this option is a list and not a string.
        if "http" not in dev.options["awesometool"]["pull_methods"]:
            cls.log.warning(
                f"Skipping method 'http' for pull from {dev.ip}: "
                f"'http' not listed in 'awesometool.pull_methods' option"
            )

        # Check if the HTTP port is closed. If it's not, then run the
        # normal verification check, and if it's successful, use HTTP
        elif dev.service_status({"protocol": "http"}) == "closed":
            cls.log.warning(f"Failed to pull HTTP on {dev.ip}: HTTP port is closed")

        # If device hasn't been verified yet (scan wasn't called), then run
        # the verify function for the protocol. If the verify is successful,
        # then this will fall through to the final "else" statement and result
        # in HTTP being pulled.
        # NOTE: dev._is_verified is set by PEAT during scanning
        elif not dev._is_verified and not cls._verify_http_unicast(dev):
            cls.log.warning(f"Failed to pull HTTP on {dev.ip}: HTTP verification method failed")
        else:
            if cls.pull_http(dev):
                http_successful = True

        return http_successful

    @classmethod
    def _parse(cls, file: Path, dev: DeviceData | None = None) -> DeviceData | None:
        """
        Implementing DeviceModule._parse() tells PEAT how to parse
        files. The input to "peat parse" (e.g. a file or piped input)
        is passed to _parse() as a pathlib.Path object representing
        the data as a standard file (refer to the Python documentation
        for details about pathlib.Path). This file can be binary or text,
        depending on what the module is expecting.

        In this example, the data is assumed to be JSON text, so it's read using
        pathlib.Path.read_text() and parsed using Python's JSON library.

        JSON is used here to focus on the usage of the API and not the parsing.
        In the real world, device data is rarely this clean and generally
        requires some amount of analysis work to figure out how to extract
        useful information. This sort of work makes up the vast majority
        of the time spent developing a PEAT module.

        Usage:
           peat parse -d AwesomeTool -I awesome_module.py -- awesome_output.json

        """

        # Read the JSON config data from the file
        # NOTE: Explicitly specifying "utf-8" encoding avoids Windows issues
        raw_data = file.read_text(encoding="utf-8")

        # Convert the raw JSON text to a Python dictionary ("dict")
        data = json.loads(raw_data)

        # Create a DeviceData object using the IP address read from the file
        # This object stores data associated with a particular device.
        # The "datastore" is a global registry of these objects that enables
        # information sharing between disparate parts of PEAT and ensures
        # duplicates are not created.
        #
        # The datastore will return a existing object if there is one for
        # this IP, otherwise it will create and return a new object.
        #
        # A DeviceData instance *may* be passed to _parse(). This enables usage
        # of parse as part of a pull, e.g. pull artifacts from a device, then call
        # parse() on the artifacts to parse them, simplifying the code.
        if not dev:
            dev = datastore.get(data["hostIp"], "ip")  # type: DeviceData

        # Populate basic attributes. Refer to the Data Model documentation
        # and the DeviceData class for details on the available fields.
        dev.name = data["hostName"]  # host.name
        dev.os.full = data["osName"]  # host.os.full
        dev.os.name = data["osName"].split(" ")[0]  # host.os.name
        dev.os.version = data["osName"].split(" ")[1]  # host.os.version

        # Populate information about network interfaces
        for interface in data["networkInterfaces"]:
            iface_object = Interface(
                type="ethernet",
                ip=interface["ipAddress"],
                subnet_mask=interface["subnetMask"],
                gateway=interface["ipGateway"],
            )

            # "store()" is a method to insert complex information into the
            # data model, such as files or network interfaces. Refer to the
            # data model documentation for further examples.
            dev.store("interface", iface_object)

            # An alternative method is to directly append the object.
            # If duplicates aren't a concern, this is the faster method.
            # dev.interface.append(iface_object)

            if interface.get("telnetEnabled"):
                # "service" represents a typical network service running
                # on the device, such as a Telnet or FTP server.
                # You add information about the service to the Service() model,
                # then pass it to store() to insert it into PEAT's data model.
                # The specific fields are described in the data model documentation.
                service = Service(
                    protocol="telnet",
                    port=interface["telnetPort"],
                    enabled=bool(interface["telnetEnabled"] == "yes"),
                    transport="tcp",
                )

                # interface_lookup associates this service with an existing Interface object
                # If this isn't needed, then the call would be "dev.store("service", service)"
                dev.store(
                    key="service",
                    value=service,
                    interface_lookup={"ip": iface_object.ip},
                )

        # _parse() must ALWAYS return a DeviceData object
        # If you wish to save off any intermediate values, either write them
        # to a file using 'dev.write_file()' or store them in 'dev.extra'.
        return dev

    @classmethod
    def _verify_http_unicast(cls, dev: DeviceData) -> bool:
        """
        Verify the device is a ACME PLC by retrieving an
        HTTP page and parsing it's contents.
        """

        cls.log.debug(f"Checking {dev.ip} using HTTP")
        port = dev.options["http"]["port"]  # Port for this protocol
        timeout = dev.options["http"]["timeout"]  # Timeout for this protocol

        try:
            # Use of a "with" statement ensures the HTTP connection is closed
            # when this function returns or an error occurs.
            with HTTP(dev.ip, port, timeout) as http:
                # This is a simplified example. Normally the page result
                # would be parsed to extract useful information and
                # annotated to the device object before returning. While
                # simply pulling the page is usually enough to fingerprint
                # a device, PEAT's philosophy is to extract as much useful
                # information as possible from any data acquired, even if
                # it may get that information again later via different
                # methods (e.g. HTTP parsing, then SNMP queries).
                response = http.get("example_device_page.html")

                # If the device responded with an error (e.g. 404 page not found)
                # then the response is None and verification fails.
                if not response:
                    return False

                data = response.json()

                # Extract values from the response and add to the data model.
                # ".pop()" is used to remove the values as they're read.
                # This allows the remaining data to be added to "extra"
                # without adding duplicates.
                dev.name = data.pop("deviceName")
                dev.description.model = data.pop("deviceModel")
                dev.geo.timezone = data.pop("timezone")
                dev.related.ip.update(data.pop("connectedIps"))

                # Times in PEAT are datetime objects normalized to UTC timezone
                # Note that PEAT provides a robust set of well-tested utilities
                # to handle common tasks such as parsing timestamps. Use them!
                # (Refer to the Internal API documentation for further details)
                ts = utils.parse_date(data.pop("timeStarted"))
                dev.start_time = ts.astimezone(tz=UTC)

                # Set the "extra" field to leftover data
                dev.extra = data

                cls.log.debug(f"Successfully verified {dev.ip} using HTTP")
                return True
        except Exception as err:
            # PEAT's philosophy to error handling is "proceed as far as we
            # can without sacrificing safety and stability of the network".
            # In this case, while the pull from this device failed, other
            # devices in the PEAT run may still succeed, so the exception
            # is logged and verification returns False.
            cls.log.warning(
                f"Failed to verify {dev.ip} via HTTP due to an unhandled exception: {err}"
            )
            return False

    @classmethod
    def pull_http(cls, dev: DeviceData) -> bool:
        cls.log.info(f"Pulling HTTP from {dev.ip}")

        with HTTP(
            ip=dev.ip,
            port=dev.options["http"]["port"],  # Port for this protocol
            timeout=dev.options["http"]["timeout"],  # Timeout for this protocol
        ) as http:
            response = http.get("awesome_output.json")

        if not response:
            # The level at which you log a failure is up to you.
            # It could be a warning or an error, depending on how
            # critical the protocol is to recovering an adequate
            # amount of data from the device.
            cls.log.error(f"HTTP pull failed for {dev.ip}")
            return False

        try:
            data = response.json()
            path = dev.write_file(data, "awesome_output.json")
            cls.parse(path, dev)
        except Exception as ex:
            cls.log.warning(f"HTTP pull failed for {dev.ip}: {ex}")
            return False

        cls.log.info(f"Finished pulling HTTP from {dev.ip}")
        return True


# Identification methods are injected (added to the class) after the class
# is defined. These methods do not have to be defined on the class, and can
# be functions defined elsewhere or imported from another library.
#
# Identification methods MUST accept a DeviceData instance as the first
# positional argument, and MUST return a bool indicating success or failure.
#
# Refer to the DeviceModule API documentation for further details on identify methods.
#
# To test this example, run an HTTP server locally:
#   python3 -m http.server 8090 --directory examples/example_peat_module/
#   peat scan -d AwesomeTool -I examples/example_peat_module/awesome_module.py -i localhost
AwesomeTool.ip_methods = [
    IPMethod(
        # Name of the method, this can be whatever you want
        name="awesome_scrape_http_page",
        # Set the description to the Python docstring of the identify function
        # This can also be defined as a string.
        description=str(AwesomeTool._verify_http_unicast.__doc__).strip(),
        # unicast_ip or broadcast_ip (if your method sends broadcast packets)
        type="unicast_ip",
        # Callback function to perform fingerprinting.
        # Note the lack of parenthesis '()'. This is the function object, not
        # a call to the function. Functions are first-class objects in Python.
        identify_function=AwesomeTool._verify_http_unicast,
        # How reliable the method is, in general, rated on scale of 1-10
        reliability=8,
        # Name of the application protocol
        protocol="http",
        # Transport protocol, 'tcp', 'udp', or 'other'
        transport="tcp",
        # The standard port used by this protocol.
        # For example, Telnet would be 23.
        default_port=8090,
    )
]


# Where any serial methods would go. This is not required unless you're
# interacting with a device over a serial link. Look at the serial-supporting
# PEAT modules for examples of this, such as SELRelay.
AwesomeTool.serial_methods = []


# "__all__" is a Python-ism that reduces "namespace pollution"
__all__ = ["AwesomeTool"]

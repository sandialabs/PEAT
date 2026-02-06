from peat import DeviceData, DeviceModule, IPMethod

from .totus_http import TotusHTTP

# TODO: need to get the OS version somehow
#   could use output from "hostnamectl" while ssh'd in

# TODO: see if we can download arbitrary files via an API

# TODO: download export
#   Generate and download
#   Download existing export if available

# TODO: parse export file/directory using PEAT
# Generate an export
# POST http://localhost/totus/api/1.0/exports
# {"startTime":1602655200000,"endTime":1634191200000,
# "historicalData":true,"pdPatterns":true,"integoRaw":true,
# "tfcData":true,"tcmSyslog":true,"tcmKernelLog":true,
# "tcmCalcStates":true,"dgaLogs":true}
# Get exports
# http://localhost/totus/api/1.0/exports
# Download export
#   Get download url from "downloadUrl" for a export in list
# GET http://localhost/totus/api/1.0/exports/1634196496957?compress=1
# Remove the generated export from the device
# DELETE http://localhost/totus/api/1.0/exports/1634196496957

# TODO: Extract IP from login.html ("issuer" parameter in href)


class Totus(DeviceModule):
    """PEAT module for the Camlin Totus G9 Dissolved Gas Analyzer (DGA).

    Listening services

    - SSH (TCP 22)
    - HTTP (TCP 80)

    Data collected

    - Metadata
    - Status
    - Network configuration
    - DNP3 registers
    - Modbus registers

    Authors

    - Christopher Goes
    - Thomas Byrd
    """

    device_type = "DGA"
    vendor_id = "Camlin"  # aka Camlin Energy, Camlin Group
    vendor_name = "Camlin Ltd"
    brand = "Totus"
    model = "G9"
    default_options = {"http": {"user": "", "pass": ""}}

    @classmethod
    def _verify_http(cls, dev: DeviceData) -> bool:
        """Verify the device is a DGA via HTTP."""
        cls.log.debug(f"Checking {dev.ip} via HTTP")

        try:
            with TotusHTTP(
                ip=dev.ip,
                port=dev.options["http"]["port"],
                timeout=dev.options["http"]["timeout"],
                dev=dev,
            ) as http:
                response = http.get("")
                if not response:
                    cls.log.debug(f"Failed to verify {dev.ip} via HTTP: no response")
                    return False

                page = response.text
                if not page:
                    cls.log.debug(
                        f"Failed to verify {dev.ip} via HTTP: no page content in response"
                    )
                    return False

                # Check for Totus-specific strings in the homepage HTML content
                if (
                    "<title>TOTUS</title>".lower() in page.lower()
                    or "totus-webapp." in page.lower()
                ):
                    cls.log.debug(f"Successfully verified {dev.ip} using HTTP")
                    return True

                cls.log.debug(f"Failed to verify {dev.ip} via HTTP")
        except Exception:
            cls.log.exception(f"failed to verify {dev.ip} via HTTP due to an unhandled exception")

        return False

    @classmethod
    def _pull(cls, dev: DeviceData) -> bool:
        cls.log.info(f"Pulling from {dev.ip} via HTTP")

        if not dev._cache.get("totus_http_session"):
            dev._cache["totus_http_session"] = TotusHTTP(
                ip=dev.ip,
                port=dev.options["http"]["port"],
                timeout=dev.options["http"]["timeout"],
                dev=dev,
            )
        http = dev._cache["totus_http_session"]

        if not http.login(
            username=dev.options["http"]["user"], password=dev.options["http"]["pass"]
        ):
            cls.log.error(f"Failed to pull from {dev.ip}: http login failed")
            return False

        dev.related.user.add(dev.options["http"]["user"])

        at_least_one_success = http.get_and_process_all(dev)

        # If all methods failed, exit with error
        if not at_least_one_success:
            return False

        return True


Totus.ip_methods = [
    IPMethod(
        name="Totus DGA scrape HTTP homepage",
        description=str(Totus._verify_http.__doc__).strip(),
        type="unicast_ip",
        identify_function=Totus._verify_http,
        reliability=6,
        protocol="http",
        transport="tcp",
        default_port=80,
    )
]


__all__ = ["Totus"]

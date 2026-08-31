"""
SEL HTTP module specialized for the SEL-3622

Author: Francisco Santana
"""

from typing import Final, Literal
from urllib.parse import urljoin

from bs4 import BeautifulSoup
from bs4.element import Tag

from ..sel_http import SELHTTP, Response

# A list of endpoint names available in the `ENDPOINTS` dictionary.
#
# This list may not be exhaustive.
AVAILABLE_ENDPOINTS = Literal[
    # Commissioning
    "commissioning",
    # Login/Dash/Logout
    "login",
    "dashboard",
    "logout",
    # System
    "usage_policy",
    "file_management",
    "web_server",
    "management_interface",
    "nat",
    "device_reset",
    "physical_sensors",
    # User
    "accounts",
    "ldap_settings",
    "radius_settings",
    "local_groups",
    # Network
    "network_settings",
    "static_routes",
    "syslog",
    "firewall",
    "hosts",
    "snmp_settings",
    # Serial Ports
    "serial_port_settings",
    "serial_port_profiles",
    "port_mappings",
    # Security
    "x509_certificates",
    "ipsec_connections",
    "allowed_clients",
    "ssh_host_key",
    "password_management",
    # Reports
    "system_logs",
    "diagnostics",
    "proxy_reports",
]

# Dictionary mapping endpoint names to actual endpoint URLs.
#
# Like `AVAILABLE_ENDPOINTS`, this may not be exhaustive.
ENDPOINTS: Final[
    dict[
        AVAILABLE_ENDPOINTS,
        str,
    ]
] = {
    # Commissioning
    "commissioning": "/Commissioning.sel",
    # Login/Dash/Logout
    "login": "/Login.sel",
    "dashboard": "/index.sel",
    "logout": "/Logout.sel",
    # System
    "usage_policy": "/UsagePolicy.sel",
    "file_management": "/FileManagement.sel",
    "web_server": "/WebServer.sel",
    "management_interface": "/ManagementInterface.sel",
    "nat": "/NAT.sel",
    "device_reset": "/DeviceReset.sel",
    "physical_sensors": "/PhysicalSensors.sel",
    # User
    "accounts": "/Users.sel",
    "ldap_settings": "/LDAP.sel",
    "radius_settings": "/RADIUS.sel",
    "local_groups": "/LocalGroups.sel",
    # Network
    "network_settings": "/NetworkSettings.sel",
    "static_routes": "/StaticRoutes.sel",
    "syslog": "/Syslog.sel",
    "firewall": "/Firewall.sel",
    "hosts": "/Hosts.sel",
    "snmp_settings": "/SNMP.sel",
    # Serial Ports
    "serial_port_settings": "/SerialPortSettings.sel",
    "serial_port_profiles": "/SerialPortProfiles.sel",
    "port_mappings": "/PortMappings.sel",
    # Security
    "x509_certificates": "/X509.sel",
    "ipsec_connections": "/IPsec.sel",
    "allowed_clients": "/AllowedClients.sel",
    "ssh_host_key": "/SSH_Host_Key.sel",
    "password_management": "/PasswordManagement.sel",
    # Reports
    "system_logs": "/SysLogReport.sel",
    "diagnostics": "/Diagnostics.sel",
    "proxy_reports": "/ProxyReports.sel",
}


class HTTP362X(SELHTTP):
    """
    Class specialization of `SELHTTP` for the SEL-3622/3620.

    Though not super-specialized, it changes some behaviors to accommodate the requirements of this module.
    """

    def __init__(self, *args, **kwargs) -> None:
        """Ensure HTTPS"""
        super().__init__(*args, **kwargs)

        self.protocol = "https"

    def get(self, *args, **kwargs) -> Response | None:
        if "use_cache" not in kwargs:
            return super().get(*args, use_cache=False, **kwargs)
        else:
            return super().get(*args, **kwargs)

    def get_endpoint(self, page: AVAILABLE_ENDPOINTS, *args, **kwargs) -> Response | None:
        """
        Simplification of the "get" function which takes the name of the endpoint
        """
        return self.get(ENDPOINTS[page], *args, **kwargs)

    def post_endpoint(self, page: AVAILABLE_ENDPOINTS, *args, **kwargs) -> Response | None:
        """
        Simplification of the "post" function which takes the name of the endpoint
        """
        return self.post(self.endpoint(page), *args, **kwargs)

    def endpoint(self, endpoint: AVAILABLE_ENDPOINTS) -> str:
        """
        Generate an endpoint URL (necessary in post for some reason)
        """

        if endpoint not in ENDPOINTS:
            raise IndexError(f"Endpoint {endpoint} not available")
        else:
            return urljoin(self.url, ENDPOINTS[endpoint])

    def is_logged_in(self) -> bool:
        """
        Check if the session is still logged in
        """

        result = self.get("/index.sel", allow_redirects=False)

        return not result or (
            result.ok and not (result.is_redirect or result.is_permanent_redirect)
        )

    def needs_selssid(self, soup: BeautifulSoup) -> bool:
        """Checks if the SELSSID token is required to log in"""
        return isinstance(soup.find("input", {"name": "SELSESSID", "type": "hidden"}), Tag)

    def login(
        self, user: str = "admin", passwd: str = "Admin123!", login_timeout: int = 10
    ) -> bool:
        """
        Attempt to log in using the SEL-3622 Gateway's web interface.

        Newer firmware appears to submit a token matching a cookie stored in
        the browser on first connection.
        """

        # We only need login data and the Submit button
        login_data = {
            "Username": user,
            "Password": passwd,
            "submit": "Submit",
        }

        # Voodoo magicks be here
        # Gets a session cookie
        resp = self.get(ENDPOINTS["login"], "https")
        if not resp:
            self.log.error("Could not get login page")
            return False

        ssid = self.session.cookies["SELSESSID"]
        if not ssid:
            self.log.error("Did not get a session ID")
            return False

        self.session_id = ssid

        if self.needs_selssid(self.gen_soup(resp.text)):
            login_data["SELSESSID"] = ssid

        # NOTE: attempting to log in with a short timeout will fail.
        # At least 10 seconds will suffice.
        resp = self.post(
            self.endpoint("login"), data=login_data, timeout=max(self.timeout, login_timeout)
        )

        # Null response means no host
        if not resp:
            self.log.warning("Received no response.")
            return False

        # Non-200 response indicates an error
        if resp.status_code != 200:
            self.log.error(f"Login failed: received non-200 response ({resp.status_code}).")
            return False

        # Log-in failure
        # This more specific query will yield fewer false positives
        if "<!-- # ERROR MESSAGES # -->" in resp.text:
            self.log.error("Failed to log in")

        self.gateway_logged_in = True
        self.gateway = "SEL-3622"

        return True

    def get_global_token_value(self) -> str:
        response = self.get_endpoint("device_reset")
        if not response or not response.status_code == 200 or len(response.history) > 0:
            raise Exception("Could not get token")

        soup = self.gen_soup(response.text)
        t = soup.find("input", {"type": "hidden", "name": "t"})
        assert isinstance(t, Tag)

        return t.get_text(strip=True)

    def get_fid(self) -> str | None:
        """
        Get the FID of the device. Typically, this contains the device model.
        """

        assert self.gateway_logged_in
        assert self.gateway in ["SEL-3622", "SEL-3620"]

        idx = self.get(ENDPOINTS["dashboard"], use_cache=False)
        if not idx:
            self.log.error(f"Could not get {ENDPOINTS['dashboard']}")
            return None

        # We can perform an explicit check for the device's FID.
        idx_soup = self.gen_soup(idx.text)

        fid = idx_soup.find("td", {"id": "fid"})
        if not isinstance(fid, Tag):
            self.log.error("Could not get fid field")
            return None
        txt = fid.get_text()

        self.log.debug(f"FID: {txt}")

        return txt

    def validate_fid(self) -> bool:
        """
        Validate that the SEL is a supported SEL-3620 or SEL-3622 device
        """
        VALID_FID_SUBSTRINGS = ["SEL-3622", "SEL-3620"]

        fid_txt = self.get_fid()

        if not fid_txt or not any([x in fid_txt for x in VALID_FID_SUBSTRINGS]):
            self.log.error("This device is not an SEL-3620 or SEL-3622")
            return False

        return True

    def logout(self):
        """
        Log out of an SEL-3622 gateway
        """
        if self.gateway_logged_in and self.gateway not in ["SEL-3622", "SEL-3620"]:
            self.get(ENDPOINTS["logout"], use_cache=False)
            self.gateway_logged_in = False
            del self.gateway

    def disconnect(self) -> None:
        if self.gateway_logged_in and self.gateway not in ["SEL-3622", "SEL-3620"]:
            self.logout()
        return super().disconnect()

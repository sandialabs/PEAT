"""
SEL-3620 Ethernet Security Gateway.

Note: "This device accepts HTTPS connections only and will reject all HTTP connection requests. "
Authors

- Amanda Gonzales
- James Gallagher
"""

from peat import DeviceData, DeviceModule, IPMethod, exit_handler

from .sel_http import SELHTTP


class SEL3620(DeviceModule):
    """
    SEL-3620 Ethernet Security Gateway.
    """

    device_type = "Gateway"
    vendor_id = "SEL"
    vendor_name = "Schweitzer Engineering Laboratories"
    brand = "SEL"
    module_aliases = ["sel-3620", "3620"]
    default_options = {
        "web": {
            "user": "",
            "pass": "",
            "users": [
                "admin",
                "Admin",
                "administrator",
            ],
        }
    }

    @classmethod
    def _verify_http(cls, dev: DeviceData) -> bool:
        """
        Verify a device is a SEL-3620 Gateway via the HTTPS web interface.
        """
        port = dev.options["https"]["port"]
        timeout = dev.options["https"]["timeout"]

        cls.log.debug(
            f"Verifying SEL-3620 HTTP for {dev.ip}:{port} using HTTPS (timeout: {timeout})"
        )

        session = SELHTTP(dev.ip, port, timeout)
        logged_in = False

        if dev._cache.get("verified_web_user") and dev._cache.get("verified_web_pass"):
            logged_in = session.login_3620(
                dev._cache["verified_web_user"],
                dev._cache["verified_web_pass"],
            )
        # Check all user, and pass, only proceed when logged_in is True, or exhausted
        else:
            if dev.options["web"]["user"]:
                users = [dev.options["web"]["user"]]
            else:
                users = dev.options["web"]["users"]

            if dev.options["web"]["pass"]:
                passwords = [dev.options["web"]["pass"]]
            else:
                passwords = dev.options["web"]["passwords"]

            for username in users:
                cls.log.debug(f"Attempting SEL-3620 login to {dev.ip} with user '{username}'")

                for password in passwords:
                    logged_in = session.login_3620(username, password)
                    if logged_in:
                        dev._cache["verified_web_user"] = username
                        dev._cache["verified_web_pass"] = password
                        dev.related.user.add(username)
                        break

                if logged_in:
                    break

        if logged_in:
            try:
                dashboard = session.get_index(dev=dev)
            except Exception:
                cls.log.exception(f"Failed to view dashboard for {dev.ip}")
                session.disconnect()
                return False

            # Check if dashboard has appropriate fields
            if ("web_device_info" not in dashboard) or (
                "Firmware Version" not in dashboard["web_device_info"]
            ):
                session.disconnect()
                return False

            # TODO: don't hardcode check to 3620, process_fid() should set model #
            if (
                "3620" in dashboard["web_device_info"]["Firmware Version"]
                # and "3620" in dashboard["web_device_info"]["Host Name"]
            ):
                # Cache the session using this protocol
                if not dev._cache.get("web_session"):
                    dev._cache["web_session"] = session
                    exit_handler.register(session.disconnect, "CONNECTION")
                else:
                    session.disconnect()
                return True

        session.disconnect()
        cls.log.debug(f"SEL3620 HTTPS verification failed for {dev.ip}:{port}")
        return False

    @classmethod
    def _pull(cls, dev: DeviceData) -> bool:
        cls.log.info(f"Pulling web pages from {dev.ip}")
        session = dev._cache["web_session"]

        # TODO: explicit list of functions to call
        # TODO: return false if all functions fail
        methods = [
            k
            for k, f in SELHTTP.__dict__.items()
            if callable(f) and f.__name__.startswith("gateway_")
        ]
        cls.log.debug(f"Get Requests for {len(methods)} HTTP methods...")
        for name in methods:
            cls.log.info(f"** Getting: {name} **")
            try:
                res = getattr(session, name)(dev)
                if not res:
                    cls.log.warning(f"False result for method '{name}'")
            except Exception as ex:
                cls.log.error(f"{name}: {ex!s}")

        return True


SEL3620.ip_methods = [
    IPMethod(
        name="sel_3620_web_fingerprint",
        description=str(SEL3620._verify_http.__doc__).strip(),
        type="unicast_ip",
        identify_function=SEL3620._verify_http,
        default_port=443,
        protocol="https",
        reliability=6,  # Should find title for 3620 on login page
        transport="tcp",
    )
]

__all__ = ["SEL3620"]

"""
Retrieve the system settings backup (among other data)

Author: Francisco Santana
"""

# TODO: This needs to be updated to better support the SEL-3620 or R212 of the firmware.
# It would be best to implement support for the single file backup tab as well

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Final

from bs4.element import Tag
from loguru import logger as log
from pydantic import BaseModel

from peat.data.models import DeviceData

from .sel362x_http import ENDPOINTS, HTTP362X
from .sel362x_pull import (
    element_exists_by_id,
    get_text_of,
    get_text_of_f,
)
from .sel362x_pull import (
    find_tag_f as find_tag,
)
from .sel362x_pull import (
    get_attrib_f as get_attrib,
)

# Variants of the class for the system settings hash
SYSTEM_SETTINGS_HASH_ID: Final[list[str]] = [
    "display_systemSettingsExportHash",
    "display_systemFileExportHash",
]


def copy_form(version: int) -> dict[str, tuple[str | None, str]]:
    """Get the appropriate base form"""
    # The base content to perform a request on this page
    if version <= 200:
        return {
            "fileUploadType": (None, "firmwareFile"),
            "JAVASCRIPT": (None, "True"),
            "MAX_FILE_SIZE": (None, "125000000"),
            "t": (None, ""),
            "uploadedfile": (None, ""),
            "ImportPassword": (None, ""),
            "Password": (None, ""),
            "PasswordConfirm": (None, ""),
            "submit": (None, ""),
        }
    else:
        return {
            "fileUploadType": (None, "firmwareFile"),
            "JAVASCRIPT": (None, "True"),
            "MAX_FILE_SIZE": (None, "125000000"),
            "t": (None, ""),
            "uploadedfile": (None, ""),
            "ImportPassword": (None, ""),
            "SysSettingsPassword": (None, ""),
            "SysSettingsPasswordConfirm": (None, ""),
            "BackupFilePassword": (None, ""),
            "BackupFilePasswordConfirm": (None, ""),
            "submit": (None, ""),
        }


# How many times to query the page before forcing a pull
MAX_QUERIES: int = 3


def sys_settings_form_generate(
    password: str, token: str, version: int
) -> dict[str, tuple[str | None, str]]:
    """
    Create a form populated with the requisite "Generate" data
    """
    result = copy_form(version)
    result["t"] = (None, token)
    if version <= 200:
        result["Password"] = (None, password)
        result["PasswordConfirm"] = (None, password)
        result["submit"] = (None, "Generate")
    else:
        result["SysSettingsPassword"] = (None, password)
        result["SysSettingsPasswordConfirm"] = (None, password)
        result["submit"] = (None, "Generate System Settings")

    return result


def sys_settings_form_export(token: str, version: int) -> dict[str, tuple[str | None, str]]:
    """
    Create a form populated with the requisite "Export" data
    """
    result = copy_form(version)
    result["t"] = (None, token)
    if version <= 200:
        result["submit"] = (None, "Export")
    else:
        result["submit"] = (None, "Export System Settings")

    return result


def single_file_form_generate(
    password: str, token: str, version: int
) -> dict[str, tuple[str | None, str]]:
    """
    Create a form populated with the requisite "Generate" data
    """
    result = copy_form(version)
    result["t"] = (None, token)
    if version <= 200:
        raise Exception("Not supported")
    else:
        result["BackupFilePassword"] = (None, password)
        result["BackupFilePasswordConfirm"] = (None, password)
        result["submit"] = (None, "Generate Backup File")

    return result


def single_file_form_export(token: str, version: int) -> dict[str, tuple[str | None, str]]:
    """
    Create a form populated with the requisite "Export" data
    """
    result = copy_form(version)
    result["t"] = (None, token)
    if version <= 200:
        raise Exception("Not supported")
    else:
        result["submit"] = (None, "Export Backup File")

    return result


class SystemSettings(BaseModel):
    """
    Structured representation of the data expected here
    """

    # Fields to do with system settings
    prev_sys_settings_hash: str
    curr_sys_settings_hash: str
    password: str
    data: str
    time: str
    file_name: str

    # Fields to do with the firmware version
    current_firmware: str
    previous_firmware: str

    # Supplementary information
    last_uploaded_config_hash: str
    connection_directory_hash: str


def pull_info(http: HTTP362X) -> dict[str, str] | None:
    """
    Pulls several data points from the web page:

    - The last uploaded "connection directory" configuration file's hash
    - The last uploaded "system settings" backup file's hash
    - The last generated "system settings" backup file's hash
    - The current firmware version
    - The previous firmware version
    - The token required to initiate a backup file generation *and*
      download a copy of the generated backup file
    """
    response = http.get_endpoint("file_management", use_cache=False)

    if not response:
        http.log.error("No response")
        return None

    if response.status_code != 200:
        http.log.error("Error loading page")
        return None

    soup = http.gen_soup(response.text)

    old_hash = get_text_of_f(soup, "span", {"id": SYSTEM_SETTINGS_HASH_ID})
    token = get_attrib(find_tag(soup, "input", {"type": "hidden", "id": "t"}), "value")
    current_version = get_text_of_f(soup, "span", {"id": "display_CurrentVersion"})
    previous_version = get_text_of(soup, "span", {"id": "display_PreviousVersion"}) or "N/A"

    last_sys_cfg_upload = get_text_of_f(
        soup,
        "span",
        {"id": ["display_systemSettingsImportHash", "currentSystemFileImportHash"]},
    )

    conn_dir_hash = get_text_of_f(soup, "span", {"id": "display_connectionDirectoryHash"})

    return {
        "old_hash": old_hash,
        "token": token,
        "current_version": current_version,
        "previous_version": previous_version,
        "last_system_settings_import_hash": last_sys_cfg_upload,
        "connection_directory_hash": conn_dir_hash,
    }


def pull_generated_system_settings_hash(http: HTTP362X) -> str | None:
    """
    Pulls the current hash of the last generated configuration file.

    Used to detect whether a new file was generated recently.
    """
    response = http.get_endpoint("file_management", use_cache=False)

    if not response:
        http.log.error("No response")
        return None

    if response.status_code != 200:
        http.log.error("Error loading page")
        return None

    soup = http.gen_soup(response.text)

    return get_text_of_f(soup, "span", {"id": SYSTEM_SETTINGS_HASH_ID})


# TODO: functions to pull the hashes from the Single File Backup tab on R212 of the firmware
# Should be possible on either device


def get_password(dev: DeviceData) -> str:
    """
    For now, returns a static password.

    Was intended to generate passwords dynamically (in the hopes
    of having a different hash appear), but that hash seems to
    depend on the raw contents of the file, as opposed to the
    compressed, encrypted, Base64 representation of the file.
    """

    pw = dev.options.get("password")

    if pw:
        return str(pw)
    else:
        return "Peat!123"


class SystemSettingsPoller:
    """
    Handles queueing and polling the system settings file
    """

    http: HTTP362X
    dev: DeviceData
    old_hash: str
    token: str
    password: str
    current_version: str
    previous_version: str

    def __init__(self, http: HTTP362X, dev: DeviceData):
        self.http = http
        self.dev = dev
        self.old_hash = ""
        self.token = ""
        self.password = ""
        self.current_version = ""
        self.previous_version = ""

    def queue(self) -> bool:
        """
        Queue the generation of the system settings file.
        """

        # TODO: initiate the generation of the Single File Backup on R212 of the firmware.
        #
        # Check `self.dev._cache["VERSION"]` to get the revision of the firmware (int part only)
        # to see if such a file *should* be generated.
        #
        # Additionally, get the hashes of the last generated "single file backup" files.

        log.info("Preparing a configuration file snapshot...")

        info = pull_info(self.http)

        if not info:
            log.error("Failed to pull baseline information about the device")
            return False

        # Old hash and token
        old_hash, self.token = info["old_hash"], info["token"]
        # Get the password from the configuration, if available
        password = get_password(self.dev)
        # Post the endpoint with a request to generate the form
        response = self.http.post_endpoint(
            "file_management",
            files=sys_settings_form_generate(password, self.token, self.dev._cache["VERSION"]),
            headers={"Referer": f"https://{self.http.ip}/{ENDPOINTS['file_management']}"},
        )

        # Handle POST request errors
        if not response:
            log.error("No response")
            return False
        if response.status_code != 200:
            log.error("Could not query setting file creation")
            return False

        # Parse the form and look for a message
        soup = self.http.gen_soup(response.text)
        message = soup.find("div", {"id": "formMessage"})

        if (
            not isinstance(message, Tag)
            or "System Settings file is being generated. This may take a few minutes."
            not in message.get_text()
        ):
            log.error("Could not initiate settings file generation")
            return False

        log.info(
            f'Sent a generation request; the file will be encrypted with the password, "{password}"'
        )
        self.old_hash = old_hash
        self.password = password
        self.current_version = info["current_version"]
        self.previous_version = info["previous_version"]
        self.ss_last_uploaded_hash = info["last_system_settings_import_hash"]
        self.connection_directory_hash = info["connection_directory_hash"]

        return True

    def query_system_settings(self, force: bool = False) -> SystemSettings | bool:
        """
        Query the status of the system settings file.

        Will download it if it is ready. Returns `True` if it's not ready and `False` on error.

        NOTE: Since the SHA-1 hash generated by the device relies on the unencrypted configuration,
        pass `force=true` to this function
        """

        if self.old_hash == "" or self.token == "":
            log.error("Settings not queued!")
            return False

        hash = pull_generated_system_settings_hash(self.http)

        if not force and hash == self.old_hash:
            log.debug("No change to hash")
            return True

        response = self.http.post_endpoint(
            "file_management",
            files=sys_settings_form_export(self.token, self.dev._cache["VERSION"]),
            headers={"Referrer": f"https://{self.http.ip}/{ENDPOINTS['file_management']}"},
        )

        if not response:
            log.error("No response")
            return False

        if response.status_code != 200:
            log.error("Could not pull file")
            return False

        if response.headers["Content-Type"] == "text/html":
            log.error("Incorrect content type")
            return False

        if hash is None:
            log.error("Could not pull hash")
            return False

        gen_time = f"{datetime.now(timezone.utc):%Y%m%dT%H%M%S}"

        if not isinstance(response.content, bytes):
            log.error("Invalid response content type")
            return False

        return SystemSettings(
            prev_sys_settings_hash=self.old_hash,
            curr_sys_settings_hash=hash,
            password=self.password,
            data=response.content.decode(),
            time=gen_time,
            file_name=f"SystemSettings-{gen_time}.bkp",
            current_firmware=self.current_version,
            previous_firmware=self.previous_version,
            last_uploaded_config_hash=self.ss_last_uploaded_hash,
            connection_directory_hash=self.connection_directory_hash,
        )

    # TODO: write a function to pull the single file backup


def initialize_file_management_pull(dev: DeviceData, http: HTTP362X) -> dict[str, Any]:
    """
    Prepares the FileManagement pull. Returns an empty dictionary.
    """
    ssp = SystemSettingsPoller(http, dev)
    if not ssp.queue():  # Attempt to queue the creation of the configuration file
        raise Exception("Failed to queue system file generation")

    dev._cache[SystemSettingsPoller] = ssp

    return {}


def pull_file_management(dev: DeviceData, http: HTTP362X) -> dict[str, Any]:
    """
    Pull data from the "/FileManagement.sel" endpoint.
    """

    ssp = dev._cache[SystemSettingsPoller]

    # Query periodically up to a maximum number of times.
    # Querying this way ensures we do not retrieve an outdated version of the backup
    queries = MAX_QUERIES
    delay = 10
    ssb_opt = dev.options["system_settings_backup"]
    if ssb_opt:
        q = ssb_opt.get("pull_attemts")
        if q:
            queries = int(q)

        d = ssb_opt.get("pull_attempt_delay")
        if d:
            delay = float(d)

    for i in range(0, queries):
        log.debug(f"Query {i + 1} of {queries}...")
        from time import sleep

        sys_settings = ssp.query()
        if isinstance(sys_settings, SystemSettings):
            log.info("Pulled system configuration backup")
            break

        if not sys_settings:
            raise Exception("Error in querying system settings")

        sleep(delay)

    # Odds are, if it has failed after multiple attempts, then there were
    # no changes to the backup file.
    if not isinstance(sys_settings, SystemSettings):
        log.info("Pulling system configuration backup...")
        sys_settings = ssp.query(force=True)
        if not isinstance(sys_settings, SystemSettings):
            raise Exception("Failed to pull the system configuration backup")

    log.info(f"Pulled system configuration (saved as {sys_settings.file_name})")

    # Write, then note.
    dev.write_file(sys_settings.data, sys_settings.file_name)
    dev.related.files.add(sys_settings.file_name)

    return {
        "system_settings_backup": {
            "last_uploaded_hash": sys_settings.last_uploaded_config_hash,
            "old_system_settings_export_hash": sys_settings.prev_sys_settings_hash,
            "new_system_settings_export_hash": sys_settings.curr_sys_settings_hash,
            "file_name": sys_settings.file_name,
            "config_archive": sys_settings.data,
            "password": sys_settings.password,
            "time_pulled": sys_settings.time,
        },
        "firmware": {
            "current_version": sys_settings.current_firmware,
            "previous_version": sys_settings.previous_firmware,
        },
        "connection_directory_config_hash": sys_settings.connection_directory_hash,
    }

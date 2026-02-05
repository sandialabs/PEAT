from __future__ import annotations

import copy
import inspect
import json
import mimetypes
from copy import deepcopy
from datetime import datetime, timedelta
from pathlib import Path, PurePath
from typing import Any, AnyStr, Literal

from pydantic import (
    Field,
    PositiveInt,
    PrivateAttr,
    confloat,
    conint,
    constr,
    validator,
)

import peat
from peat import Elastic, config, consts, state, utils, log
from peat.es_mappings import KEYWORD_AND_TEXT
from peat.consts import SYSINFO, WINDOWS, PeatError
from peat.data.default_options import DEFAULT_OPTIONS
from peat.protocols import (
    address_to_pathname,
    addresses,
    ip_to_mac,
    mac_to_ip,
    mac_to_vendor_string,
)

from .base_model import BaseModel
from .data_utils import (
    DeepChainMap,
    dedupe_model_list,
    match_all,
    merge_models,
    sort_model_list,
    strip_empty_and_private,
    strip_key,
    lookup_by_str,
)
from .validators import (
    clean_protocol,
    cleanstr,
    validate_ecs,
    validate_hash,
    validate_ip,
    validate_mac,
    strip_quotes,
    validate_hex,
    convert_arbitrary_path_to_purepath,
)

# NOTE:
# - values added directly to sets/lists are not validated (e.g. related.*) (TODO: fix this somehow?)
# - validation is done on assignment because validate_assignment is true
# - validation is NOT done when items are added to a default value, e.g. "related.add("hash")"
# - Field(...) is ONLY used for schema customization, validation configuration is done using the type annotation.
# - on export, pydantic preserves the order fields are defined in the models
#     https://github.com/samuelcolvin/pydantic/issues/593#issuecomment-501735842
# https://en.wikipedia.org/wiki/God_object


# Needed for generation of JSON schema + the documentation
@classmethod
def __pathlib_modify_schema__(
    cls, field_schema: dict[str, Any]  # noqa: ARG001
) -> None:
    field_schema.update(type="string", format="path")


PurePath.__modify_schema__ = __pathlib_modify_schema__


class Vendor(BaseModel):
    """
    Identifies a device vendor (SEL, Schneider Electric, Siemens, etc).
    """

    id: constr(strip_whitespace=True) = ""
    """
    Abbreviated version of the vendor name that can be used for lookups.

    Examples

    - ``SEL``
    - ``WindRiver``
    - ``Schneider``
    - ``Siemens``
    - ``Sandia``
    """

    name: constr(strip_whitespace=True) = ""
    """
    The full expanded vendor name.
    Used for display in a visualization or dashboard.

    Examples

    - ``Schweitzer Engineering Laboratories``
    - ``Wind River Systems``
    - ``Schneider Electric``
    """


class Description(BaseModel):
    """
    Identifying information such as vendor, brand, and model.
    """

    brand: constr(strip_whitespace=True) = ""
    """
    Brand of the device.
    Can be empty string if not applicable, such as for most SEL devices.

    Examples

    - ``Modicon``
    - ``PowerLogic ION``
    - ``""``
    """

    contact_info: str = Field(default="", elastic_type=KEYWORD_AND_TEXT)
    """
    Contact info for the device, e.g. an email address, name, or phone number.
    This is commonly retrieved from :term:`SNMP`.
    """

    description: str = Field(default="", elastic_type=KEYWORD_AND_TEXT)
    """
    Free-form description of the device, such as a
    "description" configuration value extracted from the device
    or other general information that is useful to note.
    """

    full: constr(strip_whitespace=True) = Field(
        default="", elastic_type=KEYWORD_AND_TEXT
    )
    """
    Combination of vendor, brand, model, and any other
    identifiers. Used to perform lookups with fuzzy string matching.

    Examples

    - ``Schneider Electric Modicon M340``
    - ``SEL-351S``
    """

    model: constr(strip_whitespace=True) = ""
    """
    Model of the device.

    Examples

    - ``M340``
    - ``351S``
    """

    product: constr(strip_whitespace=True) = Field(
        default="", elastic_type=KEYWORD_AND_TEXT
    )
    """
    The product identifier for the device, minus the vendor.
    This is includes the brand and model.

    Examples

    - ``Modicon M340``
    - ``351S``
    """

    vendor: Vendor = Vendor()
    """The manufacturer/vendor of the device."""

    _strip_quotes = validator("description", "contact_info", allow_reuse=True)(
        strip_quotes
    )


class Hardware(BaseModel):
    """
    Hardware information of the device, e.g. amount of :term:`RAM`.
    """

    cpu: Description = Description()
    """
    Information about the CPU on the device, such as the vendor and model.
    """

    id: constr(strip_whitespace=True) = ""
    """
    Hardware ID of the device.
    """

    storage_available: conint(ge=0) | None = None
    """
    Amount of persistent storage currently available on the device, in bytes.
    """

    storage_usage: conint(ge=0) | None = None
    """
    Amount of persistent storage currently in use on the device, in bytes.
    """

    storage_total: conint(ge=0) | None = None
    """
    Total amount of storage on the device, in bytes.
    """

    storage_type: constr(strip_whitespace=True, to_lower=True) = ""
    """
    Type of storage on the device.

    Values should be lowercase and underscore-separated.

    Examples

    - ``hdd``
    - ``ssd``
    - ``nvram``
    """

    memory_available: conint(ge=0) | None = None
    """
    Amount of volatile memory (e.g. :term:`RAM`) currently available, in bytes.
    """

    memory_usage: conint(ge=0) | None = None
    """
    Amount of volatile memory (e.g. :term:`RAM`) currently in use, in bytes.
    """

    memory_total: conint(ge=0) | None = None
    """
    Total amount of volatile memory (e.g. :term:`RAM`) on the device, in bytes.
    """

    memory_type: constr(strip_whitespace=True, to_lower=True) = ""
    """
    Type of volatile memory on the device, lowercase and underscore-separated.

    Examples

    - ``ddr2_sdram``
    """

    revision: constr(strip_whitespace=True) = ""
    """
    Hardware revision of the device (e.g. MinorRev field in Rockwell L5X).
    This is distinct from the software (e.g., firmware or OS version), and is
    purely for the hardware itself (e.g., the mainboard or module).
    The detailed meaning of the value in this field is device-dependant.
    """

    version: constr(strip_whitespace=True) = ""
    """
    Hardware version of the device (e.g. MajorRev field in Rockwell L5X).
    This is distinct from the software (e.g., firmware or OS version), and is
    purely for the hardware itself (e.g., the mainboard or module).
    The detailed meaning of the value in this field is device-dependant.
    """

    def annotate(self, dev: DeviceData | None = None):  # noqa: ARG002
        # If available + usage are set, and total is not, auto-calculate total
        if not self.memory_total and self.memory_available and self.memory_usage:
            self.memory_total = self.memory_available + self.memory_usage
        if not self.storage_total and self.storage_available and self.storage_usage:
            self.storage_total = self.storage_available + self.storage_usage


class Hash(BaseModel):
    """
    Hashes of raw data or a file.

    .. note::
       All hashes are uppercase hexadecimal strings, per :term:`ECS`
    """

    # NOTE: "Optional" is used here since a default of "" will fail validation checks
    md5: constr(min_length=32, max_length=32, strip_whitespace=True) | None = Field(
        default=None, title="MD5 hash"
    )
    """MD5 hash."""

    sha1: constr(min_length=40, max_length=40, strip_whitespace=True) | None = Field(
        default=None, title="SHA1 hash"
    )
    """SHA1 hash."""

    sha256: constr(min_length=64, max_length=64, strip_whitespace=True) | None = Field(
        default=None, title="SHA256 hash"
    )
    """SHA256 hash."""

    sha512: constr(min_length=128, max_length=128, strip_whitespace=True) | None = (
        Field(default=None, title="SHA512 hash")
    )
    """SHA512 hash."""

    # Validators
    _validate_hash = validator("md5", "sha1", "sha256", "sha512", allow_reuse=True)(
        validate_hash
    )


class User(BaseModel):
    """
    Information describing a user on a device.
    """

    description: constr(strip_whitespace=True) = Field(
        default="", elastic_type=KEYWORD_AND_TEXT
    )
    """
    General description of the user (this is open to interpretation).
    """

    domain: constr(strip_whitespace=True) = ""
    """
    Name of the domain the user is a member of.

    For example, an LDAP or Active Directory domain name.
    """

    # TODO: validation of email? also, use to replace utils.is_email().
    # - https://pypi.org/project/email-validator
    # - EmailStr (https://pydantic-docs.helpmanual.io/usage/types/#pydantic-types)
    email: constr(strip_whitespace=True) = ""
    """
    User email address.

    Examples

    - example@example.com
    """

    full_name: constr(strip_whitespace=True) = Field(
        default="", elastic_type=KEYWORD_AND_TEXT
    )
    """
    The user's full name, if known.

    Examples

    - Billy Bob Joe
    - Administrator
    """

    id: str = ""
    """
    Unique identifier of the user.
    """

    name: constr(strip_whitespace=True) = Field(
        default="", elastic_type=KEYWORD_AND_TEXT
    )
    """
    Short name or login of the user.
    """

    permissions: set[str] = set()
    """
    Permissions the user has available.
    """

    roles: set[str] = set()
    """
    The user's roles, as strings.

    Examples

    - Administrator
    - User
    - engineers
    """

    uid: constr(strip_whitespace=True) = ""
    """
    The user's numeric user ID, if applicable.
    """

    gid: constr(strip_whitespace=True) = ""
    """
    The user's numeric group ID, if applicable.
    """

    extra: dict = Field(default={}, elastic_type="flattened")
    """
    Additional data or metadata about the user.

    This also includes unstructured raw data
    from the device that may be relevant.
    """

    _sort_by_fields: tuple[str] = PrivateAttr(
        default=("id", "name", "full_name", "description")
    )

    def annotate(self, dev: DeviceData | None = None):
        if dev:
            if self.email:
                dev.related.emails.add(self.email)
            if self.full_name:
                dev.related.user.add(self.full_name)
            if self.id:
                dev.related.user.add(self.id)
            if self.name:
                dev.related.user.add(self.name)
            if self.roles:
                for role in self.roles:
                    dev.related.roles.add(role)


class Related(BaseModel):
    """
    Information that is related to a device or interface, or was found on the device.
    """

    emails: set[constr(strip_whitespace=True)] = set()
    """
    Any email addresses related to the device or users on the device.
    """

    files: set[constr(strip_whitespace=True)] = set()
    """
    Any files found on the device or referenced
    from the device's configuration. These can either
    be absolute paths or just filenames. Absolute
    paths are preferred, if known.

    Examples

    - ``/home/user/config.txt``
    - ``config.xml``
    """

    hash: set[str] = set()
    """
    Hashes related to the device or interface.

    Allowed hash types: MD5, SHA1, SHA256, SHA512.
    """

    hosts: set[constr(strip_whitespace=True)] = set()
    """
    Hostnames or names related to the device or interface.
    """

    ip: set[str] = Field(default=set(), elastic_type="ip")
    """
    :term:`IP` addresses related to the device or interface.
    These can be IPv4 or IPv6 addresses.
    """

    mac: set[str] = set()
    """
    :term:`MAC` addresses related to the device or interface.
    """

    ports: set[conint(ge=1, le=65535)] = set()
    """
    :term:`TCP` or :term:`UDP` ports related to the device or interface.
    """

    protocols: set[str] = set()
    """
    Application layer (:term:`OSI` Layer 7) protocols
    related to a device or interface.

    Values should be lowercase, underscore-separated, with no whitespace.

    The format is the same as the ``protocol`` field in
    :class:`~peat.data.models.Interface`.

    Examples

    - ``modbus_tcp``
    - ``dnp3``
    - ``ftp``
    """

    process: set[str] = set()
    """
    Names of processes that are currently running on the device and/or ran at
    some point in the device's history (e.g. obtained from a log file).

    Examples:

    - ``telnetd``
    """

    roles: set[constr(strip_whitespace=True)] = set()
    """
    Authentication roles associated with a device.

    Values should have the same format as they're
    stored on the device.

    Examples

    - ``admin``
    - ``user``
    """

    urls: set[constr(strip_whitespace=True)] = set()
    """
    URLs related to the device or found on the device.
    """

    user: set[constr(strip_whitespace=True)] = set()
    """
    Any usernames related to the device or interface or found on the device.

    For example, this could include users that are logged into a service,
    or users that are configured on the device (e.g., in a config file).
    """

    # Validators
    _validate_ip = validator("ip", allow_reuse=True, each_item=True)(validate_ip)
    _validate_mac = validator("mac", allow_reuse=True, each_item=True)(validate_mac)
    _validate_hash = validator("hash", allow_reuse=True, each_item=True)(validate_hash)


class File(BaseModel):
    """
    Contextual information and metadata for a file.

    The file could be on disk, in memory, a directory, or simply
    represent an artifact that's known to be on the device but
    PEAT doesn't have the ability to access.
    """

    created: datetime | None = None
    """
    File creation time.
    """

    description: constr(strip_whitespace=True) = Field(
        default="", elastic_type=KEYWORD_AND_TEXT
    )
    """
    General human-readable description of what the file is.
    """

    device: constr(strip_whitespace=True) = ""
    """
    Device that is the source of the file. If this is a static
    parse, then it should be the name of the system the file
    was recovered from or parsed on. Otherwise, this should be
    the ID of the device it was pulled from.
    """

    directory: constr(strip_whitespace=True) = ""
    """
    Path to the directory where the file is located.
    """

    extension: constr(strip_whitespace=True) = ""
    """
    File extension, without a leading ``.`` character.

    Examples

    - ``txt``
    - ``tar.gz``
    - ``xml``
    - ``zip``
    """

    hash: Hash = Hash()
    """
    Hashe(s) of the file's contents.
    """

    local_path: Path | None = None
    """
    Concrete path of the file on the local system (the system running PEAT).
    """

    path: PurePath | None = None
    """
    Path of the file, in it's original form. This may be either the
    path to the file on the device, or the path from the system it originated
    from (e.g. as extracted from a project file or using PEAT Pillage).
    """

    peat_module: constr(strip_whitespace=True) = ""
    """
    PEAT module associated with this file artifact.
    """

    gid: constr(strip_whitespace=True) = ""
    """
    Primary group ID (GID) of the file.
    """

    group: constr(strip_whitespace=True) = ""
    """
    File's owning group name.
    """

    mime_type: constr(strip_whitespace=True) = ""
    """
    MIME type should identify the format of the file or stream of bytes using the
    `IANA official types <https://datatracker.ietf.org/doc/html/rfc6838>`__,
    where possible. When more than one type is applicable, the most specific
    type should be used.
    """

    mode: constr(strip_whitespace=True) = ""
    """
    Mode of the file in octal representation.

    Examples:

    - ``0640``
    - ``0644``
    - ``0777``
    """

    mtime: datetime | None = None
    """
    Last time the file content was modified.
    """

    name: constr(strip_whitespace=True) = ""
    """
    File's name, including extension (e.g. ``SET_ALL.txt``).
    """

    original: bytes = b""
    """
    Raw contents of the file.
    """

    owner: constr(strip_whitespace=True) = ""
    """
    File owner's username.
    """

    size: conint(ge=0) | None = None
    """
    Size of the file in bytes.

    Only relevant when ``file.type`` is ``"file"``.
    """

    target_path: PurePath | None = None
    """
    Target path for symlinks.

    Only relevant when ``file.type`` is ``"symlink"``.
    """

    type: Literal["file", "dir", "symlink", ""] = ""
    """
    File type, following the :term:`ECS`.

    **Allowed values**

    - ``file`` : It's a file
    - ``dir`` : It's a directory
    - ``symlink`` : It's a symbolic link
    """

    uid: constr(strip_whitespace=True) = ""
    """
    Numeric user ID (UID) or security identifier (SID) of the file owner.
    """

    extra: dict = Field(default={}, elastic_type="flattened")
    """
    Additional information about the file that
    doesn't fit into the data model.
    """

    _es_index_varname: str = PrivateAttr(default="ELASTIC_FILES_INDEX")
    _sort_by_fields: tuple[str] = PrivateAttr(
        default=(
            "directory",
            "type",
            "name",
            "device",
        )
    )

    # Validators
    @validator("extension", allow_reuse=True)
    def clean_file_extension_string(cls, v):
        return v.strip().lower().strip(".")

    _convert_paths = validator("path", "target_path", allow_reuse=True, pre=True)(
        convert_arbitrary_path_to_purepath
    )

    def annotate(self, dev: DeviceData | None = None):
        # Auto-populate many of the fields
        process_file(self)

        if dev:
            if not self.device and (self.path or self.local_path or self.extension):
                dev_id = dev.get_id()  # Set to current Device ID
                if "unknown-dev-" not in dev_id:
                    self.device = dev_id

            # Add paths to related.files, if it isn't the local path
            # or a path to the same directory on the local system.
            # Technically, this will exclude files collected by a PEAT
            # run on, say, a SCADA server or Engineering Workstation,
            # but the common case is "peat parse" or calling DeviceModule.parse()
            # on a pulled file.
            if (
                self.path
                and self.path != self.local_path
                and (not self.local_path or self.path.parent != self.local_path.parent)
            ):
                dev.related.files.add(self.path.as_posix())
            if self.target_path:
                dev.related.files.add(self.target_path.as_posix())

            _add_hashes_to_related(dev, self.hash)

    def gen_elastic_content(self, dev: DeviceData | None = None) -> dict:
        self.annotate(dev)  # populate fields

        time_now = Elastic.time_now()
        timestamp = time_now
        if self.created is not None:
            timestamp = Elastic.convert_tstamp(self.created)
        elif self.mtime is not None:
            timestamp = Elastic.convert_tstamp(self.mtime)

        content = {
            "@timestamp": timestamp,
            "message": self.description if self.description else str(self.path),
            "tags": ["file"],
            "event": {"ingested": time_now},
            "file": self.dict(exclude_defaults=True),
        }

        if dev:
            # host.{basic fields}
            content["host"] = dev.gen_base_host_fields_content()
            content["tags"].extend(
                [
                    dev.description.vendor.name,
                    dev.description.product,
                ]
            )
            if dev._module:
                content["event"]["module"] = dev._module.__name__
        return content


class Firmware(BaseModel):
    """
    Device firmware.
    """

    checksum: constr(strip_whitespace=True) = ""
    """
    Checksum used by the device to verify the firmware image is valid.
    This is usually found in or with the firmware image file or the
    device configuration.
    """

    extra: dict = Field(default={}, elastic_type="flattened")
    """
    Additional unstructured information related to the firmware,
    generally vendor-specific information such as "settings_version".
    """

    file: File = File()
    """
    Firmware image metadata, such as size, hashes, etc.
    """

    hash: Hash = Hash()
    """
    Hashes of the raw firmware (the contents of ``original``).

    .. note::
       This may differ from the file hash, if present.
    """

    id: constr(strip_whitespace=True) = ""
    """
    Firmware identification string, e.g. the "FID" or "BFID" strings in SEL devices.
    """

    last_updated: datetime | None = None
    """
    The timestamp of when the firmware was last updated on the device.
    """

    original: bytes = b""
    """
    Full raw unmodified binary image of the device's firmware.
    """

    revision: constr(strip_whitespace=True) = ""
    """
    Revision of the device's current firmware (or operating system).
    Common field seen on devices that's sometimes distinct from
    the canonical version string.
    """

    release_date: datetime | None = None
    """
    The release date of the firmware.
    """

    timestamp: datetime | None = None
    """
    Timestamp as extracted from the device or firmware, device-dependent meaning.
    Often represents when the firmware was compiled/built or released.
    """

    version: constr(strip_whitespace=True) = ""
    """
    Version of the device's current firmware (or operating system).
    """

    def annotate(self, dev: DeviceData | None = None):
        if self.original and not _all_hashes_set(self.hash):
            self.hash = Hash.parse_obj(utils.gen_hashes(self.original))

        if dev:
            _add_hashes_to_related(dev, self.hash)

            # !! Hack to set file description properly !!
            if not self.file.description and self.hash.md5:
                if self.hash.md5 == dev.boot_firmware.hash.md5:
                    self.file.description = "Boot firmware for the device"
                else:
                    self.file.description = "Firmware for the device"


class Logic(BaseModel):
    """
    What the device has been programmed to do (it's "logic").

    In a :term:`PLC`, the logic is one or more of the five `IEC 61181-3
    <https://en.wikipedia.org/wiki/IEC_61131-3>`_  languages:

    - Ladder Diagram (LD)
    - Function Block Diagram (FBD)
    - Structured Text (ST)
    - Instruction List (IL)
    - Sequential Function Chart (SFC)

    In a Relay, the logic is the protection schemes.

    In a Power Meter, the logic is the programmed metering/monitoring setpoints.

    .. note::
       Logic is separate from protocol register mappings or values, such as
       Modbus or DNP3, as well as memory values. There is sometimes overlap,
       as some devices have been known to store their logic as e.g. a set
       of Modbus registers.
    """

    author: constr(strip_whitespace=True) = Field(
        default="", elastic_type=KEYWORD_AND_TEXT
    )
    """
    Name of the person/organization/program that wrote the logic.
    """

    created: datetime | None = None
    """
    :term:`UTC` timestamp of when the logic was first created (when the source
    project file was created) or fist uploaded to the device.
    """

    description: str = Field(default="", elastic_type=KEYWORD_AND_TEXT)
    """
    Description for the logic or project file.
    """

    file: File = File()
    """
    File or directory of the logic.
    """

    formats: dict[str, AnyStr | dict] = Field(default={}, elastic_type="nested")
    """
    Sub-formats the logic has been parsed into, such as
    ``"structured_text"`` or ``"tc6"``. Device dependent.
    """

    hash: Hash = Hash()
    """
    Hashes of the raw unparsed logic (the contents of``original``).

    .. note::
       This may differ from the file hash, if present.
    """

    id: constr(strip_whitespace=True) = ""
    """
    Project ID or a similar identifier for the logic,
    e.g. a machine-generated :term:`UUID` for the logic stored by the device.
    """

    last_updated: datetime | None = None
    """
    :term:`UTC` timestamp of when the logic was last updated on the device.
    """

    name: constr(strip_whitespace=True) = Field(
        default="", elastic_type=KEYWORD_AND_TEXT
    )
    """
    Project name or other such identifier for the logic,
    e.g. a human-readable name for the logic stored by the device.
    """

    original: str = Field(default="", elastic_type="text")
    """
    Unparsed device program logic, in whatever format makes sense for
    that device. It is the file(s) that make up the process state logic,
    e.g., the ladder logic on a :term:`PLC` or the configured protection
    schemes on a substation relay.
    """

    parsed: str = Field(default="", elastic_type="text")
    """
    Complete parsed device program logic, in whatever format makes
    sense for that device. It is the file(s) that make up the process
    state logic, e.g., the ladder logic on a :term:`PLC` or the configured
    protection schemes on a substation relay.
    """

    _strip_quotes = validator(
        "author", "description", "name", "id", "parsed", allow_reuse=True
    )(strip_quotes)

    def annotate(self, dev: DeviceData | None = None):
        if self.original and not _all_hashes_set(self.hash):
            self.hash = Hash.parse_obj(utils.gen_hashes(self.original))
        if dev:
            _add_hashes_to_related(dev, self.hash)


class CertEntity(BaseModel):
    """
    Issuer or Subject in a x509 certificate.

    `ECS documentation: x509 Certificate Fields <https://www.elastic.co/guide/en/ecs/current/ecs-x509.html>`__
    """

    common_name: constr(strip_whitespace=True) = ""
    """Common name (CN)."""

    country: constr(strip_whitespace=True) = ""
    """Country code."""

    distinguished_name: constr(strip_whitespace=True) = ""
    """Distinguished Name (DN)."""

    locality: constr(strip_whitespace=True) = ""
    """Locality (L)."""

    organization: constr(strip_whitespace=True) = ""
    """Organization (O)."""

    organizational_unit: constr(strip_whitespace=True) = ""
    """Organizational Unit (OU)."""

    state_or_province: constr(strip_whitespace=True) = ""
    """State or province names (ST, S, or P)."""


class X509(BaseModel):
    """
    x509 certificate.

    `ECS documentation: x509 Certificate Fields <https://www.elastic.co/guide/en/ecs/current/ecs-x509.html>`__
    """

    alternative_names: list[constr(strip_whitespace=True)] = []
    """List of subject alternative names (SAN)."""

    hash: Hash = Hash()
    """Hashes of raw certificate contents (the data stored in ``original``)."""

    issuer: CertEntity = CertEntity()
    """Issuing certificate authority."""

    not_after: datetime | None = None
    """Time at which the certificate is no longer considered valid."""

    not_before: datetime | None = None
    """Time at which the certificate is first considered valid."""

    original: str = ""
    """The raw certificate data."""

    public_key_algorithm: constr(strip_whitespace=True) = ""
    """Algorithm used to generate the public key."""

    public_key_curve: constr(strip_whitespace=True) = ""
    """The curve used by the elliptic curve public key algorithm."""

    public_key_exponent: conint(ge=0) | None = None
    """Exponent used to derive the public key."""

    public_key_size: conint(ge=0) | None = None
    """The size of the public key space in bits."""

    serial_number: constr(strip_whitespace=True) = ""
    """
    Unique serial number issued by the certificate authority.

    For consistency, if this value is alphanumeric, it should be
    formatted without colons and uppercase characters.
    """

    signature_algorithm: constr(strip_whitespace=True) = ""
    """Identifier for certificate signature algorithm."""

    subject: CertEntity = CertEntity()
    """Certificate subject."""

    version_number: constr(strip_whitespace=True) = ""
    """Version of x509 format."""

    def annotate(self, dev: DeviceData | None = None):
        if self.original and not _all_hashes_set(self.hash):
            self.hash = Hash.parse_obj(utils.gen_hashes(self.original))

        if dev:
            _add_hashes_to_related(dev, self.hash)

            if self.alternative_names:
                for an in self.alternative_names:
                    if utils.is_ip(an):
                        dev.related.ip.add(an)
                    elif utils.is_email(an):
                        dev.related.emails.add(an)

            if "://" in self.issuer.common_name:
                dev.related.urls.add(self.issuer.common_name)
            if "://" in self.subject.common_name:
                dev.related.urls.add(self.subject.common_name)


class UEFIHash(BaseModel):
    """
    UEFI model that specifically labels objects from a UEFI file hash file.
    This model is different because it includes all file systems, not just
    the EFI File system

    File system is either FS0 or FS1
    pathname is the pathname of the files in the file system
    hash is the SHA256 hash of the files computed via python script
    """

    file_system: str = ""
    pathname: str = ""
    hash: str = ""
    _es_index_varname: str = PrivateAttr(default="ELASTIC_UEFI_HASHES_INDEX")
    _sort_by_fields: tuple[str] = PrivateAttr(
        default=("file_system", "pathname", "hash")
    )

    def gen_elastic_content(self, dev: DeviceData | None = None) -> dict:
        self.annotate(dev)  # populate fields
        time_now = Elastic.time_now()
        content = {
            # @timestamp is the time mentioned above
            "@timestamp": time_now,
            "event": {"ingested": Elastic.time_now()},
            "uefi": self.dict(exclude_defaults=True),
        }
        if dev:
            # host.{basic fields}
            content["host"] = dev.gen_base_host_fields_content()
            if dev._module:
                content["event"]["module"] = dev._module.__name__
        return content


class UEFIFile(BaseModel):
    """
    UEFI model that specifically labels objects from a UEFIExtract report file.
    This model is different because it includes only the SPI file system
    included in an SPI file dump
    type is the type of entry. Examples are "Region, Volume"
    subtype is the subtype of the entry. Can be blank, can be empty or invalid
    base is the start of location in memory in HEX
    Size is the end of location in memory in HEX
    CRC32 is the calculate crc32 for the file
    Name is the name of the file
    path is the path of the file since the dumps are given in a file like
    structure
    """

    type: str = ""
    subtype: str = ""
    base: str = ""
    size: str = ""
    crc32: str = ""
    guid: str | None = ""  # Only occasionally exists
    name: str = ""
    path: str = ""
    created: datetime | None = None
    _es_index_varname: str = PrivateAttr(default="ELASTIC_UEFI_FILES_INDEX")
    _sort_by_fields: tuple[str] = PrivateAttr(default=("name", "subtype", "type"))

    def gen_elastic_content(self, dev: DeviceData | None = None) -> dict:
        self.annotate(dev)  # populate fields
        time_now = Elastic.time_now()
        content = {
            # @timestamp is the time mentioned above
            "@timestamp": time_now,
            "event": {"ingested": Elastic.time_now()},
            "uefi": self.dict(exclude_defaults=True),
        }
        if dev:
            # host.{basic fields}
            content["host"] = dev.gen_base_host_fields_content()
            if dev._module:
                content["event"]["module"] = dev._module.__name__
        return content


class Service(BaseModel):
    """
    Communication protocol "service" configured or running on the device.

    Services can be over a variety of transports, including IP/Ethernet,
    serial direct, cellular, serial bus, field bus, etc.
    """

    configured_port: conint(ge=0, le=65535) | None = None
    """
    Port the service is *configured* to listen on (for TCP or UDP transports).

    This field should only be set from values read from a device configuration,
    e.g. a config file, config dump, project file, etc. It should NOT be set
    using information from a live port list, scanning, etc.

    This is intended to supplement the "port" field, e.g. if the listening
    port differs from what's in the config, that's forensically interesting.

    .. note::
       The value must be between 0 and 65,535. Port 0 is allowed for
       the ``configured_port`` field, but not the ``port`` field, since
       there may be cases when it's set to 0 in a config (e.g. to disable).

    Examples

    - ``80``
    - ``161``
    - ``502``
    """

    enabled: bool | None = None
    """
    If the service is enabled in the device configuration.

    .. warning::
       This can differ from ``status``, don't assume they will match!
    """

    extra: dict = Field(default={}, elastic_type="flattened")
    """
    Additional unstructured information about the service, such as a
    banner grab, odd behavior, or other miscellaneous data.
    """

    listen_address: str = Field(default="", elastic_type="ip")
    """
    IP address the service is listening on.
    """

    listen_interface: str = ""
    """
    Network interface or serial port the service is listening on.
    """

    process_name: str = ""
    """
    Name of the system process or task associated with the service.
    """

    process_pid: conint(ge=0) | None = None
    """
    Process ID associated with the service. This is the PID of the
    network service's process.
    """

    port: conint(ge=1, le=65535) | None = None
    """
    Port the service is listening on (for TCP or UDP transports).

    .. note::
       The value must be between 1 and 65,535. While a port of ``0`` is
       technically accurate, it's not allowed since it's not something
       that should be seen in the real world, and if it is, then there's
       probably a bug in PEAT or one of it's modules.

    Examples

    - ``80``
    - ``161``
    - ``502``
    """

    protocol: constr(strip_whitespace=True, to_lower=True) = ""
    """
    Protocol name of the service. Must be lowercase with underscore
    separators. Format will be automatically checked and enforced.
    This is a short name or acronym, not an expanded or colloquial name.

    Examples

    - ``http``
    - ``snmp``
    - ``modbus_tcp``
    - ``icmp``
    """

    protocol_id: constr(strip_whitespace=True) = ""
    """
    Unique protocol identifier for the device, such as the Modbus Unit ID.

    Examples

    - ``"10"``
    - ``"119"``
    """

    role: constr(strip_whitespace=True) = ""
    """
    The operational role of the device for a given protocol.
    """

    status: Literal["open", "closed", "verified", ""] = ""
    """
    State of the service.

    .. note::
       ``verified`` means verified over the a live
       connection, not just read from a configuration file. Instead, the
       ``enabled`` field should be used to reflect the configuration state.

    Valid values

    - ``open``: something is listening, though it may not be the named service
    - ``closed``: port is not able to be accessed.
    - ``verified``: service was positively identified (high certainty)
    - ``""``: the live status is unknown, such as when seen in
        a configuration or project file parsed offline.
    """

    transport: constr(strip_whitespace=True, to_lower=True) = ""
    """
    :term:`OSI` Layer 4 transport protocol.

    Examples

    - ``udp``
    - ``tcp``
    - ``icmp``
    """

    _sort_by_fields: tuple[str] = PrivateAttr(
        default=("port", "protocol", "transport", "status", "enabled")
    )

    # Validators
    _clean_protocol = validator("protocol", allow_reuse=True)(clean_protocol)
    _validate_ip = validator("listen_address", allow_reuse=True)(validate_ip)

    def annotate(self, dev: DeviceData | None = None):
        # auto-populate "transport" field if it's unset and protocol is set
        if not self.transport and self.protocol:
            if self.protocol in [
                "telnet",
                "ftp",
                "http",
                "https",
                "modbus_tcp",
                "postgres",
                "smtp",
            ]:
                self.transport = "tcp"
            elif self.protocol in ["snmp", "sntp"]:
                self.transport = "udp"

        if dev:
            if self.port and (
                self.enabled or self.status in ["open", "verified"] or not self.status
            ):
                dev.related.ports.add(self.port)

            if self.protocol and (
                self.enabled or self.status in ["open", "verified"] or not self.status
            ):
                dev.related.protocols.add(self.protocol)


class Interface(BaseModel):
    """
    Communication interface, such as a Ethernet port or Serial link.

    .. note::
       Currently, the ``ip``, ``subnet_mask``, and ``gateway`` fields are
       assumed to be :term:`IP` version 4 (IPv4). However, they can and
       will hold IPv6 values in the future when PEAT adds IPv6 support.
    """

    alias: str = ""
    """
    Interface alias as reported by the system, typically used in firewall implementations for e.g. inside, outside, or dmz logical interface naming.
    """

    application: str = ""
    """
    Higher-level communication protocol being used regardless
    of whether the device is connected via serial or :term:`IP`.

    This field should be lowercase and without separators, when
    possible, or with underscore (``_``) separators otherwise.

    Examples

    - ``modbus``
    - ``dnp3``
    - ``sel``
    """

    connected: bool | None = None
    """
    If the interface is currently connected to something
    (e.g. carrier signal on Ethernet or connected to a
    tower for wireless interfaces).
    """

    description: Description = Description()
    """
    Identifying information for the interface's hardware or
    software, such as vendor, brand, and model.
    """

    duplex: Literal["half", "full", "auto", ""] = ""
    """
    Duplex mode for Ethernet interfaces.

    Allowed values

    - half
    - full
    - auto
    - "" (empty string)
    """

    enabled: bool | None = None
    """
    If the interface is enabled in the device's configuration.
    """

    extra: dict = Field(default={}, elastic_type="flattened")
    """
    Additional unstructured information related to the interface,
    generally this is vendor-specific information.
    """

    name: constr(strip_whitespace=True) = ""
    """
    Interface name, as defined by the device.

    For example, SEL relays refer to the serial and network
    ports by names such as ``1``, ``2``, ``3``, or ``F``.

    Examples

    - ``PF``
    - ``ens0``
    - ``eth1``
    - ``F``
    """

    type: str = ""
    """
    The type of physical communication medium the communication
    interface utilizes. Lowercase, underscore separators.

    Examples

    - ``ethernet``
    - ``loopback``
    - ``point_to_point``
    - ``rs_232``
    - ``rs_422``
    - ``rs_485``
    - ``usb``
    """

    hostname: constr(strip_whitespace=True) = ""
    """
    Hostname of the network interface.

    Examples

    - ``some-relay.local``
    """

    mac: str = ""
    """
    The IEEE 802 standard 48-bit :term:`MAC` address of the interface.
    This is the current MAC address used by the interface.

    Only applicable to Ethernet-type interfaces.
    The MAC address is formatted as a uppercase colon-separated string.

    Examples

    - ``00:00:00:FF:FF:FF``
    """

    mac_vendor: str = Field(default="", elastic_type=KEYWORD_AND_TEXT)
    """
    Vendor name resolved from the :term:`MAC` address :term:`OUI`.

    This field is auto-populated by PEAT if the ``mac`` field is set.
    """

    mtu: PositiveInt | None = Field(default=None, elastic_type="integer")
    """
    Maximum Transmission Unit (MTU) size configured for the interface.
    This generally only applies to Ethernet interfaces.
    """

    physical: bool | None = None
    """
    If the interface is a physical interface (e.g. is a port on the device).
    If false, then it's likely a virtual interface or software-defined.
    Use the "type" and "description" fields to store additional details.
    """

    promiscuous_mode: bool | None = None
    """
    If the interface is in Promiscuous Mode (passive capture).
    """

    speed: conint(ge=0) | None = Field(default=None, elastic_type="integer")
    """
    Transmission rate of the interface, in Mbps (megabits per second).
    Example: for Gigabit Ethernet, this would be 1000.
    """

    uptime: timedelta | None = None
    """
    How long the interface has been connected, in milliseconds or
    as a :class:`~datetime.timedelta` instance.

    NOTE: normal integers can be assigned to this! (e.g. ``iface.uptime = 123``)
    """

    hardware_mac: str = ""
    """
    The hardware :term:`MAC` address of the interface.
    This is intrinsic to the physical :term:`NIC`, and may differ from the
    :term:`MAC` address currently in use by the interface.

    Only applicable to Ethernet-type interfaces.
    The MAC address is formatted as a uppercase colon-separated string.

    Examples

    - ``00:00:00:FF:FF:FF``
    """

    id: constr(strip_whitespace=True) = ""
    """
    Identifier for the interface. The meaning of this value is
    device-dependent.
    """

    ip: str = Field(default="", elastic_type="ip")
    """
    The :term:`IP` address of the interface. This is usually applicable
    to Ethernet-type interfaces, but could be applicable to Serial
    interfaces as well (e.g. on SEL devices).

    Examples

    - ``192.0.2.123``
    """

    subnet_mask: str = Field(default="", elastic_type="ip")
    """
    :term:`IP` subnet mask of the interface.

    Examples

    - ``255.255.255.0``
    - ``255.255.255.192``
    """

    gateway: str = Field(default="", elastic_type="ip")
    """
    IPv4 address of the default gateway of the interface.

    Examples

    - ``192.0.2.1``
    """

    serial_port: constr(strip_whitespace=True) = ""
    """
    Serial port on the local system connected to the device.
    This could be a Windows COM port, e.g. ``COM4``, or a Linux file
    path, e.g. ``/dev/ttyS0``. This is also used for USB connections.

    Examples

    - ``COM4``
    - ``/dev/ttyS0``
    - ``/dev/ttyUSB0``
    """

    baudrate: PositiveInt | None = Field(default=None, elastic_type="integer")
    """
    Data rate for a serial link.

    Examples

    - ``56700``
    """

    data_bits: conint(ge=0) | None = Field(default=None, elastic_type="byte")
    """
    Number of data bits for a serial link.

    Examples

    - ``8``
    """

    parity: Literal["none", "even", "odd", ""] = ""
    """
    Parity setting for a serial link.

    Allowed values

    - none
    - even
    - odd
    - "" (empty string)
    """

    stop_bits: conint(ge=0) | None = Field(default=None, elastic_type="byte")
    """
    Number of stop bits for a serial link.

    Examples

    - 0
    - 1
    """

    flow_control: str = ""
    """
    Flow control setting for a serial link.

    Should be ``none`` or ``rts/cts`` in most cases.

    Examples

    - none
    - rts/cts
    """

    services: list[Service] = []
    """
    Communication protocols configured or running on the interface.
    """

    version: str = ""
    """
    Version of the interface's firmware or software.
    """

    _sort_by_fields: tuple[str] = PrivateAttr(
        default=("name", "type", "ip", "serial_port", "id", "application")
    )

    # Validators
    _clean_str = validator(
        "application", "type", "parity", "flow_control", allow_reuse=True
    )(cleanstr)
    _validate_ip = validator("ip", "subnet_mask", "gateway", allow_reuse=True)(
        validate_ip
    )
    _validate_mac = validator("mac", "hardware_mac", allow_reuse=True)(validate_mac)
    _strip_quotes = validator("description", allow_reuse=True)(strip_quotes)

    def annotate(self, dev: DeviceData | None = None):
        # Resolve host if not set OR if IP is changed and host is not
        if config.RESOLVE_HOSTNAME and (self.ip and not self.hostname):
            self.hostname = addresses.resolve_ip_to_hostname(self.ip)

        # Resolve IP from MAC (may make an ARP request)
        if config.RESOLVE_IP and self.mac and not self.ip:
            self.ip = mac_to_ip(self.mac)

        # Resolve IP from hostname (may make a DNS request or broadcast)
        if config.RESOLVE_IP and self.hostname and not self.ip:
            self.ip = addresses.resolve_hostname_to_ip(self.hostname)

        # Resolve MAC from IP
        if config.RESOLVE_MAC and self.ip and not self.mac:
            self.mac = addresses.clean_mac(ip_to_mac(self.ip))

        if self.mac and not self.mac_vendor:
            self.mac_vendor = mac_to_vendor_string(self.mac)

        # Add to the host's "related" fields
        if dev:
            if self.ip and self.ip not in dev.related.ip:
                dev.related.ip.add(self.ip)

            if self.mac and self.mac not in dev.related.mac:
                dev.related.mac.add(addresses.clean_mac(self.mac))

            if self.hardware_mac and self.hardware_mac not in dev.related.mac:
                dev.related.mac.add(addresses.clean_mac(self.hardware_mac))

            if self.gateway and self.gateway not in dev.related.ip:
                # sanity check
                if utils.is_ip(self.gateway):
                    dev.related.ip.add(self.gateway)

            if self.hostname and self.hostname not in dev.related.hosts:
                dev.related.hosts.add(self.hostname)


class Register(BaseModel):
    """
    Configured I/O protocol data point ("registers"), e.g. DNP3 or Modbus/TCP.
    """

    address: constr(strip_whitespace=True) = ""
    """
    Address of the data. Tells protocol parser how to identify a
    data field in a packet. A number, string, or more complex identifier.
    For Object Oriented protocols, this field flattens the data_address.

    Examples

    - ``12``
    - ``123456``
    - ``pump-jack-six-example``
    - ``device-example_1234_trend-log``
    """

    data_type: str = ""
    """
    Data type of the register.  Tells the user or code reading
    our data how to interpret the field. Format: Lowercase,
    underscore-separated string.

    Examples

    - ``float_16``
    - ``string``
    - ``int_32``
    """

    description: str = Field(default="", elastic_type="text")
    """
    Human-readable description of the register (some device
    configurations or project files have this).

    Examples

    - ``"Intake Fuel - Valve 1 - Second Boiler"``
    """

    enabled: bool | None = None
    """
    If the register is considored to be "enabled", e.g. has a valid configuration
    or is otherwise enabled for use on the device.
    """

    extra: dict = Field(default={}, elastic_type="flattened")
    """
    Additional metadata for the register.
    """

    group: constr(strip_whitespace=True) = ""
    """
    Logical mapping or settings group (e.g. on SEL relays) associated
    with the Register.

    Examples:

    - D1
    - D3
    - M
    - DNPA
    """

    io: constr(strip_whitespace=True) = ""
    """
    I/O point it's attached to (e.g. protocol register or physical I/O).

    This allows direct reference to an IO object without requiring a Tag.

    Examples

    - ``rtu-8_I0``
    """

    measurement_type: constr(strip_whitespace=True) = ""
    """
    Type of information the register is tracking
    (e.g analog I/O, Discrete I/O). Tells analytic which algorithms
    to deploy. For example, in Modbus a 16-bit register can track an
    event count (Discrete), a temperature (analog), or could be a set
    of 16 Boolean flags (alarms).

    Examples

    - ``analog``
    - ``binary``
    """

    name: constr(strip_whitespace=True) = ""
    """
    Name or unique descriptor of the register
    (if different from the address).

    Examples

    - ``AI_99``
    - ``MOD_005``
    """

    protocol: str = ""
    """
    The Parser uses this to distinguish protocols. Not all
    vendors follow the protocol spec. To indicate if this is a vendor-
    specific deviation from the standard, use the syntax
    ``[protocol]_[device or vendor name]``.

    Examples

    - ``dnp3``
    - ``modbus``
    """

    read_write: Literal["read", "write", "read_write", ""] = ""
    """
    Direction of information flow. Is register read, write, or both?

    **Allowed values**

    - ``read``
    - ``write``
    - ``read_write``
    """

    tag: constr(strip_whitespace=True) = ""
    """
    Register tag given in config file. Provides analytic with some
    register context. May be a human-readable display name.

    Examples

    - ``valve_1``
    """

    _es_index_varname: str = PrivateAttr(default="ELASTIC_REGISTERS_INDEX")
    _sort_by_fields: tuple[str] = PrivateAttr(
        default=("protocol", "group", "measurement_type", "tag", "io", "read_write")
    )

    # Validators
    _cleanstr = validator("protocol", "data_type", allow_reuse=True)(cleanstr)
    _clean_protocol = validator("protocol", allow_reuse=True)(clean_protocol)
    _strip_quotes = validator("description", allow_reuse=True)(strip_quotes)

    def __lt__(self, other):
        """
        Allows for sorting of objects.
        """
        return (self.protocol, self.measurement_type, self.address, self.tag) < (
            other.protocol,
            other.measurement_type,
            other.address,
            other.tag,
        )

    def gen_elastic_content(self, dev: DeviceData | None = None) -> dict:
        self.annotate(dev)  # populate fields

        # Hacky way to make a nice fancy message describing the Register
        message = ""
        if self.description and self.protocol and self.tag:
            message = f"{self.protocol} - {self.tag} - {self.description}"
        elif self.description and self.protocol:
            message = f"{self.protocol} - {self.description}"
        elif self.description and self.tag:
            message = f"{self.tag} - {self.description}"
        elif self.description:
            message = self.description
        else:
            if self.protocol:
                message += self.protocol
            if self.tag:
                if message:
                    message += " - "
                message += self.tag
            if self.read_write and len(message) < 80:
                if message:
                    message += " - "
                message += self.read_write
            if self.measurement_type and len(message) < 80:
                if message:
                    message += " - "
                message += self.measurement_type
            if self.data_type and len(message) < 80:
                if message:
                    message += " - "
                message += self.data_type

        time_now = Elastic.time_now()
        # TODO: include service information related to the protocol?
        # e.g. if DNP3, include info from DNP3 Service in dev.services
        content = {
            "@timestamp": time_now,
            "message": message,
            "tags": ["register"],
            "event": {"ingested": time_now},
            "register": self.dict(exclude_defaults=True),
        }
        if dev:
            # host.{basic fields}
            content["host"] = dev.gen_base_host_fields_content()
            content["tags"].extend(
                [
                    dev.description.vendor.name,
                    dev.description.product,
                ]
            )
            if dev._module:
                content["event"]["module"] = dev._module.__name__
        return content


class Tag(BaseModel):
    """
    Variable in a :term:`ICS`/:term:`OT` device, often mapping to physical I/O.

    These are commonly stored in a "tag database" in a :term:`SCADA` system or
    the configuration of a device.
    """

    address: constr(strip_whitespace=True) = ""
    """
    Address of the tag.

    Examples

    - ``29``
    """

    description: str = Field(default="", elastic_type="text")
    """
    Human-readable description of the tag.
    """

    io: constr(strip_whitespace=True) = ""
    """
    I/O point it's attached to (e.g. protocol register or physical I/O).

    Examples

    - ``rtu-8_I0``
    """

    name: constr(strip_whitespace=True) = ""
    """
    Tag name or label (e.g. how it's referenced).

    Examples

    - ``var_rtu-8_I0``
    """

    type: str = ""
    """
    Data type of the tag, lowercase and underscore-separated.

    Examples

    - ``analog``
    - ``binary``
    """

    _es_index_varname: str = PrivateAttr(default="ELASTIC_TAGS_INDEX")
    _sort_by_fields: tuple[str] = PrivateAttr(default=("type", "address", "name", "io"))

    # Validators
    _cleanstr = validator("type", allow_reuse=True)(cleanstr)
    _strip_quotes = validator("description", allow_reuse=True)(strip_quotes)

    def __lt__(self, other):
        """Allows for sorting of objects."""
        return (self.type, self.name, self.address) < (
            other.type,
            other.name,
            other.address,
        )

    def gen_elastic_content(self, dev: DeviceData | None = None) -> dict:
        self.annotate(dev)  # populate fields
        # Hacky way to make a nice fancy message describing the Tag
        message = ""
        if self.description and self.name:
            message = f"{self.name} - {self.description}"
        elif self.description and self.io:
            message = f"{self.io} - {self.description}"
        elif self.description:
            message = self.description
        else:
            if self.name:
                message += self.name
            elif self.io:
                message += self.io
            if self.type and len(message) < 80:
                if message:
                    message += " - "
                message += self.type
        time_now = Elastic.time_now()
        content = {
            "@timestamp": time_now,
            "message": message,
            "tags": ["tag"],
            "event": {"ingested": time_now},
            "tag": self.dict(exclude_defaults=True),
        }
        if dev:
            # host.{basic fields}
            content["host"] = dev.gen_base_host_fields_content()
            content["tags"].extend(
                [
                    dev.description.vendor.name,
                    dev.description.product,
                ]
            )
            if dev._module:
                content["event"]["module"] = dev._module.__name__
        return content


class IO(BaseModel):
    """
    Physical Input/Output (I/O) connections on a device.

    Physical I/O points are distinct from :class:`~peat.data.models.Register`,
    which handle communication protocols and may not necessarily map to physical I/O.

    Physical I/O points are typically referenced by a :class:`~peat.data.models.Tag`,
    though this may not always be the case.

    On module-based devices like a :term:`PLC`, Physical I/O points may be associated
    with a module, however this may not always be the case.
    """

    address: constr(strip_whitespace=True) = ""
    """
    Address of the I/O point (if applicable).

    Examples

    - ``29``
    """

    description: str = Field(default="", elastic_type="text")
    """
    Human-readable description of the I/O point.
    """

    direction: Literal["input", "output", ""] = ""
    """
    Direction of the I/O point.

    **Allowed values**

    - ``input``
    - ``output``
    """

    extra: dict = Field(default={}, elastic_type="flattened")
    """
    Additional metadata for the I/O point.
    """

    id: constr(strip_whitespace=True) = ""
    """
    ID of the I/O point.

    Examples

    - ``rtu-1_I16``
    - ``O0``
    """

    name: constr(strip_whitespace=True) = ""
    """
    I/O point name or label (typically referenced by a :class:`~peat.data.models.Tag`).

    Examples

    - ``var_rtu-1_I16``
    """

    type: constr(strip_whitespace=True) = ""
    """
    Data type of the I/O point. Possible values are device-dependent.

    Examples

    - ``analog``
    - ``binary``
    - ``EBOOL``
    - ``DATE``
    """

    slot: list[constr(strip_whitespace=True)] = []
    """
    Slot number(s) of the module(s) the point is associated with, if any.
    """

    _es_index_varname: str = PrivateAttr(default="ELASTIC_IO_INDEX")
    _sort_by_fields: tuple[str] = PrivateAttr(
        default=("name", "direction", "id", "address", "type")
    )

    # Validators
    _cleanstr = validator("direction", allow_reuse=True)(cleanstr)
    _strip_quotes = validator("description", allow_reuse=True)(strip_quotes)

    def __lt__(self, other):
        """Allows for sorting of objects."""
        return (self.type, self.direction, self.name, self.id, self.address) < (
            other.type,
            other.direction,
            other.name,
            self.id,
            other.address,
        )

    def gen_elastic_content(self, dev: DeviceData | None = None) -> dict:
        self.annotate(dev)  # populate fields
        # Hacky way to make a nice fancy message describing the IO point
        message = ""
        if self.description and self.name:
            message = f"{self.name} - {self.description}"
        elif self.description and self.id:
            message = f"{self.id} - {self.description}"
        elif self.description:
            message = self.description
        else:
            if self.name:
                message += self.name
            elif self.id:
                message += self.id
            if self.type and len(message) < 80:
                if message:
                    message += " - "
                message += self.type
            if self.direction and len(message) < 80:
                if message:
                    message += " - "
                message += self.direction
        time_now = Elastic.time_now()
        content = {
            "@timestamp": time_now,
            "message": message,
            "tags": ["io"],
            "event": {"ingested": time_now},
            "io": self.dict(exclude_defaults=True),
        }
        if dev:
            # host.{basic fields}
            content["host"] = dev.gen_base_host_fields_content()
            content["tags"].extend(
                [
                    dev.description.vendor.name,
                    dev.description.product,
                ]
            )
            if dev._module:
                content["event"]["module"] = dev._module.__name__
        return content


class LatLon(BaseModel):
    """
    Latitude and Longitude (geographical coordinates).
    """

    # NOTE: floats in JSON schema are "number", so we define ES type here as "double"
    lat: confloat(ge=-90.0, le=90.0) | None = Field(
        default=None, title="Latitude", elastic_type="double"
    )
    """
    Latitude.
    """

    lon: confloat(ge=-180.0, le=180.0) | None = Field(
        default=None, title="Longitude", elastic_type="double"
    )
    """
    Longitude.
    """


class Geo(BaseModel):
    """
    Geolocation information (the device's physical location).
    """

    city_name: constr(strip_whitespace=True) = ""
    """
    Name of the city where the device is physically located.

    Examples

    - ``Albuquerque``
    """

    country_name: constr(strip_whitespace=True) = ""
    """
    Name of the country where the device is physically
    located, in whatever form is reasonable.

    Examples

    - ``USA``
    - ``United States of America``
    - ``Canada``
    """

    location: LatLon = Field(default=LatLon(), elastic_type="geo_point")
    """
    Latitude ("lat") and Longitude ("lon") of the device's physical location.
    """

    name: constr(strip_whitespace=True) = ""
    """
    Custom location name, as retrieved from the device.

    Examples

    - ``abq-dc``
    - ``1st floor network closet``
    """

    timezone: constr(strip_whitespace=True) = ""
    """
    Timezone configured for the device.

    Acceptable timezone formats are: a canonical ID (e.g. ``America/Denver``)
    or abbreviated (e.g. ``EST``). Canonical ID is preferred for PEAT.

    Examples

    - ``America/Denver``
    - ``Etc/UTC``
    - ``EST``
    - ``MST``
    - ``UTC``
    """


class Event(BaseModel):
    """
    Device log entry, such as logins, metering reads, or system events.
    """

    action: constr(strip_whitespace=True, to_lower=True) = Field(
        default="", elastic_type=KEYWORD_AND_TEXT
    )
    """
    Type of event.

    Examples

    - ``alarm``
    """

    category: set[str] = set()
    """
    :term:`ECS` category of the event, out of the
    `allowed values defined by ECS <https://www.elastic.co/guide/en/ecs/current/ecs-allowed-values-event-category.html>`__.
    This is a set of values, and is an array in Elasticsearch, which allows
    for Kibana queries such as ``host.event.type:alert and host.event.category:authentication``.

    Allowed values

    - ``authentication``
    - ``configuration``
    - ``database``
    - ``driver``
    - ``file``
    - ``host``
    - ``iam``
    - ``intrusion_detection``
    - ``malware``
    - ``network``
    - ``package``
    - ``process``
    - ``registry``
    - ``session``
    - ``web``
    """

    created: datetime | None = None
    """
    When the event occurred.
    """

    dataset: constr(strip_whitespace=True) = ""
    """
    What log the event came from. This is especially important on devices
    with multiple log types.

    Examples

    - ``metering_reads``
    """

    extra: dict = Field(default={}, elastic_type="flattened")
    """
    Other event metadata that doesn't fit anywhere in the model,
    but is still worth capturing.
    """

    hash: Hash = Hash()
    """
    Hash of raw field to be able to demonstrate log integrity.
    """

    id: str = ""
    """
    Unique identifier for the Event, if any.
    """

    ingested: datetime | None = None
    """
    When the event was generated by PEAT, e.g. when it was
    parsed or pulled from a device.

    .. warning::
       This should almost always differ from ``created``
       and the two should NOT be confused.
    """

    kind: set[str] = set()
    """
    Gives high-level information about what type of
    information the event contains, without being specific to the
    contents of the event. For example, values of this field
    distinguish alert events from metric events.
    `Further reading <https://www.elastic.co/guide/en/ecs/current/ecs-allowed-values-event-kind.html>`__
    This is a set of values, and is an array in Elasticsearch, which allows
    for Kibana queries such as ``host.event.kind:event and host.event.type:deleted``.

    Allowed values

    - ``alert``
    - ``event``
    - ``metric``
    - ``state``
    - ``pipeline_error`` : Used for indicating there was an error processing the event
    """

    message: constr(strip_whitespace=True) = Field(
        default="", elastic_type=KEYWORD_AND_TEXT
    )
    """
    Simplified message body, for example a human-readable portion of the raw event.
    This should be set *in addition to* setting the ``original`` field.
    """

    module: constr(strip_whitespace=True) = ""
    """
    Name of the module this data is coming from, e.g. the PEAT module.
    """

    original: str = Field(default="", elastic_type="text")
    """
    Original raw text of the log entry.
    """

    outcome: constr(strip_whitespace=True) = ""
    """
    Outcome of the event.
    `Further reading <https://www.elastic.co/guide/en/ecs/current/ecs-allowed-values-event-outcome.html>`__

    Allowed values

    - ``success``
    - ``failure``
    - ``unknown``
    """

    provider: constr(strip_whitespace=True) = ""
    """
    Source of the event. This is almost always the Device ID.
    """

    sequence: int | None = None
    """
    Sequence number of the event. The sequence number is a value
    published by some event sources, to make the exact ordering of
    events unambiguous, regardless of the timestamp precision.
    """

    severity: constr(strip_whitespace=True) = ""
    """
    Severity or log level of the event as stored on the device.

    Examples

    - ``debug``
    - ``ERR``
    """

    timezone: constr(strip_whitespace=True) = ""
    """
    Timezone for the event.

    This field should be populated when the event's timestamp does not include timezone information already. It's optional otherwise.

    .. note::
       This field will be auto-populated from the device's timezone field
       (DeviceData.geo.timezone), if the timestamp isn't timezone-aware
       and the device's timezone is known.

    Acceptable timezone formats are: a canonical ID (e.g. ``Europe/Amsterdam``)
    or abbreviated (e.g. ``EST``). Canonical ID is preferred for PEAT.

    Examples

    - ``Europe/Amsterdam``
    - ``America/Denver``
    - ``Etc/UTC``
    - ``EST``
    - ``MST``
    - ``UTC``
    """

    type: set[str] = set()
    """
    List of event category "sub-buckets" the event falls under. The
    valid values depend on the value for ``category``, refer to the
    `ECS documentation for <https://www.elastic.co/guide/en/ecs/current/ecs-allowed-values-event-category.html>`__ details.
    This is a set of values, and is an array in Elasticsearch, which allows
    for Kibana queries such as ``host.event.type:user and host.event.type:deleted``.

    Allowed values (refer to the `ECS documentation <https://www.elastic.co/guide/en/ecs/current/ecs-allowed-values-event-type.html>`__)

    - ``access``
    - ``admin``
    - ``allowed``
    - ``change``
    - ``connection``
    - ``creation``
    - ``deletion``
    - ``denied``
    - ``end``
    - ``error``
    - ``group``
    - ``info``
    - ``installation``
    - ``protocol``
    - ``start``
    - ``user``
    """

    _es_index_varname: str = PrivateAttr(default="ELASTIC_EVENTS_INDEX")
    _sort_by_fields: tuple[str] = PrivateAttr(
        default=("provider", "dataset", "sequence", "created")
    )

    # Validators
    _validate_ecs = validator(
        "category", "kind", "outcome", "type", each_item=True, allow_reuse=True
    )(validate_ecs)

    def annotate(self, dev: DeviceData | None = None):
        if dev:
            # If provider isn't set, set it to the device's ID
            if not self.provider and dev.ip:
                self.provider = dev.ip
            elif not self.provider and dev.id:
                self.provider = dev.id

            # Set the module if not set
            if not self.module and dev._module:
                self.module = dev._module.__name__

        # If timezone isn't set, set to the timezone of the timestamp if
        # the timestamp is present and timezone-aware.
        # If it's not timezone-aware, then set it to the device's
        # timezone, if it's set.
        if not self.timezone:
            if self.created and self.created.tzinfo:
                self.timezone = self.created.tzname()
            elif dev and dev.geo.timezone:
                self.timezone = dev.geo.timezone

        # Add "event" to kind if nothing has been added
        if not self.kind:
            self.kind = {"event"}
        elif self.kind and "event" not in self.kind:
            self.kind.add("event")

    def gen_elastic_content(self, dev: DeviceData | None = None) -> dict:
        self.annotate(dev)  # populate fields
        time_now = Elastic.time_now()
        timestamp = time_now
        if self.created is not None:
            timestamp = Elastic.convert_tstamp(self.created)
        ingested = time_now
        if self.ingested is not None:
            ingested = Elastic.convert_tstamp(self.ingested)
        content = {
            "@timestamp": timestamp,
            "message": self.message if self.message else self.original,
            "tags": ["events"],
            "event": {
                # event.*
                **self.dict(exclude_defaults=True),
                # event.ingested
                "ingested": ingested,
            },
        }
        if self.original:
            content["hash"] = utils.gen_hashes(self.original)
        if dev:
            # host.{basic fields}
            content["host"] = dev.gen_base_host_fields_content()
            content["tags"].extend(
                [
                    dev.description.vendor.name,
                    dev.description.product,
                ]
            )
        return content


class OS(BaseModel):
    """
    Operating System (OS) information, such as the name and version.
    """

    family: constr(strip_whitespace=True, to_lower=True) = ""
    """
    Operating system family, such as Debian, Windows, etc. Lowercase value.
    This can be general (e.g. ``linux``) or specific (e.g. ``debian``).

    Examples

    - ``debian``
    - ``windows``
    - ``linux``
    """

    full: constr(strip_whitespace=True) = ""
    """
    Full operating system name, including the version or code name.

    Examples

    - ``WindRiver VxWorks 7``
    """

    kernel: constr(strip_whitespace=True) = ""
    """
    Operating system kernel version as a raw string.

    Examples:

    - ``4.4.0-112-generic``
    """

    name: constr(strip_whitespace=True) = ""
    """Operating system name, without the version.

    Examples

    - ``VxWorks``, ``Linux``
    """

    timestamp: datetime | None = None
    """
    Timestamp of the OS, as extracted from the device or firmware.
    Device-dependent meaning. Often represents when the OS
    was compiled/built or released.
    """

    vendor: Vendor = Vendor()
    """
    The vendor of the OS, if known.
    """

    version: constr(strip_whitespace=True) = ""
    """
    Operating system version as a raw string.
    """


class Memory(BaseModel):
    """
    Physical memory values (e.g. :term:`RAM`, EEPROM).
    """

    address: str = ""
    """
    Starting address of the read, as a hexadecimal string.

    This should be zero-padded hex bytes, without a leading
    hex identifier, and uppercase characters.

    Examples:

    - ``00000003``
    - ``D3ADB33F``
    """

    created: datetime | None = None
    """
    When the read occurred. Represents when in time
    the memory address had the value.
    """

    dataset: constr(strip_whitespace=True) = ""
    """
    Data source of the memory read, such as the memory region
    or log it was extracted from, if applicable.

    Examples

    - ``watchdog_log``
    - ``internal_memory``
    - ``RAM``
    - ``EEPROM``
    """

    device: constr(strip_whitespace=True) = ""
    """
    Device that was the source of the read.
    This is almost always the device ID.
    """

    process: constr(strip_whitespace=True) = ""
    """
    Name of the system process or task this memory read is associated with.
    """

    size: int | None = None
    """
    Size of the memory read, in bytes.
    """

    value: str = ""
    """
    The value read from memory, as a hexadecimal string.

    Each hex pair (e.g. ``3f``) represents 1 byte.

    The length of this string should be twice the value of ``size`` (size*2).

    This should be zero-padded hex bytes, without a leading
    hex identifier, and uppercase characters.

    Examples:

    - ``00000003``
    - ``D3ADB33F``
    """

    extra: dict = Field(default={}, elastic_type="flattened")
    """
    Additional data or metadata about the memory read.
    """

    _es_index_varname: str = PrivateAttr(default="ELASTIC_MEMORY_INDEX")
    _sort_by_fields: tuple[str] = PrivateAttr(
        default=("device", "dataset", "address", "created")
    )

    # Validators
    _validate_hexes = validator("address", "value", allow_reuse=True)(validate_hex)

    def annotate(self, dev: DeviceData | None = None):
        if dev:
            # Automatically set the device field if it's not already
            if not self.device:
                dev_id = dev.get_id()
                if "unknown-dev-" not in dev_id:
                    self.device = dev_id

    def gen_elastic_content(self, dev: DeviceData | None = None) -> dict:
        self.annotate(dev)  # populate fields
        # Hacky way to make a nice fancy message describing the Memory
        message = ""
        if self.dataset:
            message += f"[{self.dataset}] "
        message += f"0x{self.address}: 0x{self.value}"
        time_now = Elastic.time_now()
        timestamp = time_now
        if self.created is not None:
            timestamp = Elastic.convert_tstamp(self.created)
        content = {
            "@timestamp": timestamp,
            "message": message,
            "tags": ["memory"],
            "event": {"ingested": time_now},
            "memory": self.dict(exclude_defaults=True),
        }
        if dev:
            # host.{basic fields}
            content["host"] = dev.gen_base_host_fields_content()
            content["tags"].extend(
                [
                    dev.description.vendor.name,
                    dev.description.product,
                ]
            )
            if dev._module:
                content["event"]["module"] = dev._module.__name__
        return content


class SSHKey(BaseModel):
    """
    SSH keys (public or private).
    """

    description: constr(strip_whitespace=True) = ""
    """
    Description of the SSH key and/or any comments.
    """

    file: File = File()
    """
    The file associated with the key, if any.
    """

    host: constr(strip_whitespace=True) = ""
    """
    Host associated with the key (hostname, DNS name, or IP).
    """

    id: constr(strip_whitespace=True) = ""
    """
    Unique identifier for the key, if any.
    """

    original: constr(strip_whitespace=True) = ""
    """
    Complete contents of the key, with any trailing whitespace removed.
    """

    type: Literal["public", "public", ""] = ""
    """
    Type of key, either ``public`` or ``private``.
    """

    user: constr(strip_whitespace=True) = ""
    """
    Name of user associated with the key.
    """

    _sort_by_fields: tuple[str] = PrivateAttr(
        default=("host", "user", "type", "id", "description", "original")
    )

    def annotate(self, dev: DeviceData | None = None):
        if not dev:
            return
        if self.file.path:
            dev.related.files.add(self.file.path.as_posix())
        elif self.file.name:
            dev.related.files.add(self.file.name)
        if self.user:
            dev.related.user.add(self.user)
        if self.host:
            if utils.is_ip(self.host):
                dev.related.ip.add(self.host)
            else:
                dev.related.hosts.add(self.host)


class DeviceData(BaseModel):
    """
    Container and manager of all data about a device,
    e.g. name, :term:`IP` address, version, etc.

    .. note::
        If unset, the :attr:`~peat.data.models.DeviceData.id` attribute on this
        object will be set to the IP of the first Interface added via
        :meth:`~peat.data.models.DeviceData.store`.

    There are two main methods of storing and retrieving data:

    - Directly via class attributes. This should be used for most operations.
    - Via :meth:`~peat.data.models.DeviceData.store` and
      :meth:`~peat.data.models.DeviceData.retrieve`.
      These are used for containers of objects,
      e.g. ``dev.interface`` or ``dev.event"``.

    .. note::
        See the documentation for :meth:`~peat.data.models.DeviceData.store`
        and :meth:`~peat.data.models.DeviceData.retrieve`
        for detailed examples of how to use those methods.

    Storing data:

    - Direct assignment: ``dev.os.version = "7"``
    - Storing to a list: ``dev.store("interface", Interface(ip="192.0.2.10"))``

    Reading data:

    - General data: ``value = dev.os.version``
    - List of data: ``value = dev.retrieve("interface", {"ip": "192.0.2.10"})``

    Methods for exporting data:

    - :meth:`~peat.data.models.DeviceData.export`
    - :meth:`~peat.data.models.DeviceData.export_summary`
    - :meth:`~peat.data.models.DeviceData.elastic`
    - :meth:`~peat.data.models.DeviceData.dict`
    - :meth:`~peat.data.models.DeviceData.json`
    - :meth:`~peat.data.models.DeviceData.export_to_elastic`
    - :meth:`~peat.data.models.DeviceData.export_to_files`

    .. note::
       The device can be module or component of a larger system, e.g. a module
       in a :term:`PLC` or a wireless add-on module on a power meter. The
       :attr:`~peat.data.models.DeviceData.module` field is an example
       of this use case (a :class:`list` of :class:`~peat.data.models.DeviceData`).
    """

    successful_pulls: dict = Field(default={})
    """
    Indicates the success of the peat pull per protocol
    """

    architecture: constr(strip_whitespace=True) = ""
    """
    Architecture of the device :term:`CPU`.
    """

    boot_firmware: Firmware = Firmware()
    """
    Boot firmware information, if applicable.
    """

    description: Description = Description()
    """
    Identifying information such as vendor, brand, and model.
    """

    endian: Literal["big", "little", ""] = ""
    """
    "Endianness" of the CPU of the system where the memory was read from.
    """

    firmware: Firmware = Firmware()
    """
    Device firmware information.
    """

    hardware: Hardware = Hardware()
    """
    Information about the device's hardware specifications
    and configuration (RAM, storage, etc.).
    """

    hostname: constr(strip_whitespace=True) = ""
    """
    Hostname of the device (if resolved). In the case of a device
    with multiple communication modules, this is the hostname of the
    module PEAT primarily uses to communicate (or first discovered).
    """

    id: constr(strip_whitespace=True) = ""
    """
    Unique identifier for the device. Can be anything, as long as it's
    consistent in the module. Defaults to the device MAC, IP, or COM port.
    """

    ip: str = Field(default="", elastic_type="ip")
    """
    :term:`IP` address of the device. In the case of a device with multiple
    communication modules, this is the IP address of the module PEAT
    primarily uses to communicate (or first discovered).
    """

    mac: str = ""
    """
    :term:`MAC` address of the device. In the case of a device with
    multiple communication modules, this is the :term:`MAC` address of the
    module PEAT primarily uses to communicate (or first discovered).
    """

    mac_vendor: str = Field(default="", elastic_type=KEYWORD_AND_TEXT)
    """
    Vendor name resolved from the :term:`MAC` address :term:`OUI`.

    This field is auto-populated by PEAT if the ``mac`` field is set.
    """

    serial_port: constr(strip_whitespace=True) = ""
    """
    Serial port on the local system connected to the device.
    This could be a Windows COM port, e.g. ``COM4``, or a Linux file
    path, e.g. ``/dev/ttyS0``. This is also used for USB connections.
    To get the specific serial settings, lookup the interface with
    the matching port in ``data.interface``.
    """

    name: constr(strip_whitespace=True) = ""
    """
    Name to refer to the device as, e.g. as pulled from a config or
    resolved via :term:`DNS`. Defaults to :term:`FQDN` resolved from
    the IP address, if hostname resolutions are enabled in
    the PEAT configuration.
    """

    label: str = ""
    """
    User-specified label from the PEAT configuration file.

    This field is automatically set by PEAT, and device modules
    shouldn't write to this field.
    """

    comment: str = ""
    """
    User-specified comment from the PEAT configuration file.

    This field is automatically set by PEAT, and device modules
    shouldn't write to this field.
    """

    part_number: constr(strip_whitespace=True) = ""
    """
    Part number of the device, as defined by
    the vendor and stored on the device.
    """

    type: constr(strip_whitespace=True) = ""
    """
    The type/class of device, e.g. "PLC", "Relay", "RTU", "Controller"
    (catch-all), etc. Examples of type for a module include
    Communications Adapter, General Purpose Discrete I/O, or CPU.
    """

    serial_number: constr(strip_whitespace=True) = ""
    """
    Unique serial number of the device, as defined by
    the vendor and stored on the device.
    """

    manufacturing_date: datetime | None = None
    """
    When the device was manufactured (physically created).
    """

    run_mode: constr(strip_whitespace=True) = ""
    """
    Run mode of the device. For example, on a PLC, there may be a key in the front
    of the device that sets PROG or RUN (program vs running). What this field means
    depends on the device, for instance a PLC's potential run modes will differ
    from a RTU's potential run modes.
    """

    slot: constr(strip_whitespace=True) = ""
    """
    Position of the device in a rack or larger device. This can be a
    relative position, e.g. "0" for the first module in a :term:`PLC`, or a name
    or other identifier for the position (such as an internal bus address).
    """

    start_time: datetime | None = None
    """
    :term:`UTC` timestamp of when the device last powered on.
    """

    status: constr(strip_whitespace=True) = ""
    """
    Status of the device. The meaning of this field is device-dependant.
    """

    uptime: timedelta | None = None
    """
    Number of seconds the host has been up (powered on/online), as either a
    integer or :class:`~datetime.timedelta`.

    .. note::
       Normal Python integers (:class:`int`) can be assigned to this directly
       and they will be automatically converted to a :class:`~datetime.timedelta`.
    """

    os: OS = OS()
    """
    Operating System (OS) information, such as the name and version.
    """

    geo: Geo = Geo()
    """
    Geolocation information. This includes the device's physical
    location and configured timezone.
    """

    logic: Logic = Logic()
    """
    What the device has been programmed to do, aka the "process logic".
    """

    files: list[File] = []
    """
    All files that are present on the device, or were present at some point
    in time.
    """

    interface: list[Interface] = []
    """
    All communication interfaces configured or present on the device.
    """

    service: list[Service] = []
    """
    All communication services configured or running on the device.
    """

    ssh_keys: list[SSHKey] = []
    """
    Any SSH keys found on the device or associated with the device.
    """

    related: Related = Related()
    """
    Information that is related to a host or interface.
    """

    # NOTE: "register" shadows a field from pydantic.BaseModel
    # It has been renamed to "registers" to avoid conflict
    registers: list[Register] = []
    """
    All Input/Output (I/O) protocol data points configured on the device,
    e.g. DNP3 and Modbus.
    """

    tag: list[Tag] = []
    """
    Data variables ("tags") in a device. Often mapped in a device's logic
    to physical I/O and/or registers.
    """

    io: list[IO] = []
    """
    Physical Input/Output (I/O) connections on a device.
    """

    event: list[Event] = []
    """
    Event log entries on the device, aggregated from all log sources.
    """

    memory: list[Memory] = []
    """
    Physical memory values (e.g. RAM, EEPROM).
    """

    module: list[DeviceData] = []
    """
    Physical add-on modules in a device, e.g. slots in a :term:`PLC`
    or rack. These also include add-on components, such as a wireless radio.
    These can include analog and digital I/O modules, COMMs modules
    (Ethernet, various serial protocols, Wi-Fi, LTE, etc.), CPU modules,
    and anything else really. While there are general sorts of modules
    that are typically seen in devices like a :term:`PLC`, the reality is there
    are a ton of modules that sometimes highly specific to a vendor
    or application. Therefore, while we define a set of module types,
    they are not required to be used if the module does not fall in the
    set of defined types.
    """

    users: list[User] = []
    """
    Users on the device.
    """

    x509: X509 = X509()
    """
    x509 certificate associated with the device, e.g. from a
    HTTPS/TLS service or extracted from a file in a blob.
    """

    uefi_image: list[UEFIFile] = []
    """
    uefi_image holds all the spi files for the UEFIFile object
    """

    uefi_hashes: list[UEFIHash] = []
    """
    uefi_hashes holds all the hashes for a file that is linked to a device.
    """

    # NOTE: trying out "flattened" to prevent type mapping explosion
    # https://www.elastic.co/guide/en/elasticsearch/reference/current/flattened.html
    extra: dict = Field(default={}, elastic_type="flattened")
    """
    Additional vendor/model-specific information that doesn't
    currently fit into the defined model, but may be useful and
    we don't want to leave on the cutting room floor, so to speak.
    In other words: a piece of data belongs here if it's useful and
    doesn't fit elsewhere in the model.
    """

    _cache: dict = PrivateAttr(default={})
    """
    Cache for internal usage by device modules. Can include data such as Python
    sockets, protocol classes (e.g. :class:`~peat.protocols.ftp.FTP`)
    or other objects or state.
    """

    _es_index_varname: str = PrivateAttr(default="ELASTIC_HOSTS_INDEX")

    _sort_by_fields: tuple[str] = PrivateAttr(
        default=(
            "slot",
            "ip",
            "id",
            "name",
            "serial_port",
            "mac",
            "hostname",
            "serial_number",
        )
    )

    _module: type | None = PrivateAttr(default=None)
    """
    :class:`~peat.device.DeviceModule` class used for this device
    (generally set after identification).
    """

    _out_dir: Path | None = PrivateAttr(default=None)
    """
    Output directory for any file output and results associated with this device.
    Don't use this directly, instead use :func:`~peat.data.DeviceData.get_out_dir`,
    :func:`~peat.data.DeviceData.get_sub_dir`, or :func:`~peat.data.DeviceData.write_file`.
    """

    _options: DeepChainMap = PrivateAttr()
    """
    Master ChainMap combining all of the device options.

    .. warning::
       Don't access this, :attr:`peat.data.DeviceData.options`.

    Modifications to this will show up in :attr:`peat.data.DeviceData.options`.

    NOTE: to change values, either add individual fields or use ``.update({...})``.

    !!! DON'T DIRECTLY ASSIGN A NEW DICT TO THIS FIELD, this will break pydantic !!!
    """

    _runtime_options: dict = PrivateAttr(default={})
    """
    Options set or overridden at runtime.

    .. warning::
       Don't access this, :attr:`peat.data.DeviceData.options`.

    Modifications to this will show up in :attr:`peat.data.DeviceData.options`.

    NOTE: to change values, either add individual fields or use ``.update({...})``.

    !!! DON'T DIRECTLY ASSIGN A NEW DICT TO THIS FIELD, this will break pydantic !!!
    """

    _host_option_overrides: dict = PrivateAttr(default={})
    """
    Overrides for this particular host.

    .. warning::
       Don't access this, :attr:`peat.data.DeviceData.options`.

    Modifications to this will show up in :attr:`peat.data.DeviceData.options`.

    NOTE: to change values, either add individual fields or use ``.update({...})``.

    !!! DON'T DIRECTLY ASSIGN A NEW DICT TO THIS FIELD, this will break pydantic !!!
    """

    _module_default_options: dict = PrivateAttr(default={})
    """
    Default options injected from a module.

    .. warning::
       Don't access this, :attr:`peat.data.DeviceData.options`.

    Modifications to this will show up in :attr:`peat.data.DeviceData.options`.

    NOTE: to change values, either add individual fields or use ``.update({...})``.

    !!! DON'T DIRECTLY ASSIGN A NEW DICT TO THIS FIELD, this will break pydantic !!!
    """

    _last_module: str = PrivateAttr(default="")
    """
    Used by :attr:`peat.data.DeviceData.options`.
    """

    _is_active: bool = PrivateAttr(default=False)
    """
    If the device is active and responding.
    """

    _is_verified: bool = PrivateAttr(default=False)
    """
    If the device has been verified as a specific type.
    """

    _is_deduplicated: bool = PrivateAttr(default=False)
    """
    If the device has already had :meth:`~peat.datamodels.DeviceData.purge_duplicates`
    called on it.
    """

    _ID_KEY_ORDER: list[str] = [
        "label",
        "ip",
        "name",
        "hostname",
        "mac",
        "serial_port",
        "id",
        "part_number",
    ]
    """
    Device identification precedence with a focus on being human-friendly.
    """

    _COMM_ID_KEY_ORDER: list[str] = [
        "serial_port",
        "ip",
        "hostname",
        "mac",
        "name",
        "id",
    ]
    """
    Device identifier precedence order with a focus on getting a communication ID.
    """

    _DEFAULT_OPTIONS: dict = PrivateAttr(default=DEFAULT_OPTIONS)
    """
    Default options for all devices.
    These get set from ``peat/data/default_options.py``
    """

    # Validators
    _validate_ip = validator("ip", allow_reuse=True)(validate_ip)
    _validate_mac = validator("mac", allow_reuse=True)(validate_mac)

    def __init__(self, **data):
        super().__init__(**data)

        # BUGFIX: import here to make imports work with ipython notebooks
        from peat import module_api

        module_defaults = [
            # deepcopy to prevent changes to self._options from modifying source
            deepcopy(
                {
                    k: v
                    for k, v in module.default_options.items()
                    if k not in self._DEFAULT_OPTIONS
                }
            )
            for module in module_api.modules.values()
            if getattr(module, "default_options", None)
        ]

        if self._module:
            self._module_default_options.clear()
            self._module_default_options.update(deepcopy(self._module.default_options))

        self._options = DeepChainMap(
            # Options changed at runtime for this specific device
            self._runtime_options,
            # Options changed at initialization time for this specific device
            self._host_option_overrides,
            # Global option runtime changes, managed in datastore
            peat.data.store.datastore.global_options,  # minor hack with direct reference...
            # Defaults from the module associated with this device (or from the caller)
            self._module_default_options,
            # Fallback to module-specific defaults if the current module isn't known
            # e.g. "sel", keys that (mostly) aren't generalized
            *module_defaults,
            # Standard defaults
            # deepcopy to prevent changes to self._options from modifying source
            deepcopy(self._DEFAULT_OPTIONS),
        )

        # If data is passed to initialization and there are hosts from YAML config,
        # then attempt to automatically set the label from the config.
        #
        # This will miss data objects that don't have any parameters passed during
        # initialization, but that is by design.
        if data and not self.label and config.HOSTS:
            # At initialization time, likely only one of these will be set, and certainly
            # only in the case of a device read from a config. Therefore, the first one
            # that's set should be used for the label lookup.
            ident_key = ""
            ident_val = ""

            # TODO: config identifier keys probably should be defined somewhere...meh
            for key in ["ip", "mac", "serial_port", "name", "hostname"]:
                if getattr(self, key):
                    ident_key = key
                    ident_val = getattr(self, key)
                    break

            if ident_key:
                for host in config.HOSTS:
                    if not host.get("label") or not host.get("identifiers"):
                        continue
                    if host["identifiers"].get(ident_key) == ident_val:
                        self.label = host["label"]
                        if host.get("comment"):
                            self.comment = host["comment"]

    @property
    def address(self) -> str:
        """
        Communication address of the device (``ip``, ``serial_port`` or ``mac``).
        """
        valid_addresses = ["ip", "serial_port", "mac"]
        for key in valid_addresses:
            value = getattr(self, key, None)
            if value:
                if not isinstance(value, str):
                    value = str(value)  # convert ipaddress objects to str
                return value
        raise PeatError(
            f"'.address': no valid address defined out of "
            f"{valid_addresses} (dev.id: {self.id})"
        )

    @property
    def options(self) -> DeepChainMap:
        """
        PEAT configuration options for this device. This includes Service
        configurations (timeout, port, etc.), login credentials, etc.

        The options are composed from multiple sources and use the
        following order of precedence:

        #. Runtime changes (``self._runtime_options``)
        #. Host-specific changes (``self._host_option_overrides``)
        #. Global option changes (stored in :attr:`datastore.global_options <peat.data.store.Datastore.global_options>`)
        #. Module-specific defaults (from :attr:`peat.device.DeviceModule.default_options` for the module)
        #. Global defaults (:attr:`peat.data.DeviceData._DEFAULT_OPTIONS`)
        """
        if self._module and not self._module_default_options:
            self._module_default_options.update(deepcopy(self._module.default_options))
        elif self._module and self._last_module:
            self._last_module = ""
            self._module_default_options.clear()
            self._module_default_options.update(deepcopy(self._module.default_options))
        elif not self._module:
            try:
                c_locals = inspect.stack()[1][0].f_locals
                klass = c_locals.get("cls", c_locals.get("self"))
                if klass and hasattr(klass, "default_options"):
                    k_name = getattr(
                        klass, "__name__", klass.__class__.__name__
                    )  # type: str
                    if not self._last_module or (
                        self._last_module and k_name != self._last_module
                    ):
                        self._last_module = k_name
                        self._module_default_options.clear()
                        self._module_default_options.update(
                            deepcopy(klass.default_options)
                        )
            except Exception:
                pass
        return self._options

    def get_id(self, attribute_precedence: list[str] | None = None) -> str:
        """
        Get a canonical device ID.

        If the lookup fails a randomly generated ID is used, generated by
        :func:`~peat.consts.gen_random_dev_id`.

        The attribute used as the ID is selected based on an order of precedence.
        Each attribute is checked in the order defined, and the first attribute
        with a defined value (non-empty) is used as the ID.

        Args:
            attribute_precedence: Define a custom order of precedence for
                attributes to use for an ID. If :obj:`None`, then the
                default :attr:`~peat.data.DeviceData._ID_KEY_ORDER`
                is used.

        Returns:
            Device ID or a randomly generated ID if lookup fails
        """
        if attribute_precedence is None:
            attribute_precedence = self._ID_KEY_ORDER

        for attr in attribute_precedence:
            value: str = getattr(self, attr, None)
            if value:
                if not isinstance(value, str):
                    value = str(value)  # convert ipaddress objects to str
                return value

        if not self._cache.get("_rand_id"):
            self._cache["_rand_id"] = consts.gen_random_dev_id()
            log.critical(
                f"Failed to find a valid ID! Using "
                f"'{self._cache['_rand_id']}' as the ID"
            )

        return self._cache["_rand_id"]

    def get_comm_id(self) -> str:
        """
        Get a canonical communication protocol ID for this device
        (e.g. IP address, MAC address, serial port)

        Same as :meth:`~peat.data.models.DeviceData.get_id` except
        :attr:`~peat.data.models.DeviceData._COMM_ID_KEY_ORDER` is
        used as the order of precedence.

        Returns:
            Communication protocol ID of the device (e.g. IP, MAC, serial port)
        """
        return self.get_id(attribute_precedence=self._COMM_ID_KEY_ORDER)

    def service_status(self, lookup: dict) -> str:
        """
        Returns the status of a service, or ``"unknown"`` if the service
        isn't found.
        """
        hsvc = self.retrieve("service", lookup)

        if not hsvc or not isinstance(hsvc, Service):
            return "unknown"

        if isinstance(hsvc, list):  # !! hack for duplicate services !!
            hsvc = hsvc[0]

        return hsvc.status

    def annotate_edge_cases(self):
        # Annotate X509 and other models that are set on initialization
        for list_attr in self.get_attr_names(BaseModel):
            val = getattr(self, list_attr, None)
            if val and hasattr(val, "annotate"):
                val.annotate(self)

        # Annotate all objects in lists. This works around cases where
        # the object was added directly via a list.append() instead of
        # via the .store() API (generally for performance reasons).
        for list_attr in self.get_attr_names(list):
            val = getattr(self, list_attr, None)
            if val:
                for item in val:
                    if hasattr(item, "annotate"):
                        item.annotate(self)

    def export(
        self,
        include_original: bool = False,
        exclude_fields: list[str] | None = None,
        only_fields: str | list[str] | None = None,
    ) -> dict:
        """
        Return device data as a normalized JSON-friendly :class:`dict`.

        Args:
            include_original: If ``original`` keys should be included (this is
                the raw data, e.g. raw firmware or raw logic)
            exclude_fields: Field names (keys) to exclude from the
                returned :class:`dict`. This recursively excludes fields!
            only_fields: Only include the specified fields (keys) in the
                returned :class:`dict` (Note: this only applies to top-level
                fields in the data, e.g. ``name``, ``firmware``, etc.)

        Returns:
            The exported data as a JSON-serializable :class:`dict`

            .. note::
               The order of data returned will be the same as
               the order of the fields in the models
        """
        self.populate_fields()
        self.purge_duplicates()
        self.annotate_edge_cases()

        to_exclude = {}
        if exclude_fields:
            if isinstance(exclude_fields, str):
                to_exclude[exclude_fields] = True
            else:
                for ef in exclude_fields:
                    to_exclude[ef] = True
        if not to_exclude:
            to_exclude = None

        to_include = {}
        if only_fields:
            if isinstance(only_fields, str):
                to_include[only_fields] = True
            else:
                for of in only_fields:
                    to_include[of] = True
        if not to_include:
            to_include = None

        results = self.dict(
            exclude=to_exclude, include=to_include, exclude_defaults=True
        )

        if not include_original:  # Note: parsed logic is stored in "parsed"
            results = strip_key(results, "original")

        results = consts.convert(results)  # Normalize to JSON-friendly values
        results = strip_empty_and_private(results)

        # minor hack to apply IP sorting to the list of IPs in related.ip
        if results.get("related", {}).get("ip"):
            results["related"]["ip"] = addresses.sort_ips(results["related"]["ip"])

        # NOTE: pydantic preserves the order they're defined in the models
        # https://github.com/samuelcolvin/pydantic/issues/593#issuecomment-501735842
        return results

    def export_summary(self, cached_export: dict | None = None) -> dict:
        """
        Return a summarized version of the device data as a
        normalized JSON-friendly :class:`dict`, with certain
        large fields removed.

        Returns:
            The exported data as a JSON-serializable :class:`dict`

            .. note::
               The order of data returned will be the same as
               the order of the fields in the models
        """
        # Summary of data, excluding large/excessive fields like "original"
        if not cached_export:
            summary_data = self.export(include_original=True)
        else:
            summary_data = copy.deepcopy(cached_export)

        # Hack to directly exclude "original" only from
        # firmware and logic, not other things like events.
        for original_key in ["logic", "firmware", "boot_firmware"]:
            if summary_data.get(original_key, {}).get("original"):
                del summary_data[original_key]["original"]

        # Exclude fields from the summary
        for exclude_key in ["memory", "registers", "tag", "io", "event", "files"]:
            if summary_data.get(exclude_key):
                del summary_data[exclude_key]

        # Exclude "raw-values" from summary data
        if summary_data.get("logic", {}).get("formats", {}).get("raw-values"):
            del summary_data["logic"]["formats"]["raw-values"]
            if not summary_data["logic"]["formats"]:
                del summary_data["logic"]["formats"]

        return summary_data

    def export_to_files(self, overwrite_existing: bool = False) -> bool:
        """
        Export data to files named ``device-data-full`` and ``device-data-summary``.

        Args:
            overwrite_existing: if any files that already exist should be
                replaced with new data (overwritten)

        Returns:
            :obj:`True` if the writes completed, :obj:`False` if an exception occurred
        """
        self.populate_fields()
        self.purge_duplicates()

        # TODO: export large fields to separate JSON files
        #   memory
        #   event
        #   registers

        try:
            # All data, including "original" and other large fields
            full_device_data = self.export(include_original=True)

            self.write_file(
                data=full_device_data,
                filename="device-data-full.json",
                overwrite_existing=overwrite_existing,
            )

            # Summary of data, excluding excessively large fields
            # such as logic.original or memory.
            summary_data = self.export_summary(cached_export=full_device_data)

            self.write_file(
                data=summary_data,
                filename="device-data-summary.json",
                overwrite_existing=overwrite_existing,
            )

            return True
        except Exception:
            log.exception(
                f"Failed to export data to files for device '{self.get_id()}'"
            )
            state.error = True
            return False

    def export_to_elastic(self, elastic: Elastic | None = None) -> bool:
        """
        Save device data to an Elasticsearch database.

        Args:
            elastic: The :class:`~peat.elastic.Elastic` instance to use.
                If unspecified, this defaults to the global
                :class:`~peat.elastic.Elastic` instance in
                :attr:`~peat.settings.State.elastic`.

        Returns:
            If the export was successful
        """

        dev_id = self.get_id()
        elastic = resolve_es_instance(elastic, dev_id)
        if not elastic:
            return False

        log.info(f"Exporting device {dev_id} to {elastic.type}")
        success = True

        # Export this DeviceData object (self)
        if not export_models_to_elastic([self], self, elastic):
            success = False

        # Automatically determine what lists of models to push
        for list_attr_name in self.get_attr_names(list):
            model_list = getattr(self, list_attr_name, None)

            if not model_list:
                log.trace2(
                    f"Skipping {elastic.type} export of DeviceData.{list_attr_name} (no data)"
                )
                continue

            # If the list is populated, and it has "_es_index_varname" attribute defined,
            # then proceed with attempting to export it to Elasticsearch.
            # Also, skip self.modules.
            if (
                model_list
                and getattr(model_list[0], "_es_index_varname", None)
                and not isinstance(model_list[0], DeviceData)
            ):
                log.info(
                    f"Exporting {len(model_list)} {model_list[0].__repr_name__()} "
                    f"models (DeviceData.{list_attr_name}) to {elastic.type} for "
                    f"device '{self.get_id()}'"
                )

                # Export all models in the list to Elasticsearch
                if not export_models_to_elastic(
                    models=model_list, dev=self, elastic=elastic
                ):
                    success = False

        if success:
            log.debug(f"Exported device '{self.get_id()}' to {elastic.type}")
            return True
        else:
            log.error(f"Failed to export device '{self.get_id()}' to {elastic.type}")
            state.error = True
            return False

    def elastic(self) -> dict[str, Any]:
        """
        This generates the ``host`` portion of Elasticsearch data.

        .. note::
           Attributes in any data objects with an empty value or a name that starts
           with an underscore (``_``) will not be included in the return value

        Returns:
            The host's data as a elasticsearch-friendly dictionary
        """
        self.populate_fields()
        self.purge_duplicates()

        # We don't use self.export() here because consts.convert() transforms objects
        # like datetime() into strings. The PeatSerializer Elasticsearch serializer
        # will handle the conversions instead.
        results = strip_empty_and_private(self.dict(exclude_defaults=True))
        if not config.ELASTIC_SAVE_BLOBS:
            results = strip_key(results, "original")

        # minor hack to apply IP sorting to the list of IPs in related.ip
        # this is because parse_api calls dev.elastic() instead of dev.export()
        if results.get("related", {}).get("ip"):
            results["related"]["ip"] = addresses.sort_ips(results["related"]["ip"])

        return results

    def gen_elastic_content(
        self, dev: DeviceData | None = None  # noqa: ARG002
    ) -> dict:
        self.populate_fields()

        content = {
            "@timestamp": Elastic.time_now(),
            "message": f"{self.description.vendor.name} {self.type}",
            "tags": [
                self.description.vendor.name,
                self.description.product,
                "devices",
            ],
            "host": self.elastic(),  # Export the current data
        }

        # If the logic is a dict (like with raw-values), then
        # convert it to a JSON string before pushing to elastic.
        if content["host"].get("logic", {}).get("original"):
            if isinstance(content["host"]["logic"]["original"], dict):
                content["host"]["logic"]["original"] = json.dumps(
                    consts.convert(content["host"]["logic"]["original"])
                )

        # Exclude "raw-values" from Elasticsearch data
        if content["host"].get("logic", {}).get("formats", {}).get("raw-values"):
            del content["host"]["logic"]["formats"]["raw-values"]
            if not content["host"]["logic"]["formats"]:
                del content["host"]["logic"]["formats"]

        return content

    def gen_base_host_fields_content(self) -> dict:
        """Populate ``host`` field values for new indices."""
        content = {}
        for key in [
            "hostname",
            "id",
            "ip",
            "mac",
            "mac_vendor",
            "serial_port",
            "name",
            "label",
            "comment",
            "type",
            "serial_number",
            "slot",
            "description",
            "geo",
        ]:
            if not self.is_default(key) and getattr(self, key):
                value = getattr(self, key)
                if isinstance(value, BaseModel):
                    value = value.dict(exclude_defaults=True, exclude_none=True)
                content[key] = value
        return content

    def write_file(
        self,
        data: Any,
        filename: str,
        overwrite_existing: bool = False,
        out_dir: Path | None = None,
        merge_existing: bool = False,
    ) -> Path:
        """
        Save data to a file in the device's output directory.

        .. note::
           Data will NOT be written if both
           :attr:`~peat.settings.Configuration.DEVICE_DIR`
           and ``self._out_dir`` are unset.

        Args:
            data: Raw data to write
            filename: Name including extension of the file
            overwrite_existing: If existing files with the same name should be
                overwritten instead of being written with a ".<num>" appended
                to the name.
            out_dir: Directory the data should be written to.
                Defaults to result of ``dev.get_out_dir()``
            merge_existing: If the file already exists and is JSON, then
                read the data from the existing file, merge the new data with it,
                then overwrite the file with the merged data.

        Returns:
            Path to the file that was written
        """
        filename = consts.sanitize_filepath(filename)

        # If device file output is disabled, return the filename as a path
        if not self._out_dir and not config.DEVICE_DIR:
            log.debug(
                f"Device file output is disabled, skipping write to file {filename}"
            )
            return Path(filename)

        if not out_dir:
            out_dir = self.get_out_dir()

        full_path = out_dir / filename

        utils.write_file(
            data=data,
            file=full_path,
            overwrite_existing=overwrite_existing,
            merge_existing=merge_existing,
        )

        return full_path

    def get_out_dir(self) -> Path:
        """
        Get the path to the directory for any file output and results
        associated with this device.
        """
        if not self._out_dir:
            dir_name = address_to_pathname(self.get_id())
            self._out_dir = config.DEVICE_DIR / dir_name

        return self._out_dir

    def get_sub_dir(self, basename: str) -> Path:
        """
        Generate a directory path for specific file output, for example FTP files.
        The path will be a sub-dir in the device's results directory.
        """
        return self.get_out_dir() / basename

    def populate_fields(self, network_only: bool = False) -> None:
        """
        Populate new values by extrapolating from other existing values.

        .. note::
           This method also removes duplicate services and interfaces

        Example: if the device object only has a ``mac`` field populated,
        this will resolve and update the ``ip`` and ``hostname`` fields,
        then add a ``ethernet`` :class:`~peat.data.models.Interface`
        with those fields populated.

        Args:
            network_only: Only update network-related fields (like ``interface``)
        """
        # Deduplicate network attributes, such as redundant services
        # e.g. Service(port=80) and Service(port=80, protocol="http")
        # are duplicates and the former would be removed.
        for data_attr in ["interface", "service"]:
            data_val = getattr(self, data_attr, None)  # type: Optional[list]
            if data_val:
                deduped = dedupe_model_list(data_val)
                setattr(self, data_attr, deduped)

        # Add a interface and populate other ID fields
        if not self.interface:
            if self.serial_port:
                serial_iface = Interface(serial_port=self.serial_port)
                self.store("interface", serial_iface)
            else:
                for field_name in ["ip", "mac", "hostname"]:
                    val = getattr(self, field_name, None)
                    if val:
                        # Note: remaining fields will be auto-populated
                        iface = Interface(type="ethernet")
                        setattr(iface, field_name, val)
                        iface.annotate(self)
                        self.store("interface", iface)
                        break
        # Deduplicate services associated with interfaces
        else:
            for iface in self.interface:
                iface.annotate(self)
                if iface.services:
                    iface.services = dedupe_model_list(iface.services)
                    sort_model_list(iface.services)

        # Add to Related fields
        if self.ip and self.ip not in self.related.ip:
            self.related.ip.add(self.ip)
        if self.hostname and self.hostname not in self.related.hosts:
            self.related.hosts.add(self.hostname)

        # Always set the device ID to the IP, if it's known
        if self.ip and (self.id != self.ip or (self.name and self.id != self.name)):
            self.id = self.ip

        # If device ID isn't set, use one of the identifying values (IP, etc.)
        if not self.id:
            if self.ip:
                self.id = self.ip
            elif self.hostname:
                self.id = self.hostname
            elif self.name:
                self.id = self.name
            elif self.mac:
                self.id = self.mac

        # If ID is localhost, attempt to fallback to name or MAC, if they're defined
        if self.id in ["127.0.0.1", "localhost"]:
            if self.name:
                self.id = self.name
            elif self.mac:
                self.id = self.mac

        if self.mac and not self.mac_vendor:
            self.mac_vendor = mac_to_vendor_string(self.mac)

        if network_only:
            return

        # Generate/update file fields and read/save data, if applicable
        for field_name in self.__fields__.keys():
            field_obj = getattr(self, field_name)
            file_obj = getattr(field_obj, "file", None)  # type: Optional[File]
            if file_obj and isinstance(file_obj, File):
                if hasattr(field_obj, "original"):
                    # Run annotate_obj_and_file on all attributes
                    # with a "file" and "original"
                    annotate_obj_and_file(field_obj, field_name, self)
                else:
                    # Run process_file on all modules with "File" type field
                    file_obj.annotate(self)
                    process_file(file_obj)

        # Generate the product string
        if not self.description.product and self.description.brand:
            if self.description.brand == self.description.model:
                self.description.product = self.description.brand
            else:
                self.description.product = (
                    f"{self.description.brand} {self.description.model}".strip()
                )

        # Generate the description "full" field
        if not self.description.full:
            if self.description.vendor.name and self.description.product:
                self.description.full = (
                    f"{self.description.vendor.name} "
                    f"{self.description.product}".strip()
                )
            elif self.description.vendor.id and self.description.product:
                self.description.full = (
                    f"{self.description.vendor.id} "
                    f"{self.description.product}".strip()
                )

        # Populate vendor name from ID
        if not self.description.vendor.name:
            self.description.vendor.name = self.description.vendor.id

        # Populate os.full
        if not self.os.full:
            vend = self.os.vendor.id
            if self.os.vendor.name:
                vend = self.os.vendor.name
            self.os.full = " ".join(
                [x for x in [vend, self.os.name, self.os.version] if x]
            ).strip()

    def retrieve(
        self, attr: str, search: dict[str, Any]
    ) -> BaseModel | list[BaseModel] | None:
        """
        Retrieve a complex device data value.

        .. code-block:: python

           >>> from peat.data import DeviceData, Interface, Service, Tag
           >>> dev = DeviceData()
           >>> dev.store("interface", Interface(ip="192.0.2.123", type="ethernet"))
           >>> dev.store("interface", Interface(ip="192.0.2.20", type="ethernet"))
           >>> dev.store("service", Service(protocol="http", port=80))
           >>> dev.store("tag", Tag(name="var_rtu-8_I0", type="binary"))
           >>> dev.store("tag", Tag(name="var_rtu-9_I1", type="binary"))
           >>> dev.store("tag", Tag(name="var_rtu-10_Q0", type="analog"))

           # Interface with IP address of 192.0.2.20
           >>> iface = dev.retrieve("interface", {"ip": "192.0.2.20"})
           >>> iface.ip
           '192.0.2.20'

           # All "ethernet" interfaces
           >>> eth_ifaces = dev.retrieve("interface", {"type": "ethernet"})
           >>> len(eth_ifaces)
           2
           >>> iface in eth_ifaces
           True

           # The 'HTTP' service
           >>> svc = dev.retrieve("service", {"protocol": "http"})
           >>> svc.port
           80

           # Tag with name of var_rtu-8_I0
           >>> tag = dev.retrieve("tag", {"name": "var_rtu-8_I0"})
           >>> tag.name
           'var_rtu-8_I0'

           # All the binary tags
           >>> binary_tags = dev.retrieve("tag", {"type": "binary"})
           >>> len(binary_tags)
           2
           >>> tag in binary_tags
           True

        Args:
            attr: Attribute name to lookup as a string, e.g. ``"interface"``
            search: Dict with key-values to search for. Note that
                all key-value pairs must match for a search to succeed.

        Returns:
            The matching item or list of items if the search succeeded,
            otherwise :obj:`None` (the search failed or an error occurred). Items
            are data model objects, such as :class:`~peat.data.models.Interface`,
            :class:`~peat.data.models.Service`, or :class:`~peat.data.models.Tag`.

        Raises:
            PeatError: unexpected input or an invalid internal program state
        """
        # Basic check if it's a valid attribute
        if not hasattr(self, attr):
            raise PeatError(
                f"Data does not have attribute '{attr}'. "
                f"You should never see this error, if you are "
                f"then there's a severe bug in the PEAT module!"
            )

        obj = getattr(self, attr)  # Attempt to get the object
        if not obj:
            return None

        found = []
        for val in obj:
            # Compare the key/value pairs in search dict against the
            #   attributes of each value in the top-level container.
            if all(getattr(val, k, None) == v for k, v in search.items()):
                found.append(val)

        if len(found) == 1:
            return found[0]  # Found one result, return the item
        elif len(found) >= 2:
            return found  # Multiple results, return list of items
        return None

    def store(
        self,
        key: Literal[
            "interface",
            "service",
            "ssh_keys",
            "registers",
            "tag",
            "io",
            "event",
            "memory",
            "module",
            "users",
            "uefi_image",
            "uefi_hashes",
            "files",
        ],
        value: BaseModel,
        lookup: str | list | dict | None = None,
        interface_lookup: dict | None = None,
        append: bool = False,
    ) -> None:
        """
        Add or update complex device data.

        .. code-block:: python

           >>> from datetime import datetime
           >>> from pprint import pprint
           >>> from peat.data import DeviceData, Interface, Memory, Tag, Register

           # Create the device instance
           >>> dev = DeviceData()

           # Add a single network interface with IP of 192.0.2.20
           # NOTE: MAC address and hostname will be auto-resolved
           #       the next time "dev.populate_fields()" is called.
           >>> dev.store("interface", Interface(ip="192.0.2.20", type="ethernet"))
           >>> dev.export(only_fields="interface")
           {'interface': [{'type': 'ethernet', 'ip': '192.0.2.20'}]}

           # Add a HTTP service to the interface with an IP of 192.0.2.20
           >>> dev.store(
               "service",
               Service(protocol="http", port=80),
               # Lookup the interface for the service to be associated with
               interface_lookup={"ip": "192.0.2.20"})
           >>> dev.export(only_fields="service")
           {'service': [{'port': 80, 'protocol': 'http', 'transport': 'tcp'}]}
           >>> pprint(dev.export(only_fields="interface"))
           {'interface': [{'ip': '192.0.2.20',
                           'services': [{'port': 80,
                                         'protocol': 'http',
                                         'transport': 'tcp'}],
                           'type': 'ethernet'}]}

           # Services are also stored in interfaces
           >>> dev.service[0] == dev.interface[0].services[0]
           True

           # However, keep in mind it's not the same instance, so changes to the
           # interface in dev.service will not be reflected in the one in
           # interface.services. If making changes, use store().
           >>> dev.service[0] is dev.interface[0].services[0]
           False

           # I/O protocol registers, e.g. for Modbus and DNP3
           >>> dev.store("registers", Register(protocol="dnp3", data_type="bool"))
           >>> pprint(dev.export(only_fields="registers"))
           {'registers': [{'data_type': 'bool', 'protocol': 'dnp3'}]}

           # I/O tags, e.g. from a SCADA database
           >>> dev.store("tag", Tag(name="var_rtu-8_I0", type="binary"))
           >>> pprint(dev.export(only_fields="tag"))
           {'tag': [{'name': 'var_rtu-8_I0', 'type': 'binary'}]}

           # Store a raw read from device memory
           >>> dev.store("memory", Memory(
               address="0000FFAB",
               created=datetime(2019, 2, 25, 17, 39, 11, 507318),
               value="D3ADB33F"))
           >>> dev.memory
           [Memory(address='0000FFAB', created=datetime.datetime(2019, 2, 25, 17, 39, 11, 507318), device='192.0.2.20', value='D3ADB33F')]
           >>> pprint(dev.export(only_fields="memory"))
           {'memory': [{'address': '0000FFAB',
                        'created': '2019-02-25 17:39:11.507318',
                        'device': '192.0.2.20',
                        'value': 'D3ADB33F'}]}

           # Adding a module by constructing a new DeviceData object
           >>> io_module = DeviceData(name="digitalIO", type="I/O", slot="1")
           >>> dev.store("module", io_module)
           >>> dev.export(only_fields="module")
           {'module': [{'name': 'digitalIO', 'type': 'I/O', 'slot': '1'}]}

        .. note::
           If unset, the :attr:`~peat.data.models.DeviceData.id` attribute on this
           object will be set to the IP of the first Interface added via
           :meth:`~peat.data.models.DeviceData.store`

        .. note::
           When adding a service, the interface the service should be associated
           with can be specified by including specific keys in the ``interface_lookup`` argument.
           These keys are: ``name``, ``ip``, ``serial_port``, ``mac``, and ``hostname``.
           Example: ``interface_lookup={"ip": "192.0.2.20"}`` will add the service to the
           Interface object with an IP address of ``192.0.2.20``.

        Args:
            key: Name of the field to add or edit, e.g. ``interface`` to
                add data to a new or existing interface.
            value: Value to store. Type and structure depends
                on the field being changed.
            lookup: Values to use to search for an existing item to edit.

                .. note::
                   If :obj:`None`, then ``lookup`` will fallback to hardcoded
                   search defaults if the type is :class:`~peat.data.models.Service`
                   or :class:`~peat.data.models.Interface`.

                The lookup value can be one of the following:

                - String of an attribute name to compare, e.g. ``"ip"``
                    to use the ``ip`` attribute to compare interfaces.
                - A list of strings of attribute names to compare, e.g.
                    ``["name", "ip"]``. The attributes will be checked
                    in order, so a interface with the same ``name``
                    attribute will be merged before one that matches
                    the ``ip`` attribute.
                - a dict of values to lookup, with key being attribute name
                    and value the value to compare. ALL values MUST match for a
                    lookup to be successful!

                .. code-block:: python
                   :caption: Examples of different lookup argument data types

                   >>> from pprint import pprint
                   >>> from peat.data import DeviceData, Memory, Service, IO
                   >>> dev = DeviceData(ip="192.0.2.20")

                   # Specify name of a service to update
                   >>> dev.store("service", Service(protocol="telnet"))
                   >>> dev.export(only_fields="service")
                   {'service': [{'protocol': 'telnet', 'transport': 'tcp'}]}
                   >>> dev.store("service",
                       value=Service(status="open"),
                       lookup={"protocol": "telnet"})
                   >>> dev.export(only_fields="service")
                   {'service': [{'protocol': 'telnet', 'status': 'open', 'transport': 'tcp'}]}

                   # Lookup using a key
                   >>> dev.store("memory", Memory(address="0000FFAB"))
                   >>> dev.export(only_fields="memory")
                   {'memory': [{'address': '0000FFAB', 'device': '192.0.2.20'}]}
                   >>> dev.store("memory",
                       value=Memory(
                           address="0000FFAB",
                           created=datetime(2019, 2, 25, 17, 39, 11, 507318),
                        ),
                       lookup="address")
                   >>> pprint(dev.export(only_fields="memory"))
                   {'memory': [{'address': '0000FFAB',
                                'created': '2019-02-25 17:39:11.507318',
                                'device': '192.0.2.20'}]}

                    # Lookup using list of keys
                    >>> dev.store("io", IO(address="0001", direction="input"))
                    >>> dev.export(only_fields="io")
                    {'io': [{'address': '0001', 'direction': 'input'}]}
                    >>> dev.store("io",
                            IO(address="0001", direction="input", type="analog"),
                            lookup=["address", "direction"]
                        )
                    >>> dev.export(only_fields="io")
                    {'io': [{'address': '0001', 'direction': 'input', 'type': 'analog'}]}
            interface_lookup: :class:`dict` with :class:`~peat.data.models.Interface` attribute keys and values to lookup when storing a :class:`~peat.data.models.Service`
            append: Append the item to the list and don't attempt lookups

        Raises:
            PeatError: Invalid key specified or other
                errors indicative of issues with module code
        """
        # Require value to be a instance of a model. no dict nonsense anymore.
        if not isinstance(value, BaseModel):
            raise PeatError(
                f"Invalid value type '{value.__class__.__name__}', "
                f"expected BaseModel (value={value})"
            )
        if lookup and not isinstance(lookup, (dict, str, list)):
            raise PeatError(
                f"Invalid type '{lookup.__class__.__name__}' for 'lookup' argument "
                f"to store(), expected dict, str, or list (lookup={lookup})"
            )

        # Check the destination list attribute name is valid
        if not hasattr(self, key):
            raise PeatError(f"No attribute for key '{key}'. Value: {value}")

        # Get the list of objects (self.memory => list[Memory], etc.)
        container = getattr(self, key)  # type: list[BaseModel]

        # Automatically call annotate()
        value.annotate(self)

        # Append item to the list and return, don't lookup
        if append:
            container.append(value)
            return

        # !! hack !!
        # Fallback to hardcoded values for Service and Interface if lookup is None
        if not lookup:
            if isinstance(value, Service):
                lookup = ["protocol", "port"]
            elif isinstance(value, Interface):
                lookup = ["name", "mac", "ip", "serial_port", "id"]
            elif isinstance(value, File):
                if value.local_path:
                    lookup = "local_path"
                elif value.path:
                    lookup = "path"
                else:
                    lookup = "name"

        # Add the value to the container, and merge with any existing values
        # if they match the lookup
        value = self._lookup_and_merge(container, value, lookup)

        # If it's a service, add it to relevant interface(s)
        # NOTE: if there isn't a positive match for a interface lookup,
        # then the default is to NOT add it to any interfaces
        if interface_lookup and isinstance(value, Service):
            if_position = match_all(self.interface, interface_lookup)
            if if_position is not None:
                # Merge with existing services on the interface
                self._lookup_and_merge(
                    self.interface[if_position].services, value, lookup
                )

        # Copy comm attributes from first interface added
        if key == "interface" and len(self.interface) == 1:
            # Ensure serial_port and ip/etc are mutually exclusive
            if not self.serial_port and self.interface[0].serial_port:
                self.serial_port = self.interface[0].serial_port
            else:
                for attr in ["ip", "mac", "hostname"]:
                    if not getattr(self, attr, None):
                        val = getattr(self.interface[0], attr, None)
                        if val:
                            setattr(self, attr, val)
                            if not self.id:
                                self.id = val

    def _lookup_and_merge(
        self,
        container: list[BaseModel],
        value: BaseModel,
        lookup: str | list | dict | None,
    ) -> BaseModel:
        """
        Handle adding objects to lists.

        This is needed as a standalone method from store() so
        services can be added to interfaces in the same manner
        as they are in store().
        """
        # Append to a list of objects if no lookup is specified
        # If there is a lookup specified, and the list is empty,
        # just append it since there's nothing to look up.
        if not lookup or not container:
            container.append(value)
            return value

        # Attempt to lookup an existing object in the list of objects
        position = None  # type: Optional[int]
        if isinstance(lookup, str):
            # Attribute to use for lookup, e.g. "ip" for Interface
            position = lookup_by_str(container, value, lookup)
        elif isinstance(lookup, list):
            # List of attributes to use for lookup,
            # e.g. ["port", "protocol"] for Service
            # NOTE: only one value needs to match for lookup to succeed
            for lookup_str in lookup:
                position = lookup_by_str(container, value, lookup_str)
                if position is not None:
                    break
        elif isinstance(lookup, dict):
            # Multiple key-value pairs to look for, e.g.
            # {"ip": "192.0.2.123", "type": "Ethernet"}
            # NOTE: ALL values must match for lookup to succeed
            position = match_all(container, lookup)
        else:
            raise PeatError(
                f"Invalid type '{lookup.__class__.__name__}' for 'lookup' argument "
                f"to store(), expected str, list, or dict (lookup={lookup})"
            )

        # If the lookup was successful, then copy the values from
        # the new object to existing object
        if position is not None:
            merge_models(container[position], value)
            container[position].annotate(self)
            value = container[position]
        # Otherwise, just append the value to the list
        else:
            container.append(value)

        return value

    def is_duplicate(self, other: DeviceData) -> bool:
        """
        If this device is likely a duplicate of another.

        .. note::
           Only deduplicate if devices have the same communication ID (IP, MAC, Serial port) or label (from a PEAT config file)

        Args:
            other: Device to compare

        Returns:
            If the device is likely a duplicate of this device
        """
        # NOTE: we assume SEL devices with different serial numbers or part numbers
        # are different devices. This fixes an issue with parsing large numbers
        # of SEL files.
        if self.description.vendor.id == "SEL" and other.description.vendor.id == "SEL":
            for attr in ["part_number", "serial_number"]:
                this_val = getattr(self, attr, None)
                other_val = getattr(other, attr, None)

                if this_val and other_val and this_val != other_val:
                    return False

        for attr in ["label", "ip", "mac", "serial_port"]:
            this_val = getattr(self, attr, None)
            other_val = getattr(other, attr, None)

            # If current value is not empty or None,
            # and equals the other devices value,
            # then mark it as a duplicate
            if this_val and other_val == this_val:
                return True

        return False

    def purge_duplicates(self, force: bool = False) -> None:
        """
        Removes duplicates from all :class:`list`-type attributes on this object
        that aren't private.

        Once performed, ``self._is_deduplicated`` is set to True. If True,
        subsequent calls won't perform deduplication. To override this behavior,
        set force=True, or set ``self._is_deduplicated`` to False.
        """
        if self._is_deduplicated and not force:
            return

        log.debug(f"Purging duplicates from device '{self.get_id()}'")

        # Iterate over all list-type attributes
        for list_attr in self.get_attr_names(list):
            val = getattr(self, list_attr, None)

            # TODO: temporary hack to only deduplicate smaller lists
            #   "Large" lists of even just 30,000 objects can take close
            #   to an hour to dedupe!
            #   Need to refactor how models are stored and how deduplication
            #   occurs.
            if val and len(val) < 5000:
                deduped = dedupe_model_list(val)
                sort_model_list(deduped)
                setattr(self, list_attr, deduped)

        self._is_deduplicated = True

    def get_attr_names(self, typ: type) -> list[str]:
        """
        Get names of attributes on this instance that aren't private.

        Args:
            typ: Class to check for, e.g. :class:`list` or BaseModel
        """
        attrs = [k for k in self.__dict__.keys() if not k.startswith("_")]

        attribute_names = [
            attr for attr in attrs if isinstance(getattr(self, attr, None), typ)
        ]

        return attribute_names


# Required by pydantic to resolve types that are "forward-references" (self-referential)
DeviceData.update_forward_refs()


def process_file(file: dict | File) -> File:
    """
    Transform a :class:`dict` into a :class:`~peat.data.models.File` object
    and populate unfilled fields.
    """
    # Convert the dict into a new File instance
    if isinstance(file, dict):
        file = File.parse_obj(file)

    # Create the path from the directory and name (note: the name includes extensions)
    if not file.path and (file.directory and file.name):
        file.path = PurePath(file.directory, file.name)

    # Resolve to absolute path
    if file.local_path and file.local_path.exists():
        file.local_path = file.local_path.resolve()

    # If path isn't set, then set it to the local path
    if not file.path and file.local_path:
        file.path = PurePath(file.local_path)

    # Use local file metadata to fill out fields, e.g. size, modification time, etc.
    if file.local_path and file.local_path.is_file():
        try:
            if not file.mtime:
                mtime = file.local_path.stat().st_mtime
                file.mtime = datetime.fromtimestamp(mtime)

            if not file.created:
                ctime = file.local_path.stat().st_ctime
                file.created = datetime.fromtimestamp(ctime)

            # .owner() and .group() don't work on Windows
            # WINDOWS: NotImplementedError: Path.group() is unsupported on this system
            if not WINDOWS:
                if not file.group:
                    file.group = file.local_path.group()
                if not file.owner:
                    file.owner = file.local_path.owner()
        except (NotImplementedError, OSError, KeyError) as err:
            msg = (
                f"Failed to get ownership info and/or timestamps "
                f"for file '{file.local_path.name}'. This can occur if "
                f"you're running PEAT in a container environment "
                f"(e.g. Docker or podman). Error that occurred: {err}"
            )
            # KeyError: 'getgrgid(): gid not found: 89040'
            # If in a docker container it's not important, so log as debug
            # This shouldn't happen outside of a container, so log that as a warning
            if SYSINFO.get("containerized"):
                log.debug(msg)
            else:
                log.warning(msg)

        if not file.size:
            file.size = file.local_path.stat().st_size

        if not _all_hashes_set(file.hash):
            file.hash = Hash.parse_obj(utils.gen_hashes(file.local_path))

    if not file.directory and file.path:
        file.directory = file.path.parent.as_posix()

    if not file.name and file.path:
        file.name = file.path.name

    if not file.type and (file.path or file.local_path):
        file_type = "file"

        if file.local_path:
            try:
                if file.local_path.is_dir():
                    file_type = "dir"
            except Exception:
                pass

        file.type = file_type

    process_file_extension(file)

    if file.directory and not file.directory.endswith("/"):
        file.directory += "/"

    return file


def process_file_extension(file: File) -> None:
    """
    Automatically infer and populate unset fields
    on a :class:`~peat.data.models.File` object.
    """
    if not file.extension and file.path:
        # NOTE: we just get the last extension even if a file may have more,
        #   e.g. ".tar.gz" will only save as ".gz". This is due to many files
        #   having multiple "."'s in them, so joining suffixes leads to weird
        #   output.
        # NOTE2: make extension lowercase even if filename is upper case for
        #   consistent matching/searching, since the Elastic type is "keyword".
        file.extension = file.path.suffix.lower().strip(".")
    elif not file.extension and not file.path and "." in file.name:
        file.extension = ".".join(PurePath(file.name).suffixes).lower().strip(".")

    if file.extension:
        file.extension = file.extension.lower().strip(".").split(".")[-1]

    if not file.mime_type and not file.type == "dir":
        # Hardcode known binary file types
        if file.extension in [
            "rdb",
            "db",
            "pkl",
            "dmk",
            "apx",
            "ztx",
            "stu",
            "mc7",
            "firmware",
            "dcf",
        ]:
            file.mime_type = "application/octet-stream"
        # Hardcode known text file types
        elif file.extension in ["upg", "st"]:
            file.mime_type = "text/plain"
        elif file.name:
            # guess_type() returns: tuple(type, encoding)
            guessed_type = mimetypes.guess_type(file.name, strict=False)[0]
            if guessed_type:
                # Windows returns "text/xml" instead of "application/xml"
                # for unknown (though likely historical) reasons. The latter
                # form is preferred for our use cases, and for consistency
                # across platforms. Refer to RFC 3023 for more details:
                # https://tools.ietf.org/html/rfc3023
                if guessed_type == "text/xml":
                    guessed_type = "application/xml"
                file.mime_type = guessed_type


def annotate_obj_and_file(
    obj: Firmware | Logic, field_name: str, dev: DeviceData
) -> None:
    """
    Populate original field if not set,
    and save data to file if it hasn't been.
    """
    obj.file.annotate(dev)

    process_file(obj.file)

    # If no raw data and the file has data, read data from the file
    if not obj.original and obj.file.local_path and obj.file.local_path.is_file():
        if isinstance(obj, Firmware):
            obj.original = obj.file.local_path.read_bytes()
        else:
            try:
                with obj.file.local_path.open(encoding="utf-8", newline="") as f:
                    obj.original = f.read()
            except UnicodeDecodeError:
                log.warning(
                    f"Skipping save of non-text source for logic "
                    f"(source: {obj.file.local_path})"
                )

    # If there's data and the data hasn't been saved locally (and output directory is set)
    if obj.original and not obj.file.local_path and config.DEVICE_DIR:
        file_ext = obj.file.extension
        if not file_ext:
            file_ext = ".bin" if isinstance(obj.original, bytes) else ".txt"
        if not file_ext.startswith("."):
            file_ext = f".{file_ext}"

        obj.file.local_path = dev.write_file(
            data=obj.original,
            # "firmware", "boot-firmware", "logic"
            filename=field_name.lower().replace("_", "-") + file_ext,
        )

    process_file(obj.file)

    # Calculate hashes for original
    if obj.original and not _all_hashes_set(obj.hash):
        obj.hash = Hash.parse_obj(utils.gen_hashes(obj.original))
        _add_hashes_to_related(dev, obj.hash)


def _all_hashes_set(hash_obj: Hash) -> bool:
    """
    Check all hashes in ``config.HASH_ALGORITHMS``
    have been calculated and set.
    """
    for algo in config.HASH_ALGORITHMS:
        if hasattr(hash_obj, algo) and not getattr(hash_obj, algo, None):
            return False
    return True


def _add_hashes_to_related(dev: DeviceData, hash_obj: Hash) -> None:
    """
    Add any hashes to ``dev.related.hash``.
    """
    for algo in config.HASH_ALGORITHMS:
        hash_value = getattr(hash_obj, algo, None)
        if hash_value and hash_value not in dev.related.hash:
            dev.related.hash.add(hash_value.upper())


def export_models_to_elastic(
    models: list[BaseModel], dev: DeviceData, elastic: Elastic | None = None
) -> bool:
    """
    Export model objects to an Elasticsearch database.

    Under the hood, this uses the Elasticsearch Bulk API to do efficient
    exporting in parallel and with fewer API requests.

    Args:
        models: the models to export. All models in the list must be
            of the same type (don't mix models). To export a single
            model, wrap the model in a list, e.g. ``models=[mymodel]``.
        dev: the DeviceData object the model(s) are associated with
        elastic: The :class:`~peat.elastic.Elastic` instance to use.
            If unspecified, this defaults to the global
            :class:`~peat.elastic.Elastic` instance in
            :attr:`~peat.settings.State.elastic`.

    Returns:
        True if the export was successful, False if there were any errors
    """

    dev_id = dev.get_id()

    elastic = resolve_es_instance(elastic, dev_id)
    if not elastic:
        return False

    # Resolve configuration name to the configured index name
    # If this fails, you probably messed up your model class :)
    mn = models[0].__repr_name__()
    if not hasattr(config, models[0]._es_index_varname):
        log.critical(
            f"Failed to determine index name for '{mn}': PEAT config "
            f"has no attribute '{models[0]._es_index_varname}'"
        )
        state.error = True
        return False

    if not all(m.__repr_name__() == mn for m in models):
        log.critical("Mixed model types in export_models_to_elastic!")
        state.error = True
        return False

    # Skip push if index is disabled (config value is "" or None)
    ts_index = getattr(config, models[0]._es_index_varname, None)
    if not ts_index:
        return True

    to_push = []
    for model in models:
        content = model.gen_elastic_content(dev)
        content = utils.sort(content)  # Sort for determinism/consistency

        # Save doc ID of first push, subsequent calls should just update the
        # existing doc. This ensures it's safe to call this at various points
        # of execution without creating a bunch of copies in the same run.
        if not model._elastic_doc_id:
            model._elastic_doc_id = elastic.gen_id()
        elif config.DEBUG >= 3:
            log.trace3(
                f"Updating EXISTING timeseries '{mn}' data from device "
                f"'{dev_id}' to {elastic.type} server {elastic!s}"
            )

        to_push.append((model._elastic_doc_id, content))

    failed_msg = (
        f"Failed {elastic.type} export for '{mn}' timeseries data from "
        f"device '{dev_id}' to {elastic.type} server {elastic!s}"
    )

    try:
        if not elastic.bulk_push(
            index=ts_index,
            contents=to_push,
        ):
            log.error(failed_msg)
            state.error = True
            return False
    except Exception:
        log.exception(failed_msg)
        state.error = True
        return False

    return True


def resolve_es_instance(elastic: Elastic | None, dev_id: str) -> Elastic | None:
    if not elastic:  # Use the global instance by default
        elastic = state.elastic
    if not elastic:
        log.error(
            f"export_models_to_elastic() called for device '{dev_id}' but "
            f"Elasticsearch or OpenSearch has not been configured or initialized!"
        )
        state.error = True

    return elastic


__all__ = [
    "IO",
    "OS",
    "X509",
    "CertEntity",
    "Description",
    "DeviceData",
    "Event",
    "File",
    "Firmware",
    "Geo",
    "Hardware",
    "Hash",
    "Interface",
    "LatLon",
    "Logic",
    "Memory",
    "Register",
    "Related",
    "SSHKey",
    "Service",
    "Tag",
    "User",
    "Vendor",
    "export_models_to_elastic",
    "process_file",
]

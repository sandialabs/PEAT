"""
Simple Network Management Protocol (:term:`SNMP`) functionality for PEAT.

Under the hood, PEAT uses the lovely open-source
`PySNMP <https://github.com/etingof/pysnmp>`__
package (NOTE: as of May 2024, we now use
`a fork <https://github.com/lextudio/pysnmp>`__).

The code in this file is essentially a wrapper around
``pysnmp`` with error handling, logging, and other additions.

``1.3.6.1. = iso.org.dod.internet = Any network device``.

**Building custom MIBs**

Use ``mibdump.py`` or ``build-pysnmp-mib`` (included with PySNMP)
to build a :term:`MIB` in a format usable by PySNMP for use with PEAT.

NOTE: once the MIBs are generated, make sure they're included in the PyInstaller
spec file that's used to build the PEAT executable, in ``distribution/peat.spec``.

- Example 1: ``mibdump.py --generate-mib-texts SIEMENS-SMI``.
  This should generate a PySNMP module for the ``SIEMENS-SMI.mib`` file in ``~/.pysnmp/mibs``.
- Example 2: ``build-pysnmp-mib -o SipOptical.py SipOptical.mib``

References/further reading:

- https://github.com/lextudio/pysnmp
- https://www.pysnmp.com/
- https://github.com/etingof/pysnmp/docs/pysnmp-hlapi-tutorial.rst

Authors:

- Christopher Goes
"""

import os.path
from copy import deepcopy
from pathlib import Path
from typing import Final

from pyasn1.codec.native.encoder import encode
from pysnmp.hlapi import (
    CommunityData,
    ContextData,
    ObjectIdentity,
    ObjectType,
    SnmpEngine,
    UdpTransportTarget,
    getCmd,
    nextCmd,
)
from pysnmp.smi.builder import DirMibSource, MibBuilder

import peat
from peat import consts, config, state, utils, exit_handler, log

# https://www.iana.org/assignments/ianaiftype-mib/ianaiftype-mib
INTERFACE_MAP: Final[dict[int, str]] = {
    1: "other",
    6: "ethernet",
    24: "loopback",
}


class SNMP:
    """
    Generic wrapper for Simple Network Management Protocol (SNMP) functionality.
    """

    def __init__(
        self,
        ip: str,
        port: int = 161,
        timeout: float = 1.0,
        community: str = "public",
        snmp_version: int = 1,
        mib_paths: list[str | Path] | None = None,
    ) -> None:
        """
        Args:
            ip: IP address of the SNMP device
            port: UDP port of the SNMP device
            timeout: Number of seconds to wait for a response
            community: SNMP Community string to use
                (this is a plain-text credential used for authentication).
            snmp_version: Version of SNMP to use (1 = v1 | 2 = v2c)
            mib_paths: List of paths to MIB files to use for lookups.
                These ``.py`` files compiled from a MIB by PySNMP.
        """
        self.ip: str = ip
        self.port: int = port
        self.timeout: float = timeout
        self.community: str = community
        self.snmp_version: int = snmp_version
        self.log = log.bind(
            classname=self.__class__.__name__,
            target=f"{self.ip}:{self.port}",
        )

        # TODO: globally cache MIB file loads so they only happen once per PEAT run
        self.mib_paths: list[str] = [
            # Include MIBs that are included with PEAT
            str(Path(Path(__file__).parent, "mibs").resolve()),
        ]
        if mib_paths:
            for path in mib_paths:
                # Convert Path object to absolute path str for use with PySNMP
                if isinstance(path, Path):
                    path = str(path.resolve())
                if not os.path.exists(path):
                    self.log.error(f"MIB '{path}' doesn't exist, skipping...")
                    continue
                self.mib_paths.append(path)
        self.log.trace2(f"mib_paths: {self.mib_paths}")

        # SNMPv1 (1) => mpModel 0
        # SNMPv2c (2) => mpModel 1
        mp_model = self.snmp_version - 1
        if mp_model < 0 or mp_model > 1:
            state.error = True
            raise ValueError(f"Invalid SNMP version: {self.snmp_version}")

        self.engine = SnmpEngine()
        self.community_data = CommunityData(self.community, mpModel=mp_model)
        self.transport = UdpTransportTarget((self.ip, self.port), timeout=self.timeout)
        self.context = ContextData()

        self.all_output: dict[str, list[dict]] = {}

        # auto-save output to disk on exit
        exit_handler.register(self._save_all_output, "FILE")

        self.log.trace2(f"Initialized {repr(self)}")

    def __str__(self) -> str:
        return self.ip

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}({self.ip}, {self.port}, {self.timeout}, "
            f"'{self.community}', {self.snmp_version}, {self.mib_paths})"
        )

    def _save_all_output(self) -> None:
        """
        Save the raw output to disk as an artifact.
        """
        if self.all_output:
            try:
                dev = peat.data.datastore.get(self.ip)
                dev.write_file(
                    self.all_output, "raw-snmp-output.json", merge_existing=True
                )
            except Exception as ex:
                self.log.warning(f"Failed to write raw output to file: {ex}")

    def get(
        self,
        identity: str | tuple,
        single_query: bool = True,
        query_limit: int = 0,
        walk_whole_mib: bool = False,
    ) -> list[dict]:
        """
        Gets the value(s) of a SNMP object.

        The SNMP object is referenced by passing a :class:`tuple` to the
        ``identity``argument. This is then passed directly to PySNMP.
        Additionally, a custom MIB definition can be used by providing an
        absolute file path to the ``mib_path`` argument.

        The object identity can be one of the following:

        - OID
        - MIB name (this will enumerate the entire MIB)
        - MIB name + object name
        - MIB name + object name + instance number (for an enumeration/table)
        - Any of the above + a custom MIB definition file to use

        Examples:

        .. code-block:: python

           from pathlib import Path
           from peat.protocols.snmp import SNMP
           snmp = SNMP(ip="192.0.2.1")
           # OID
           snmp.get("1.3.6.1.2.1.1.1.0")
           # "Walk" all values out of a MIB
           snmp.get("SNMPv2-MIB", single_query=False)
           # MIB + Object
           snmp.get(("SNMPv2-MIB", "sysDescr"))
           # MIB + Object + Instance
           snmp.get(("SNMPv2-MIB", "sysDescr", 0))
           # Custom MIB definition file with a Path object (absolute path)
           snmp_with_mib = SNMP(ip="192.0.2.1", mib_paths=[Path("/path/myMib.py")])
           snmp_with_mib.get(("MyMib", "myObj"))
           # Custom MIB definition file with a raw string (absolute path)
           snmp_with_mib = SNMP(ip="192.0.2.1", mib_paths=["/path/myMib.py"])
           snmp_with_mib.get(("MyMib", "myObj"))

        Args:
            identity: Tuple used to reference the SNMP object.
                Refer to function documentation above for details.
            single_query: If :obj:`True`, the OID will be queried once with ``getCmd``.
                Otherwise, it will be iterated over using ``nextCmd`` until there is no
                more data (for OIDs with "sub values", e.g. tables or enumerations).
            query_limit: If ``single_query`` is :obj:`False`, limit the iteration to this
                number of queries and stop. This is cheap workaround if you don't have a MIB.
            walk_whole_mib: If all values in a MIB should be walked.
                This sets ``lexicographicMode=True`` in PySNMP ``nextCmd``.

        Returns:
            :class:`list` of values, or an empty :class:`list` if the get failed.

        Raises:
            ValueError: If a critical error occurred, such as a invalid type being passed
        """
        if not identity:
            state.error = True
            raise ValueError(f"{self.ip}: empty identity provided")

        if isinstance(identity, bytes):  # Handle bytes, just in case
            identity = identity.decode()

        if not isinstance(identity, (str, tuple)):
            state.error = True
            raise ValueError(
                f"{self.ip}: identity is not str or tuple (value={identity})"
            )

        if isinstance(identity, str):
            identity = (identity,)  # Convert str to 1-item tuple

        self.log.trace(f"SNMP query: {identity}")
        object_identity = ObjectIdentity(
            *identity
        )  # TODO: self.cache of these objects?

        # Add a local MIB file to use for resolving names and types
        if self.mib_paths:
            for mib_path in self.mib_paths:
                object_identity.addMibSource(mib_path)

        # Create and call a PySNMP generator object
        if single_query:
            querier = getCmd(
                self.engine,
                self.community_data,
                self.transport,
                self.context,
                ObjectType(object_identity),
            )
        else:
            querier = nextCmd(
                self.engine,
                self.community_data,
                self.transport,
                self.context,
                ObjectType(object_identity),
                lexicographicMode=walk_whole_mib,
            )
        if querier is None:
            raise ValueError(
                f"{self.ip}: bad querier iterator (single_query={single_query})"
            )

        values = []
        finished = False
        query_counter = 0

        # Keep querying nextCmd until it's exhausted
        # For getCmd, it'll usually just iterate once and finish
        while not finished:
            try:
                error_indication, error_status, error_index, var_binds = next(querier)

                if error_indication:  # SNMP engine errors
                    self.log.debug(f"SNMP engine error: {error_indication}")
                    return []
                elif error_status:  # SNMP agent errors
                    errloc = var_binds[int(error_index) - 1] if error_index else "?"
                    pretty_err = error_status.prettyPrint()
                    self.log.debug(
                        f"SNMP agent error: '{pretty_err}' at location {errloc}"
                    )
                    return []
                elif isinstance(var_binds[0][1], ObjectIdentity):
                    self.log.debug(
                        f"Skipping ObjectIdentity response payload "
                        f"for {var_binds[0][1].prettyPrint()} "
                        f"(oid: {var_binds[0][1].getOid()})"
                    )
                else:
                    # https://stackoverflow.com/questions/41544110/pysnmp-form-dictionary-from-table
                    # TODO: handle cases where len(var_binds) > 1
                    var_name, var_value = var_binds[0]
                    # ('SNMPv2-MIB', 'sysDescr', (<ObjectName value object, tagSet <TagSet object, tags 0:0:6>, payload [0]>,))  # noqa: E501
                    mib_name, object_name, object_instance_id = var_name.getMibSymbol()
                    # Return as a string
                    try:
                        # Some ASN.1 classes get garbled when you force them to strings
                        # A lot of them have a function that stringifies the class
                        value_string = str(var_value.prettyOut(var_value))
                    except Exception:
                        value_string = str(var_value)
                    var_dict = {
                        "index": ".".join([str(i) for i in object_instance_id]),
                        "mib_name": mib_name,
                        "object_name": object_name,
                        # "SNMPv2-MIB::sysDescr.0"
                        "pretty_name": var_name.prettyPrint(),
                        "oid": str(var_name.getOid()),
                        "value_encoded": encode(var_value),
                        "value_string": value_string,
                        "value_string_original": value_string,
                    }

                    # auto-convert interface types to PEAT-standard names
                    if object_name == "ifType":
                        if var_dict["value_encoded"] in INTERFACE_MAP:
                            var_dict["value_string"] = INTERFACE_MAP[
                                var_dict["value_encoded"]
                            ]
                        else:
                            var_dict["value_string"] = utils.convert_to_snake_case(
                                var_dict["value_string"]
                            )
                    values.append(var_dict)
                    if config.DEBUG >= 2:
                        self.log.trace2(f"var_dict: {consts.convert(var_dict)}")
            except StopIteration:
                finished = True

            query_counter += 1
            if query_counter and query_counter == query_limit:
                finished = True

        self.all_output[utils.utc_now().isoformat()] = deepcopy(values)

        return values

    def verify(self, identity: str | tuple, to_find: str | list[str]) -> bool:
        """
        Checks if a string is in the response data for an SNMP query.

        Args:
            identity: Tuple used to reference the SNMP object.
            find: String(s) to search the response for

        Returns:
            If the verification succeeded

        Raises:
            ValueError: If a critical error occurred, such as a invalid type being passed
        """
        self.log.debug(
            f"Verifying SNMP device with identity '{identity}' "
            f"and search string {to_find}"
        )

        try:
            data = self.get(identity)
            if data:
                data = str(data[0]["value_string"]).lower()
        except Exception as ex:
            self.log.error(f"Failed SNMP verification due to unhandled exception: {ex}")
            data = None

        # Check if the desired string or strings is in the response
        if data is None:
            is_valid = False
        elif isinstance(to_find, str) and to_find.lower() in str(data):
            is_valid = True
        elif isinstance(to_find, list) and any(x.lower() in str(data) for x in to_find):
            is_valid = True
        else:
            is_valid = False

        if is_valid:
            log.info("SNMP verification succeeded")
        else:
            log.debug("SNMP verification failed")

        return is_valid


# TODO: move to class or delete, since SNMP.get() can do this with a MIB name parameter
def snmp_walk(
    ip: str,
    mib_name: str,
    mib_src: str | Path,
    community: str = "public",
    timeout: float = 0.5,
    port: int = 161,
    snmp_version: int = 1,
) -> dict:
    """
    Walks an SNMP MIB and returns a dictionary of names and values

    Args:
        ip: IPv4 address of the SNMP device
        mib_name: Name of the mib to reference
        mib_src: Filesystem path to the MIB file, which must be a PySNMP module (optional)
        timeout: Number of seconds to wait for a response
        community: SNMP Community string to use
        port: Port the device's SNMP server is listening on
        snmp_version: Version of SNMP to use (1 = v1 | 2 = v2c)

    Returns:
        A dictionary of names and values. An empty :class:`dict` is returned
        if there was an error.
    """
    if isinstance(mib_src, Path):
        mib_src = str(mib_src.resolve())

    # Create an instance of the builder
    mib_builder = MibBuilder()

    # Set an alternative path to compiled MIBs
    mib_sources = (DirMibSource(mib_src),)
    mib_builder.setMibSources(*mib_sources)

    # Loading modules
    mib_builder.loadModules(mib_name)

    # Perform the walk
    walk_results = {}
    for error_indication, error_status, error_index, var_binds in nextCmd(
        SnmpEngine(),
        CommunityData(community, mpModel=snmp_version - 1),
        UdpTransportTarget((ip, port), timeout=timeout),
        ContextData(),
        ObjectType(ObjectIdentity(mib_name).addMibSource(mib_src)),
        lexicographicMode=False,
        lookupNames=True,
        lookupValues=True,
    ):
        if error_indication:
            log.debug(f"SNMP Walk error for {ip}:{port}: {error_indication}")
            break

        if error_status:
            errloc = var_binds[int(error_index) - 1] if error_index else "?"
            pretty_err = error_status.prettyPrint()
            log.debug(
                f"SNMP agent error for {ip}:{port}: '{pretty_err}' at location {errloc}"
            )
            break

        for varBind in var_binds:
            try:
                name = varBind[0].prettyPrint()
                name = name[len(mib_name) + 2 : name.find(".")]
                value = varBind[1].prettyPrint()
                log.trace(f"SNMP value for {ip}:{port}: {value}")
                walk_results[name] = value
            except Exception as err:
                log.error(f"{type(err).__name__}: {err}")
                return walk_results

    return walk_results


__all__ = ["SNMP", "snmp_walk"]

from typing import Literal
from collections.abc import Callable

from pydantic import conint, constr

from peat.data.base_model import BaseModel


class IdentifyMethod(BaseModel):
    name: str
    """Human-friendly name for the method."""

    description: str
    """Human-friendly description of the method."""

    identify_function: Callable | None
    """
    Python function used to perform the verification.

    .. note::
       This is the identification function itself, since functions
       are first-class objects in Python and can be treated like classes
    """

    reliability: conint(ge=0, le=10)
    """
    Reliability of a method.
    Value ranges from from 0 (unknown reliability) to 10 (very reliable).
    Values of 5 or below are considored to have at least some degree
    of inconsistency or "flakiness" (e.g. Telnet user interface),
    while 6 and up are considored to be fairly reliable (e.g. HTTP).
    This is used by PEAT to sort methods during discovery
    and other similar contexts, as well as for future features.
    """


class IPMethod(IdentifyMethod):
    """
    Method for identifying devices via networking protocols (IP, Ethernet).
    """

    protocol: constr(strip_whitespace=True, to_lower=True)
    """
    Lowercase name of the protocol used.

    .. note::
       Similar protocols, such as ``http`` and ``https``,
       should be two separate :class:`~peat.api.identify_methods.IPMethod`
       instances with nearly identical attributes
    """

    transport: Literal["tcp", "udp", "other"]
    """
    Network transport protocol.

    Allowed values:

    - ``tcp``
    - ``udp``
    - ``other``
    """

    type: Literal["unicast_ip", "broadcast_ip"]
    """
    The type of IP method this is.

    Allowed values for this method (IPMethod):

    - ``unicast_ip``
    - ``broadcast_ip``
    """

    default_port: conint(ge=1, le=65535)
    """
    Default protocol port used by the service the method interacts with.
    Note that a different port may be used if configured at runtime.
    """

    port_function: Callable | None = None
    """
    Python function used to check if the port is open.
    Defaults to standard TCP/UDP check based on the value of
    ``transport`` (e.g. a ``transport`` of ``tcp`` will cause
    PEAT to use a TCP SYN-RST method to check if the port is open).
    """


class SerialMethod(IdentifyMethod):
    """
    Method for identifying devices via Serial interfaces and protocols (e.g. RS-232).
    """

    type: Literal["direct"]
    """
    The type of method, is it direct or broadcast?

    Currently, only "direct" is used, but "broadcast" may be
    added in the future for transports like CANbus, RS485, etc.

    Allowed values for this method (SerialMethod):

    - ``direct``
    """


__all__ = ["IPMethod", "IdentifyMethod", "SerialMethod"]

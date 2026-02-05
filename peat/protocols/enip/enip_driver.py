from __future__ import annotations

import random

from peat import log
from peat.protocols.cip.cip_const import (
    CIP_SC_BYTES,
    CLASS_CODE,
    CLASS_ID,
    CONNECTION_MANAGER_INSTANCE,
    INSTANCE_ID,
)
from peat.protocols.common import scapy_human_field
from peat.protocols.data_packing import *

from .enip_const import (
    ADDRESS_ITEM,
    CONNECTION_PARAMETER,
    CONNECTION_SIZE,
    DATA_ITEM,
    ENIP_SEQ_MAX,
    ENIP_SEQ_MIN,
    PRIORITY,
    TIMEOUT_MULTIPLIER,
    TIMEOUT_TICKS,
    TRANSPORT_CLASS,
    EnipCommError,
)
from .enip_packets import (
    ENIP,
    ENIPListIdentityResponse,
    ENIPListInterfacesResponse,
    ENIPListServicesResponse,
)
from .enip_socket import EnipSocket

# TODO (cegoes, 06/02/2023): rewrite packet generation using Scapy
#   This will be transformed into a interface for working with ENIP endpoints
#   by wrapping the packet construction, session handling, etc. in a class
#   basically what pycomm did, but simpler and easier to maintain, with better
#   error handling and logging.
#   Combine much of the functionality currently in ab_scan and elsewhere into here.
#   NOTE: this assumes unicast, need to properly handle broadcast. maybe separate file
#   with generalized functions (like discovery) that can be used for unicast or broadcast.
# TODO: leverage scapy to take PCAPs?


class EnipDriver:
    """
    Ethernet/IP (ENIP) protocol handler.
    """

    def __init__(
        self,
        enip_socket: EnipSocket,
        cpu_slot: int = 0,
        rpi: int = 5000,
        timeout: int = 0xAF12,
        backplane: int = 1,
        cid_ot: bytes = b"\x00\x00\x00\x00",
        cid_to: bytes = b"\x27\x04\x19\x71",
        csn: bytes = b"\x8f\x00",
        vid: bytes = b"\x4d\x00",
        vsn: bytes = b"\x71\x6e\x4c\x0c",
    ) -> None:
        self.log = log.bind(
            classname=self.__class__.__name__,
            target=f"{enip_socket.ip}:{enip_socket.port}",
        )

        self.enip_socket = enip_socket
        self.cpu_slot = cpu_slot
        self.rpi = rpi
        self.timeout = timeout
        self.backplane = backplane
        self.cid_ot = cid_ot
        self.cid_to = cid_to

        self.csn = csn
        self.vid = vid
        self.vsn = vsn

        self.sequence = random.randint(ENIP_SEQ_MIN, ENIP_SEQ_MAX)
        self.session = 0
        self.is_forward_opened = False

        self.log.trace(f"Initialized {self.__class__.__name__}")

    def __enter__(self) -> EnipDriver:
        if not self.open():
            raise ConnectionError(f"failed to connect to {str(self.enip_socket)}")
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> bool:
        retval = self.close()
        if exc_type:
            self.log.debug(f"{exc_type.__name__}: {exc_val}")
        return retval

    def __str__(self) -> str:
        return f"{self.enip_socket.ip}:{self.enip_socket.port}"

    def open(self) -> bool:
        """
        Connect and open a session with the device.

        Raises:
            EnipCommError: exception occurred while opening the session
        """
        if self.enip_socket.connect() and self.register_session() is not None:
            return self.forward_open()

        self.log.warning("Sessions not registered")
        return False

    def close(self) -> bool:
        """
        Close the session with the device and the underlying socket.

        Returns:
            If the close was successful

        Raises:
            EnipCommError: Exception occurred while unregistering the session
        """
        retval = True
        try:
            if self.is_forward_opened:
                try:
                    retval = self.forward_close()
                except EnipCommError as ex:
                    self.log.warning(
                        f"Exception occurred during forward_close, the connection "
                        f"may not have been cleaned up properly. Exception: {ex}"
                    )
                    if self.enip_socket.is_connected:
                        self.enip_socket.close()
                    return False

            if self.session:
                self.unregister_session()

            if self.enip_socket.is_connected:
                self.enip_socket.close()
        except Exception as err:
            raise EnipCommError(err) from None

        return retval

    def send(self, msg: bytes) -> int:
        """
        Sends a message through the ENIP socket.

        Returns:
            Number of bytes sent

        Raises:
            EnipCommError: if the send failed
        """
        return self.enip_socket.send(msg)

    def recv(self) -> bytes:
        """
        Receives a message from the ENIP socket.

        Returns:
            The message received as bytes

        Raises:
            EnipCommError: if the received failed
        """
        return self.enip_socket.receive()

    def _get_sequence(self) -> int:
        """
        Increment and return the sequence number used with
        connected messages.

        Returns:
            The current sequence number
        """
        if self.sequence < ENIP_SEQ_MAX:
            self.sequence += 1
        else:
            self.sequence = 0

        return self.sequence

    @staticmethod
    def _build_common_packet_format(
        message_type: bytes,
        message: bytes,
        addr_type: bytes,
        addr_data: bytes | None = None,
        timeout: int = 10,
    ) -> bytes:
        """
        Builds and returns a common message.

        Check Volume 2 (page 2.22) of CIP specification for reference.

        Returns:
            The built message
        """
        msg: bytes = pack_dint(0)  # Interface Handle: shall be 0 for CIP
        msg += pack_uint(timeout)  # Timeout
        msg += pack_uint(2)  # Item count: should be at list 2 (Address and Data)
        msg += addr_type  # Address Item Type ID

        if addr_data is not None:
            msg += pack_uint(len(addr_data))  # Address Item Length
            msg += addr_data
        else:
            msg += pack_uint(0)  # Address Item Length

        msg += message_type  # Data Type ID
        msg += pack_uint(len(message))  # Data Item Length
        msg += message

        return msg

    def send_nop(self) -> None:
        """
        Send a NOP to the target, gets no reply.

        A NOP provides a way for either an originator or target to determine
        if the TCP connection is still open.

        Raises:
            EnipCommError: if the message send failed
        """
        packet = ENIP(
            commandCode="NOP",
            sessionHandle=self.session,
        )
        self.send(bytes(packet))

    # TODO: unit test in CI
    # TODO: use this function instead of the currently used one
    def list_identity(self) -> ENIPListIdentityResponse:
        """
        ListIdentity command to locate and identify potential target.

        Raises:
            EnipCommError: if the message send failed
        """
        packet = ENIP(commandCode="ListIdentity")
        self.send(bytes(packet))

        reply = ENIP(self.recv())
        # TODO: check error code
        return ENIPListIdentityResponse(reply.data)

    # TODO: unit test in CI
    def list_services(self) -> list[str]:
        """
        Returns list of service names returned by ListServices command.
        """
        services_response = self._get_services()
        service_names = [
            svc.serviceName.decode().replace("\x00", "")
            for svc in services_response.listItems
        ]
        return service_names

    def _get_services(self) -> ENIPListServicesResponse:
        packet = ENIP(commandCode="ListServices")
        self.send(bytes(packet))

        reply = ENIP(self.recv())
        # TODO: check error code
        return ENIPListServicesResponse(reply.data)

    def list_interfaces(self) -> list[str]:
        """
        Returns list of interfaces returned by ListInterfaces command.
        """
        # TODO: don't know if this actually works
        interfaces_response = self._get_interfaces()
        interfaces = []
        if interfaces_response.listItems:
            interfaces = [
                svc.itemData.decode().replace("\x00", "")
                for svc in interfaces_response.listItems
            ]
        return interfaces

    def _get_interfaces(self) -> ENIPListServicesResponse:
        packet = ENIP(commandCode="ListInterfaces")
        self.send(bytes(packet))

        reply = ENIP(self.recv())
        # TODO: check error code
        return ENIPListInterfacesResponse(reply.data)

    def send_rr_data(self, message: bytes) -> tuple[bytes, bytes]:
        """
        SendRRData transfer an encapsulated request/reply packet between
        the originator and target.

        Args:
            message: The message to be send to the target

        Returns:
            a :class:`tuple` where:
              0: (boolean) reply is valid
              1: the target CID T->O value from the response

        Raises:
            EnipCommError: if the message send failed
        """
        rr_message = ENIP(
            commandCode="SendRRData",
            sessionHandle=self.session,
            data=bytes(message),
        )

        self.send(bytes(rr_message))
        reply = ENIP(self.recv())

        # TODO: generalize error handling
        status = scapy_human_field(reply, "status")
        if status != "Success":
            raise EnipCommError(f"Failed SendRRData: {status}")

        target_cid_to = reply.data[20:24]
        return reply.data[16:], target_cid_to

    def send_unit_data(self, message: bytes) -> bytes:
        """
        SendUnitData send encapsulated connected messages.

        Args:
            message: The message to be sent to the target

        Returns:
            The reply data

        Raises:
            EnipCommError: if the message send failed
        """
        unit_message = ENIP(
            commandCode="SendUnitData",
            sessionHandle=self.session,
            data=bytes(message),
        )
        self.send(bytes(unit_message))
        reply = ENIP(self.recv())

        # TODO: generalize error handling
        status = scapy_human_field(reply, "status")
        if status != "Success":
            raise EnipCommError(f"Failed SendUnitData: {status}")

        return reply.data[22:]

    def send_connected_command(
        self, service: int, path: bytes, cmd_data: bytes
    ) -> bytes:
        """
        Sends a connected command to the device.

        Args:
            service: One byte value indicating the request service
            path: The path to the specified instance (including path length)
            cmd_data: Additional command data

        Returns:
            The reply data

        Raises:
            EnipCommError: if the message send failed
        """
        message_request = [
            pack_uint(self._get_sequence()),
            bytes([service]),
            path,
            cmd_data,
        ]
        message = self._build_common_packet_format(
            DATA_ITEM["Connected"],
            b"".join(message_request),
            ADDRESS_ITEM["Connection Based"],
            addr_data=self.cid_to,
        )

        return self.send_unit_data(message)

    def register_session(self) -> int:
        """
        Register a new session with the communication partner.

        Returns:
            The session number

        Raises:
            EnipCommError: if the registration message send failed
        """
        if self.session:
            return self.session

        message = bytes(ENIP(commandCode="RegisterSession"))

        self.send(message)
        reply = ENIP(self.recv())

        # check if session registered successfully
        status = scapy_human_field(reply, "status")
        if status != "Success":
            raise EnipCommError(f"Failed to register session: {status}")

        self.session = reply.sessionHandle

        self.log.debug(f"Session = 0x{self.session:0>8x} has been registered")
        return self.session

    def unregister_session(self) -> None:
        """
        Unregister a connection.

        Raises:
            EnipCommError: if the unregister message send failed
        """
        message = ENIP(
            commandCode="UnregisterSession",
            sessionHandle=self.session,
        )
        self.send(bytes(message))
        self.session = 0

    def forward_open(self) -> bool:
        """
        CIP implementation of the forward open message.

        Refer to ODVA documentation Volume 1 3-5.5.2

        Returns:
            :obj:`False` if any error in the replayed message

        Raises:
            EnipCommError: No session was registered before calling forward open
        """
        if not self.session:
            raise EnipCommError(
                f"a session need to be registered before call "
                f"to forward open to {str(self)}"
            )

        forward_open_msg = [
            CIP_SC_BYTES["FORWARD_OPEN"],
            pack_usint(2),
            CLASS_ID["8-bit"],
            pack_usint(CLASS_CODE["Connection Manager"]),  # Volume 1: 5-1
            INSTANCE_ID["8-bit"],
            CONNECTION_MANAGER_INSTANCE["Open Request"],
            PRIORITY,
            TIMEOUT_TICKS,
            self.cid_ot,
            self.cid_to,
            self.csn,
            self.vid,
            self.vsn,
            TIMEOUT_MULTIPLIER,
            b"\x00\x00\x00",
            pack_dint(self.rpi * 1000),
            pack_uint(CONNECTION_PARAMETER["Default"]),
            pack_dint(self.rpi * 1000),
            pack_uint(CONNECTION_PARAMETER["Default"]),
            TRANSPORT_CLASS,  # Transport Class
            CONNECTION_SIZE["Backplane"],
            pack_usint(self.backplane),
            pack_usint(self.cpu_slot),
            CLASS_ID["8-bit"],
            pack_usint(CLASS_CODE["Message Router"]),
            INSTANCE_ID["8-bit"],
            pack_usint(1),
        ]
        message = self._build_common_packet_format(
            DATA_ITEM["Unconnected"], b"".join(forward_open_msg), ADDRESS_ITEM["UCMM"]
        )

        send_rr_data_success, target_cid_to = self.send_rr_data(message)

        if send_rr_data_success:
            self.cid_to = target_cid_to
            self.is_forward_opened = True
            self.log.info("forward_open successful")
            return True

        self.log.warning("send_rr_data failed")
        return False

    def forward_close(self) -> bool:
        """
        CIP implementation of the forward close message

        Each connection opened with the froward open message need to be closed.
        Refer to ODVA documentation Volume 1 3-5.5.3

        Returns:
            :obj:`False` if any error in the message reply

        Raises:
            EnipCommError: No session was registered before calling forward close
        """
        if not self.session:
            raise EnipCommError(
                f"a session need to be registered before call "
                f"to forward_close to {str(self)}"
            )

        forward_close_msg = [
            CIP_SC_BYTES["FORWARD_CLOSE"],
            pack_usint(2),
            CLASS_ID["8-bit"],
            pack_usint(CLASS_CODE["Connection Manager"]),  # Volume 1: 5-1
            INSTANCE_ID["8-bit"],
            CONNECTION_MANAGER_INSTANCE["Open Request"],
            PRIORITY,
            TIMEOUT_TICKS,
            self.csn,
            self.vid,
            self.vsn,
            CONNECTION_SIZE["Backplane"],
            b"\x00",  # Reserved
            pack_usint(self.backplane),
            pack_usint(self.cpu_slot),
            CLASS_ID["8-bit"],
            pack_usint(CLASS_CODE["Message Router"]),
            INSTANCE_ID["8-bit"],
            pack_usint(1),
        ]
        message = self._build_common_packet_format(
            DATA_ITEM["Unconnected"], b"".join(forward_close_msg), ADDRESS_ITEM["UCMM"]
        )

        send_rr_data_success, _ = self.send_rr_data(message)

        if send_rr_data_success:
            self.is_forward_opened = False
            self.log.debug("forward_close successful")
            return True

        self.log.warning("failed forward_close")
        return False


__all__ = ["EnipDriver"]

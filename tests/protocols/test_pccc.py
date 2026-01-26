from scapy.packet import Packet

from peat.protocols import pccc
from peat.protocols.enip import ENIP

# TODO: write actual tests for these


def test_pccc_const_imports():
    """Ensure PCCC data structures are accessible and valid Python."""
    assert isinstance(pccc.PCCC_DATA_TYPE, dict)
    assert isinstance(pccc.PCCC_DATA_SIZE, dict)
    assert isinstance(pccc.PCCC_CT, dict)
    assert isinstance(pccc.PCCC_ERROR_CODE, dict)
    assert isinstance(pccc.UNPACK_PCCC_DATA_FUNCTION, dict)
    assert isinstance(pccc.PACK_PCCC_DATA_FUNCTION, dict)


def test_pccc_pcccovercip_packet():
    assert isinstance(pccc.PCCCoverCIP(), Packet)


def test_generate_packets():
    assert isinstance(pccc.generate_pccc_packet({}), ENIP)

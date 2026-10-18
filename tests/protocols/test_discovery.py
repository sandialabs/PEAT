import pytest

from peat import consts
from peat.protocols.discovery import get_reachable_hosts


@pytest.mark.skipif(consts.WSL, reason="Doesn't work in WSL")
def test_get_reachable_hosts_localhost():
    """Localhost should return as online, since a closed port responds with a RST."""
    assert get_reachable_hosts(["127.0.0.1"], [44818]) == ["127.0.0.1"]

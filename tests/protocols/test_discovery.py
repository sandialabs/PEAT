from platform import system, version

import pytest

from peat.protocols.discovery import get_reachable_hosts


@pytest.mark.skipif(
    (system() == "Linux" and "Microsoft" in version()), reason="Doesn't work in WSL"
)
def test_get_reachable_hosts_localhost(win_or_wsl):
    """Localhost should return as online."""
    expected = [] if (win_or_wsl or system() == "Darwin") else ["127.0.0.1"]
    assert get_reachable_hosts(["127.0.0.1"], [44818]) == expected

from unittest.mock import MagicMock

import pytest

from peat import PeatError, config, datastore, state
from peat.api.pull_api import pull


def test_pull_static(mocker):
    mocker.patch.object(datastore, "objects", [])
    assert not pull([], "", [])


# ---------------------------------------------------------------------------
# pull --skip-scan
# ---------------------------------------------------------------------------


def _mock_module(name="MockModule"):
    """Return a minimal DeviceModule stand-in that reports a successful pull."""
    mod = MagicMock()
    mod.__name__ = name
    mod.pull.return_value = True
    mod.elastic = MagicMock(return_value={})
    return mod


@pytest.fixture
def _skip_scan_base(mocker, tmp_path):
    """Apply patches common to all skip-scan tests: clean datastore, reset
    error state, redirect file output to tmp_path, and stub out summary
    saving so no real files are written."""
    mocker.patch.object(datastore, "objects", [])
    mocker.patch.dict(state["CONFIG"], {"error": False})
    mocker.patch.dict(
        config["CONFIG"],
        {"DEVICE_DIR": tmp_path / "devices", "TEMP_DIR": tmp_path / "temp"},
    )
    mocker.patch("peat.api.pull_api.utils.save_results_summary")
    mocker.patch("peat.api.pull_api.module_api.lookup_names", return_value=[])


@pytest.mark.usefixtures("_skip_scan_base")
def test_returns_none_with_no_valid_ips(mocker):
    """An empty target list should short-circuit and return None."""
    mocker.patch.dict(config["CONFIG"], {"HOSTS": []})
    mocker.patch("peat.api.pull_api.module_api.lookup_types", return_value=[])

    result = pull([], "unicast_ip", [], skip_scan=True)

    assert result is None


@pytest.mark.usefixtures("_skip_scan_base")
def test_raises_with_multiple_modules_and_no_host_map(mocker):
    """Specifying more than one device type without per-host peat_module
    mappings in the config is ambiguous and should raise PeatError."""
    mocker.patch.dict(config["CONFIG"], {"HOSTS": []})
    mod1, mod2 = _mock_module("Mod1"), _mock_module("Mod2")
    mocker.patch("peat.api.pull_api.module_api.lookup_types", return_value=[mod1, mod2])

    with pytest.raises(PeatError):
        pull(["192.168.0.1"], "unicast_ip", ["Mod1", "Mod2"], skip_scan=True)


@pytest.mark.usefixtures("_skip_scan_base")
def test_uses_fallback_module_when_no_host_map(mocker):
    """When no per-host mapping exists but a single -d module is given,
    that module should be used for all targets."""
    mocker.patch.dict(config["CONFIG"], {"HOSTS": []})
    mod = _mock_module()
    mocker.patch("peat.api.pull_api.module_api.lookup_types", return_value=[mod])

    result = pull(["192.168.0.1"], "unicast_ip", ["MockModule"], skip_scan=True)

    assert result is not None
    dev = datastore.get("192.168.0.1")
    assert dev._module is mod


@pytest.mark.usefixtures("_skip_scan_base")
def test_uses_per_host_module_from_config(mocker):
    """A peat_module defined under a host entry in the YAML config should
    take precedence over any fallback module."""
    mocker.patch.dict(
        config["CONFIG"],
        {
            "HOSTS": [{"identifiers": {"ip": "192.168.0.1"}, "peat_module": "MockModule"}],
        },
    )
    mod = _mock_module()
    mocker.patch(
        "peat.api.pull_api.module_api.lookup_types",
        side_effect=lambda names, **_: [mod] if names else [],
    )

    result = pull(["192.168.0.1"], "unicast_ip", [], skip_scan=True)

    assert result is not None
    dev = datastore.get("192.168.0.1")
    assert dev._module is mod


@pytest.mark.usefixtures("_skip_scan_base")
def test_skips_ip_with_no_resolved_module(mocker):
    """An IP that cannot be mapped to any module should cause pull to
    return None and set state.error to True."""
    mocker.patch.dict(config["CONFIG"], {"HOSTS": []})
    mocker.patch("peat.api.pull_api.module_api.lookup_types", return_value=[])

    result = pull(["192.168.0.1"], "unicast_ip", [], skip_scan=True)

    assert result is None
    assert state.error is True


@pytest.mark.usefixtures("_skip_scan_base")
def test_devices_marked_active_and_verified(mocker):
    """Devices built by skip-scan should be pre-marked as active and
    verified so the pull loop treats them as confirmed targets."""
    mocker.patch.dict(config["CONFIG"], {"HOSTS": []})
    mod = _mock_module()
    mocker.patch("peat.api.pull_api.module_api.lookup_types", return_value=[mod])

    pull(["192.168.0.1"], "unicast_ip", ["MockModule"], skip_scan=True)

    dev = datastore.get("192.168.0.1")
    assert dev._is_active is True
    assert dev._is_verified is True

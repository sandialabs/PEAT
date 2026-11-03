import pytest

from peat import PeatError, datastore, push


def test_push(mocker, tmp_path):
    mocker.patch.object(datastore, "objects")

    # Bad input source
    with pytest.raises(PeatError):
        push([], "", [], input_source=None, push_type="")

    # Bad push type
    with pytest.raises(PeatError):
        push([], "", [], input_source=tmp_path, push_type="invalidpushtype")

    # Skip scan
    with pytest.raises(PeatError):
        push([], "unicast_ip", ["clx", "extra"], tmp_path, "config", skip_scan=True)
    assert not push([], "unicast_ip", ["clx"], tmp_path, "config", skip_scan=True)

    # with scan
    assert not push([], "unicast_ip", ["clx"], tmp_path, "config")


def test_push_module_raises(mocker, tmp_path):
    # A module push raising must be logged and fail the push, not crash
    mocker.patch.object(datastore, "objects", [])
    dev = datastore.get("192.0.2.10")
    dev._is_verified = True
    dev._module = mocker.Mock(push=mocker.Mock(side_effect=RuntimeError("boom")))
    mocker.patch("peat.api.push_api.scan", return_value={"hosts_verified": ["192.0.2.10"]})

    assert push(["192.0.2.10"], "unicast_ip", ["sceptre"], tmp_path, "firmware") is False
    dev._module.push.assert_called_once()

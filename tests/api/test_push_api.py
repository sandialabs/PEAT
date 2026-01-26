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

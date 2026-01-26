from peat import datastore, pull


def test_pull_static(mocker):
    mocker.patch.object(datastore, "objects", [])
    assert not pull([], "", [])

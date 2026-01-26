from peat import ControlLogix, datastore


# TODO: test input file is validated for push (file extension, contents)
def test_controllogix_push_firmware_invalid_content_localhost(mocker):
    mocker.patch.object(datastore, "objects", [])

    dev = datastore.get("127.0.0.6")
    dev._runtime_options["timeout"] = 0.01

    assert ControlLogix.push(dev, b"xyz", "config") is False
    assert ControlLogix.push(dev, b"xyz", "firmware") is False
    assert ControlLogix.push(dev, b"", "firmware") is False
    # TODO: pytest fixture /w firmware content (see test_rest_api)

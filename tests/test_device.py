from peat import SCEPTRE, ControlLogix, DeviceData, DeviceModule, SELRelay


def test_device_method_implemented():
    assert ControlLogix.method_implemented("_parse") is False
    assert SELRelay.method_implemented("_parse")
    assert SCEPTRE.method_implemented("_parse")


def test_device_base_methods():
    """
    This is mostly for coverage purposes.
    """
    dev = DeviceData()
    assert DeviceModule._pull(dev) is None
    assert DeviceModule._push(dev, "", "config") is None
    assert DeviceModule._parse(None, None) is None

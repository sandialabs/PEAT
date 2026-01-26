import pytest

from peat.consts import PeatError
from peat.data.data_utils import (
    DeepChainMap,
    dedupe_model_list,
    find_position,
    lookup_by_str,
    match_all,
    merge_models,
    only_include_keys,
    strip_empty_and_private,
    strip_key,
)
from peat.data.models import (
    OS,
    DeviceData,
    File,
    Geo,
    Interface,
    Memory,
    Register,
    Service,
    Vendor,
)


def test_deep_chain_map():
    assert DeepChainMap().to_dict() == {}

    layer1 = {}
    layer2 = {"key": 9999}
    layer3 = {"deep_object": {"deep_key": "The Deep"}}
    dmap = DeepChainMap(layer1, layer2, layer3)

    assert dmap["key"] == 9999
    assert dmap.to_dict() == {"deep_object": {"deep_key": "The Deep"}, "key": 9999}

    layer1["key"] = -1111
    assert dmap["key"] == -1111
    assert layer2["key"] == 9999
    assert dmap["deep_object"]["deep_key"] == "The Deep"

    layer1["deep_object"] = {"another_key": "another_value"}
    assert dmap["deep_object"]["deep_key"] == "The Deep"
    assert dmap["deep_object"]["another_key"] == "another_value"


def test_lookup_by_str():
    # empty container
    assert lookup_by_str([], Vendor(name="vend"), "name") is None

    # bad lookup
    assert lookup_by_str([Vendor(name="vend")], Vendor(name="vend"), "") is None

    # invalid attribute ("bogus")
    assert lookup_by_str([Vendor(name="vend")], Vendor(name="vend"), "bogus") is None

    # "id" is a default on the value
    assert lookup_by_str([Vendor(id="v_id")], Vendor(name="vend"), "id") is None

    # Fail lookup even if it's set on value being searched
    assert lookup_by_str([Vendor()], Vendor(id="vend_id"), "id") is None

    # successful lookups
    assert lookup_by_str([Vendor(id="vend_id")], Vendor(id="vend_id"), "id") == 0

    # multiple objects
    to_search = [Vendor(name="vend_name"), Vendor(id="vend_id"), Vendor(id="vend_id")]
    assert lookup_by_str(to_search, Vendor(id="vend_id"), "id") == 1


def test_find_position():
    obj = [File, Vendor(name="vend")]
    assert find_position(obj, "name", "vend") == 1
    assert find_position(obj, "doesnotexist", "vend") is None


def test_match_all():
    assert match_all([], {}) is None
    assert match_all([OS(family="test_family")], {}) is None
    assert match_all([Vendor(name="test_name")], {"name": "test_name"}) == 0

    test_vendor_list = [
        OS(),
        Vendor(name="tst"),
        Vendor(name="tst", id="vnd_id"),
        Vendor(name="tst", id="other_id"),
        Vendor(id="vnd_id"),
    ]
    assert match_all(test_vendor_list, {"name": "tst", "id": "vnd_id"}) == 2


def test_strip_empty_and_private():
    assert strip_empty_and_private({}) == {}
    assert strip_empty_and_private({"x": {None, ""}, "y": [], "z": {}}) == {}
    assert strip_empty_and_private({"x": set(), "y": [], "z": {}}) == {}
    assert strip_empty_and_private({"x": {None}}) == {}
    assert strip_empty_and_private({"x": {""}}) == {}

    original = {
        "empty": "",
        "_private": "priv",
        "t": "t",
        "x": {"_p": 1, "y": 2, "z": 0, "n": -1},
        "b": False,
        "l": [],
        "la": [-1, 0, 1],
        "lal": [-1, 1, None, [], [0, 1, 2, -3], ""],
    }
    expected = {
        "t": "t",
        "x": {"y": 2, "z": 0, "n": -1},
        "b": False,
        "la": [-1, 0, 1],
        "lal": [-1, 1, [0, 1, 2, -3]],
    }
    assert strip_empty_and_private(original) == expected
    assert strip_empty_and_private(original, False, False) == original

    empty_with = {
        "empty": "",
        "_private": "priv",
        "t": "t",
    }
    empty_without = {
        "_private": "priv",
        "t": "t",
    }
    assert strip_empty_and_private(empty_with, strip_private=False) == empty_without

    priv_with = {
        "empty": "",
        "_private": "priv",
        "t": "t",
    }
    priv_without = {
        "empty": "",
        "t": "t",
    }
    assert strip_empty_and_private(priv_with, strip_empty=False) == priv_without


def test_strip_key():
    data = {"x": "y", "b": "e", "z": 0}
    assert strip_key(data, "b") == {"x": "y", "z": 0}
    assert strip_key({}, "shrug") == {}
    assert strip_key({}, "") == {}


def test_only_include_keys():
    data = {"x": "y", "b": "e", "z": 0}
    assert only_include_keys(data, ["x"]) == {"x": "y"}
    assert only_include_keys(data, "x") == {"x": "y"}
    assert only_include_keys(data, ["z", "b"]) == {"b": "e", "z": 0}
    assert only_include_keys(data, []) == {}

    assert only_include_keys({}, ["something"]) == {}
    assert only_include_keys({}, "something") == {}
    assert only_include_keys({}, "") == {}
    assert only_include_keys({}, []) == {}


def test_dedupe_model_list():
    assert dedupe_model_list([]) == []
    assert dedupe_model_list(None) is None

    assert dedupe_model_list([Service(port=80)]) == [Service(port=80)]
    assert dedupe_model_list([Service(port=80), Service(port=80)]) == [Service(port=80)]

    # Registers
    registers = []
    deduped_registers = []

    for i in range(100):
        registers.append(
            Register(
                address=str(i),
                name=f"testing_{i}",
                protocol="dnp3",
            )
        )

        reg2 = Register(
            address=str(i),
            name=f"testing_{i}",
            protocol="dnp3",
            read_write="read",
        )
        registers.append(reg2)
        deduped_registers.append(reg2)

    assert dedupe_model_list(registers) == deduped_registers

    # Services
    services = [
        Service(port=80),
        Service(port=80, protocol="http"),
        Service(),
        Service(port=80, protocol="http", enabled=True),
        Service(port=80),
        Service(port=8080, protocol="http"),
        Service(port=161, protocol="snmp"),
        Service(protocol="snmp"),
        Service(enabled=False),
        Service(),
        Service(port=80),
    ]
    deduped_services = [
        Service(port=80, protocol="http", enabled=True),
        Service(port=8080, protocol="http"),
        Service(port=161, protocol="snmp"),
        Service(enabled=False),
    ]

    assert dedupe_model_list(services) == deduped_services

    # Interfaces
    interfaces = [
        Interface(
            ip="192.168.0.1",
            services=[Service(port=80), Service(port=80, protocol="http")],
        ),
        Interface(services=[Service(port=80), Service(port=80, protocol="http")]),
        Interface(ip="192.168.0.1"),
        Interface(),
        Interface(ip="10.0.0.1"),
    ]
    deduped_interfaces = [
        Interface(
            ip="192.168.0.1",
            services=[Service(port=80), Service(port=80, protocol="http")],
        ),
        Interface(ip="10.0.0.1"),
    ]

    assert dedupe_model_list(interfaces) == deduped_interfaces

    # Deduplicate services on an interface
    iface_services = [Service(port=80), Service(port=80, protocol="http")]
    iface = Interface(ip="192.168.0.1", services=iface_services)

    iface.services = dedupe_model_list(iface.services)
    assert iface.services == [Service(port=80, protocol="http")]


def test_merge_models():
    """assert there are no duplicates in various places."""
    assert merge_models(None, None) is None

    with pytest.raises(PeatError):
        merge_models(Service(port=80), {"bad": "attribute"})

    mem_dst = Memory(address="0000", value="0000")
    mem_src = Memory(dataset="test_dataset")
    merge_models(mem_dst, mem_src)
    assert mem_dst.dataset == "test_dataset"

    dev_dst = DeviceData(
        id="dst",
        module=[
            DeviceData(id="mod1", slot="1"),
            DeviceData(id="mod2", slot="2"),
        ],
    )
    dev_src = DeviceData(
        id="src",
        ip="192.0.2.1",
        module=[
            DeviceData(id="mod1", slot="1"),
            DeviceData(id="mod3", slot="3"),
        ],
    )
    merge_models(dev_dst, dev_src)
    assert dev_src.id == "src"  # ensure source is unmodified
    assert dev_src.ip == "192.0.2.1"
    assert dev_dst.id == "dst"
    assert dev_dst.ip == "192.0.2.1"
    assert len(dev_dst.module) == 3
    assert dev_dst.module[0].slot == "1"
    assert dev_dst.module[1].slot == "2"
    assert dev_dst.module[2].slot == "3"

    # test lists, dataclasses, and basic attributes
    dest = DeviceData()
    src = DeviceData(type="test_type", service=[Service()])
    src.description.full = "test_description_full"
    merge_models(dest, src)
    assert dest.service == src.service
    assert dest.description.full == src.description.full
    assert dest.type == src.type

    # test zero int isn't overwritten by unset or set value
    z_int = Interface(speed=0)
    merge_models(z_int, Interface())
    assert z_int.speed == 0
    merge_models(z_int, Interface(speed=9001))
    assert z_int.speed == 0

    # test that empty values in src doesn't replace set values set in dest
    os_dst = OS(family="dest_os_family")
    src_os = OS()
    merge_models(os_dst, src_os)
    assert os_dst.family == "dest_os_family"
    assert src_os.family == ""  # Ensure the source didn't get modified

    # test set values (non-empty) in src don't replace set values in dest
    geo_dst = Geo(city_name="dest_city")
    geo_src = Geo(city_name="src_city", country_name="USA")
    merge_models(geo_dst, geo_src)
    assert geo_dst.city_name == "dest_city"
    assert geo_src.city_name == "src_city"
    assert geo_dst.country_name == geo_src.country_name

    # test .module attribute gets copied and
    # test values in src don't overwrite values in dest
    mod = DeviceData(id="mod_id")
    with_mod = DeviceData(id="with_mod", module=[mod])
    no_mod = DeviceData(id="no_mod")
    assert not no_mod.module
    merge_models(no_mod, with_mod)
    assert no_mod.id == "no_mod"
    assert mod in no_mod.module
    assert no_mod.module == with_mod.module
    assert no_mod.id != with_mod.id
    assert no_mod.module[0].id == "mod_id"

    # test empty values in src .module don't overwrite existing values in dest
    dest_data = DeviceData(type="dest_type")
    src_data = DeviceData()
    merge_models(dest_data, src_data)
    assert dest_data.type == "dest_type"
    assert not src_data.type

    # test that module list is sorted by Slot ID
    sort_dest = DeviceData()
    mod1 = DeviceData(slot="1")
    mod2 = DeviceData(slot="2")
    sort_src = DeviceData(module=[mod2, mod1])
    merge_models(sort_dest, sort_src)
    assert sort_dest.module[0] == mod1
    assert sort_dest.module[1] == mod2

import copy
import random
import time

import pytest

from peat.consts import PeatError
from peat.data.base_model import BaseModel
from peat.data.data_utils import (
    DeepChainMap,
    _freeze,
    compare_dicts,
    dedupe_model_list,
    find_position,
    lookup_by_str,
    match_all,
    merge_models,
    none_aware_attrgetter,
    only_include_keys,
    sort_model_list,
    strip_empty_and_private,
    strip_key,
)
from peat.data.models import (
    IO,
    OS,
    DeviceData,
    File,
    Geo,
    Interface,
    Memory,
    Register,
    Service,
    Tag,
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


def test_dedupe_model_list_subsets_and_order():
    # Models are merged into the first model in the list that's equal
    # to or a superset of it, and the order of the list is preserved.
    registers = [
        Register(protocol="modbus"),
        Register(address="1", protocol="modbus", name="a"),
        Register(address="2", protocol="modbus"),
        Register(address="1", protocol="modbus"),
        Register(address="2", protocol="modbus", extra={"x": [1, 2]}),
        Register(address="2", protocol="modbus", extra={"x": [1, 2]}),
        Register(),
        Register(address="3", protocol="dnp3"),
    ]
    assert dedupe_model_list(registers) == [
        Register(address="1", protocol="modbus", name="a"),
        Register(address="2", protocol="modbus", extra={"x": [1, 2]}),
        Register(address="3", protocol="dnp3"),
    ]

    # Values that differ aren't merged
    tags = [Tag(name="a", type="binary"), Tag(name="a", type="analog"), Tag(name="a")]
    assert dedupe_model_list(tags) == [
        Tag(name="a", type="binary"),
        Tag(name="a", type="analog"),
    ]


def test_dedupe_model_list_unhashable_values():
    # bytearray isn't hashable, but is equal to bytes with the same value
    registers = [
        Register(address="1", extra={"value": b"a"}),
        Register(address="1", name="a", extra={"value": bytearray(b"a")}),
    ]
    assert dedupe_model_list(registers) == [registers[1]]


def test_dedupe_model_list_modules():
    # Modules without a slot or serial number used to be duplicated when
    # devices were merged, which made a merged device differ from the
    # device it was merged into (and from the result of comparing pairs).
    module = DeviceData(name="x")
    devices = [
        DeviceData(module=[module]),
        DeviceData(name="a", module=[module]),
        DeviceData(module=[module]),
    ]
    deduped = dedupe_model_list(devices)
    assert deduped == [devices[1]]
    assert deduped[0] is devices[1]
    assert deduped[0].module == [module]


def test_dedupe_model_list_same_object():
    reg = Register(address="1")
    assert dedupe_model_list([reg, reg, reg]) == [reg]

    # Values are merged into the original object, which is what's returned
    regs = [Register(address="1", name="a"), Register(address="1", name="a", group="g")]
    deduped = dedupe_model_list(regs)
    assert len(deduped) == 1
    assert deduped[0] is regs[1]
    assert deduped[0] == Register(address="1", name="a", group="g")

    # Models with different values for a key aren't merged
    regs = [Register(address="1", name="a"), Register(address="1", group="g")]
    assert dedupe_model_list(regs) == regs


def test_dedupe_model_list_nested_values():
    # Values that are dicts, lists, and nested models are compared by value
    regs = [
        Register(address="1", extra={"a": 1, "b": {"c": [1, 2]}}),
        Register(address="1", extra={"b": {"c": [1, 2]}, "a": 1}, name="n"),
        Register(address="1", extra={"a": 1, "b": {"c": [2, 1]}}),
        Register(address="1", extra={"a": 1, "b": {"c": (1, 2)}}),  # tuple != list
    ]
    deduped = dedupe_model_list(regs)
    assert deduped == [regs[1], regs[2], regs[3]]

    ifaces = [
        Interface(ip="192.0.2.1", services=[Service(port=80)]),
        Interface(ip="192.0.2.1", services=[Service(port=80)], name="eth0"),
        Interface(ip="192.0.2.1", services=[Service(port=443)]),
        Interface(ip="192.0.2.1"),
    ]
    deduped = dedupe_model_list(ifaces)
    assert deduped == [ifaces[1], ifaces[2]]

    # Mixed hashable and unhashable values for the same key
    regs = [
        Register(address="1", extra={"v": bytearray(b"a")}),
        Register(address="1", extra={"v": "a"}),
        Register(address="1", extra={"v": "a"}, name="n"),
        Register(address="2", extra={"v": bytearray(b"a")}),
        Register(extra={"v": bytearray(b"a")}),
    ]
    deduped = dedupe_model_list(regs)
    assert deduped == [regs[0], regs[2], regs[3]]


def test_dedupe_model_list_services():
    # A "verified" service is merged with a service with the same port
    # and protocol, regardless of other values, and keeps the status
    services = [
        Service(port=80, protocol="http", status="open", enabled=True),
        Service(port=80, protocol="http", status="verified"),
        Service(port=443, protocol="https", status="verified"),
        Service(port=80, protocol="http", status="closed", transport="tcp"),
    ]
    deduped = dedupe_model_list(services)
    assert deduped == [
        Service(port=80, protocol="http", status="verified", enabled=True, transport="tcp"),
        Service(port=443, protocol="https", status="verified"),
    ]

    # "open" takes precedence over "closed"
    services = [
        Service(port=80, protocol="http", status="closed", enabled=True),
        Service(port=80, protocol="http", status="open"),
    ]
    assert dedupe_model_list(services) == [
        Service(port=80, protocol="http", status="open", enabled=True),
    ]

    # Services with the same port but a different protocol aren't merged
    services = [
        Service(port=80, protocol="http", status="closed"),
        Service(port=80, protocol="https", status="open"),
        Service(port=8080, protocol="http", status="verified"),
    ]
    assert dedupe_model_list(services) == services

    # A missing port or protocol matches any value
    services = [
        Service(port=80, protocol="http", status="closed"),
        Service(port=80, protocol="https", status="open"),
        Service(port=80, status="verified"),
    ]
    assert dedupe_model_list(services) == [
        Service(port=80, protocol="https", status="open"),
        Service(port=80, protocol="http", status="verified"),
    ]

    # Other models don't get the Service special case
    tags = [
        Tag(name="t", type="binary", address="1"),
        Tag(name="t", type="analog", address="1"),
    ]
    assert dedupe_model_list(tags) == tags


def test_dedupe_model_list_errors():
    with pytest.raises(PeatError):
        dedupe_model_list([{"port": 80}, {"port": 80}])


def _pairwise_dedupe(models: list) -> list:
    """
    Reference implementation of dedupe_model_list() that compares
    every model with every other model (how it was originally done).
    """
    cache = {id(m): m for m in models}
    dicts = {id(m): m.dict(exclude_defaults=True, exclude_none=True) for m in models}
    duplicates = set()

    for item_id, item_dict in dicts.items():
        if item_id in duplicates:
            continue
        for comp_id, comp_dict in dicts.items():
            if comp_id in duplicates or comp_id == item_id:
                continue
            if item_dict.items() <= comp_dict.items():
                if item_dict != comp_dict:
                    merge_models(cache[comp_id], cache[item_id])
                    dicts[comp_id] = cache[comp_id].dict(exclude_defaults=True, exclude_none=True)
                duplicates.add(item_id)
                break

    return [m for m in models if id(m) not in duplicates]


def test_dedupe_model_list_matches_pairwise():
    rand = random.Random(1234)
    choices = {
        "address": ["1", "2", "3"],
        "protocol": ["modbus", "dnp3"],
        "name": ["a", "b"],
        "group": ["M"],
        "extra": [{"x": [1, 2]}, {"x": [1, 2], "y": "z"}, {"b": b"a"}, {"b": bytearray(b"a")}],
    }

    def random_register() -> Register:
        kwargs = {k: rand.choice(v) for k, v in choices.items() if rand.random() < 0.5}
        return Register(**kwargs)

    def random_module() -> DeviceData:
        kwargs = {
            k: rand.choice(v)
            for k, v in {"name": ["a", "b"], "slot": ["1", "2"], "serial_number": ["s"]}.items()
            if rand.random() < 0.5
        }
        if rand.random() < 0.5:
            kwargs["module"] = [DeviceData(name=rand.choice(["x", "y"]))]
        if rand.random() < 0.5:
            kwargs["registers"] = [random_register() for _ in range(rand.randint(1, 2))]
        return DeviceData(**kwargs)

    def as_dicts(models: list) -> list[dict]:
        return [m.dict(exclude_defaults=True, exclude_none=True) for m in models]

    for generate in [random_register, random_module]:
        for _ in range(100):
            models = [generate() for _ in range(rand.randint(0, 10))]
            expected_models = copy.deepcopy(models)

            deduped = dedupe_model_list(models)
            expected = _pairwise_dedupe(expected_models)

            # Same objects (by position), in the same order, with the same values
            assert [models.index(m) for m in deduped] == [
                expected_models.index(m) for m in expected
            ]
            assert as_dicts(deduped) == as_dicts(expected)


def test_dedupe_model_list_large():
    # Regression test for sandialabs/PEAT#20, this used to take minutes
    registers = [
        Register(address=str(i), name=f"MOD_{i}", protocol="modbus", group="M")
        for i in range(20000)
    ]
    expected = list(registers)
    registers.extend(Register(address=str(i), protocol="modbus") for i in range(0, 20000, 2))
    registers.extend(Register(protocol="modbus", group="M") for _ in range(1000))

    start = time.perf_counter()
    deduped = dedupe_model_list(registers)
    assert time.perf_counter() - start < 30

    assert len(deduped) == len(expected)
    assert all(a is b for a, b in zip(deduped, expected, strict=True))


def test_merge_models_dedupes_lists():
    dest = DeviceData(registers=[Register(address="1"), Register(address="2")])
    src = DeviceData(registers=[Register(address="2"), Register(address="3")])

    merge_models(dest, src)
    assert dest.registers == [
        Register(address="1"),
        Register(address="2"),
        Register(address="3"),
    ]


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


def test_merge_models_modules():
    dest = DeviceData(module=[DeviceData(name="io", type="I/O")])
    io_module = dest.module[0]

    # The same module, an equal module, and a subset of an existing module
    # aren't duplicated (modules without a slot or serial number used to be)
    merge_models(dest, DeviceData(module=[io_module]))
    assert dest.module == [io_module]
    merge_models(dest, DeviceData(module=[DeviceData(name="io", type="I/O")]))
    assert dest.module == [io_module]
    merge_models(dest, DeviceData(module=[DeviceData(name="io")]))
    assert dest.module == [io_module]

    # A superset of an existing module replaces it, with the values merged
    merge_models(dest, DeviceData(module=[DeviceData(name="io", type="I/O", serial_number="s1")]))
    assert dest.module == [DeviceData(name="io", type="I/O", serial_number="s1")]

    # Modules with the same serial number or slot are merged
    merge_models(dest, DeviceData(module=[DeviceData(serial_number="s1", slot="2")]))
    assert dest.module == [DeviceData(name="io", type="I/O", serial_number="s1", slot="2")]
    merge_models(dest, DeviceData(module=[DeviceData(slot="2", type="I/O module")]))
    assert len(dest.module) == 1
    assert dest.module[0].type == "I/O"  # existing values aren't replaced

    # Different modules are added and sorted by slot
    merge_models(dest, DeviceData(module=[DeviceData(slot="1", name="cpu"), DeviceData(name="x")]))
    assert [m.slot for m in dest.module] == ["", "1", "2"]
    assert dest.module[0].name == "x"
    assert dest.module[1].name == "cpu"

    # Merging the same device again changes nothing
    before = dest.dict()
    merge_models(dest, DeviceData(module=list(dest.module)))
    assert dest.dict() == before


def test_merge_models_errors():
    with pytest.raises(PeatError):
        merge_models(Service(port=80), Register(address="1"))

    with pytest.raises(PeatError):
        merge_models(Service(port=80), "not a model")


def test_merge_models_values():
    # Nested models are merged, not replaced
    dest = DeviceData(name="dest")
    dest.description.vendor = Vendor(name="Vendor")
    src = DeviceData()
    src.description.vendor = Vendor(name="Other", id="VEND")
    src.description.full = "Full description"
    merge_models(dest, src)
    assert dest.description.vendor.name == "Vendor"
    assert dest.description.vendor.id == "VEND"
    assert dest.description.full == "Full description"

    # Dicts are merged, with existing values preserved
    dest = Register(extra={"a": 1, "nested": {"b": 2}})
    merge_models(dest, Register(extra={"a": 2, "c": 3, "nested": {"b": 3, "d": 4}}))
    assert dest.extra == {"a": 1, "c": 3, "nested": {"b": 2, "d": 4}}

    # Sets are combined
    dest = DeviceData(ip="192.0.2.1")
    dest.related.ip.add("192.0.2.1")
    src = DeviceData()
    src.related.ip.update({"192.0.2.1", "192.0.2.2"})
    merge_models(dest, src)
    assert dest.related.ip == {"192.0.2.1", "192.0.2.2"}

    # Lists of non-model values are combined without duplicates
    dest = IO(name="io", slot=["1", "2"])
    merge_models(dest, IO(name="io", slot=["2", "3"]))
    assert dest.slot == ["1", "2", "3"]

    # Lists of models are combined, deduplicated, and sorted
    dest = DeviceData(registers=[Register(address="2", protocol="dnp3")])
    merge_models(
        dest,
        DeviceData(
            registers=[
                Register(address="1", protocol="dnp3"),
                Register(address="2", protocol="dnp3", name="n"),
            ]
        ),
    )
    assert dest.registers == [
        Register(address="1", protocol="dnp3"),
        Register(address="2", protocol="dnp3", name="n"),
    ]

    # An empty list is replaced by the source's list
    dest = DeviceData()
    merge_models(dest, DeviceData(tag=[Tag(name="t")]))
    assert dest.tag == [Tag(name="t")]

    # Existing non-default values aren't replaced
    dest = Register(address="1", name="dest")
    merge_models(dest, Register(address="2", name="src", group="g"))
    assert dest == Register(address="1", name="dest", group="g")


def test_merge_models_service_status():
    # A "verified" service replaces values on the destination
    dest = Service(port=80, protocol="http", status="open", transport="udp")
    merge_models(dest, Service(port=80, protocol="http", status="verified", transport="tcp"))
    assert dest.status == "verified"
    assert dest.transport == "tcp"

    # "open" replaces "closed"
    dest = Service(port=80, protocol="http", status="closed")
    merge_models(dest, Service(port=80, status="open"))
    assert dest.status == "open"

    # "closed" doesn't replace "open", and "open" doesn't replace "verified"
    dest = Service(port=80, protocol="http", status="open")
    merge_models(dest, Service(port=80, status="closed"))
    assert dest.status == "open"
    dest = Service(port=80, protocol="http", status="verified")
    merge_models(dest, Service(port=80, status="open"))
    assert dest.status == "verified"


def test_compare_dicts():
    with pytest.raises(PeatError):
        compare_dicts({}, {"a": 1}, ["a"])
    with pytest.raises(PeatError):
        compare_dicts({"a": 1}, {"a": 1}, [])

    assert compare_dicts({"a": 1, "b": 2}, {"a": 1, "b": 3}, ["a"]) is True
    assert compare_dicts({"a": 1, "b": 2}, {"a": 1, "b": 3}, ["a", "b"]) is False

    # Keys that are missing or None on either side are ignored
    assert compare_dicts({"a": 1}, {"b": 2}, ["a", "b"]) is True
    assert compare_dicts({"a": 1, "b": None}, {"a": 1, "b": 2}, ["a", "b"]) is True


def test_freeze():
    assert _freeze("a") == "a"
    assert _freeze(1) == 1
    assert _freeze(None) is None
    assert _freeze([1, [2, 3]]) == (1, (2, 3))
    assert _freeze((1, 2)) == (1, 2)
    assert _freeze({"a": 1, "b": {"c": [1]}}) == frozenset(
        {("a", 1), ("b", frozenset({("c", (1,))}))}
    )
    assert _freeze({1, 2}) == frozenset({1, 2})

    # Equal values have equal frozen values, regardless of ordering
    assert _freeze({"a": 1, "b": 2}) == _freeze({"b": 2, "a": 1})
    assert hash(_freeze({"a": [1, {"b": 2}]})) == hash(_freeze({"a": [1, {"b": 2}]}))

    # Unhashable values that can't be converted raise TypeError
    with pytest.raises(TypeError):
        _freeze(bytearray(b"a"))
    with pytest.raises(TypeError):
        _freeze({"a": [bytearray(b"a")]})


def test_none_aware_attrgetter():
    getter = none_aware_attrgetter(("port", "protocol"))
    assert getter(Service(port=80, protocol="http")) == (False, 80, False, "http")
    assert getter(Service(protocol="http")) == (True, None, False, "http")

    # None values sort after other values, instead of raising a TypeError
    services = [Service(port=80), Service(), Service(port=22)]
    services.sort(key=getter)
    assert services == [Service(port=22), Service(port=80), Service()]


def test_sort_model_list():
    assert sort_model_list([]) is None
    assert sort_model_list(None) is None
    single = [Register(address="2")]
    assert sort_model_list(single) is None
    assert single == [Register(address="2")]

    with pytest.raises(PeatError):
        sort_model_list([{"a": 1}, {"a": 2}])

    class NoSortFields(BaseModel):
        name: str = ""

    with pytest.raises(PeatError):
        sort_model_list([NoSortFields(name="b"), NoSortFields(name="a")])

    # Sorted in-place by the model's _sort_by_fields, with None values last
    services = [
        Service(port=443, protocol="https"),
        Service(protocol="ssh"),
        Service(port=80, protocol="http"),
        Service(port=80, protocol="ftp"),
    ]
    assert sort_model_list(services) is None
    assert services == [
        Service(port=80, protocol="ftp"),
        Service(port=80, protocol="http"),
        Service(port=443, protocol="https"),
        Service(protocol="ssh"),
    ]

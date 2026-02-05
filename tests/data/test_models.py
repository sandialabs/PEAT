import json
from datetime import datetime, UTC
from pathlib import Path

import pytest
import yaml

from peat import Elastic, PeatError, config
from peat.data.models import (
    OS,
    Description,
    DeviceData,
    Event,
    Geo,
    Interface,
    LatLon,
    Logic,
    Register,
    Service,
    Tag,
    Vendor,
)


def test_device_data_dict():
    dev = DeviceData(name="n")
    assert isinstance(dev.dict(), dict)
    assert dev.dict()["name"] == "n"
    assert len(dev.dict(exclude_defaults=True)) == 1


def test_device_data_purge_duplicates():
    data = DeviceData()
    data.service = [
        Service(port=80),
        Service(port=80, protocol="http"),
        Service(port=80, protocol="http", enabled=True),
        Service(port=8080, protocol="http"),
        Service(),
        Service(port=161, protocol="snmp"),
        Service(protocol="snmp"),
        Service(enabled=False),
        Service(port=80),
        Service(port=80),
        Service(),
        Service(port=80),
    ]
    deduped = [
        Service(port=80, protocol="http", enabled=True),
        Service(port=161, protocol="snmp"),
        Service(port=8080, protocol="http"),
        Service(enabled=False),
    ]
    assert data.purge_duplicates() is None
    assert data.service == deduped


def test_device_data_export(mocker, tmp_path, assert_glob_path):
    mocker.patch.dict(config["CONFIG"], {"DEVICE_DIR": tmp_path})

    logic_text = "original logic"
    dev = DeviceData(
        name="tn",
        description=Description(product="prod"),
        logic=Logic(parsed="parsed logic", original=logic_text),
    )

    res = dev.export()

    assert "original" not in res["logic"]
    assert res["logic"]["parsed"]
    assert res["name"] == "tn"
    assert "_out_dir" not in res
    assert "modules" not in res
    assert res["description"]["product"] == "prod"

    assert dev.export(include_original=True)["logic"]["original"] == logic_text

    assert "logic" not in dev.export(exclude_fields=["logic"])

    assert dev.export(only_fields=["name"]) == {"name": "tn"}

    logic_path = assert_glob_path(dev._out_dir, "logic.txt")
    assert logic_path.read_text(encoding="utf-8") == logic_text


def test_device_data_export_to_files(mocker, tmp_path, assert_glob_path):
    mocker.patch.dict(config["CONFIG"], {"DEVICE_DIR": tmp_path})
    base = Path(tmp_path, "export_to_files_test")

    dev = DeviceData(id="export_to_files_test", logic={"original": "123"})
    assert not base.exists()

    assert dev.export_to_files() is True

    assert base.is_dir()
    fd_data_path = assert_glob_path(base, "device-data-full.json")
    dev_data_path = assert_glob_path(base, "device-data-summary.json")

    # load data from files as JSON and compare against exported data
    fd_data = json.loads(fd_data_path.read_text())
    assert dev.export(include_original=True) == fd_data

    dev_data = json.loads(dev_data_path.read_text())
    assert "original" not in dev_data["logic"]


def test_device_data_elastic():
    dev_id = "elastic_test"
    geo = Geo(location=LatLon(lat=-40.002, lon=0.00))
    dev = DeviceData(id=dev_id, type="RTU", os=OS(name="linux"), geo=geo)
    service = Service(protocol="modbus", enabled=False, port=502)
    dev.store("service", service)
    event = Event(sequence=0, ingested=datetime.now(UTC))
    dev.store("event", event)
    assert dev.elastic() == {
        "id": dev_id,
        "type": "RTU",
        "os": {"full": "linux", "name": "linux"},
        "related": {"ports": {502}, "protocols": {"modbus"}},
        "service": [service.dict(exclude_defaults=True)],
        "geo": geo.dict(exclude_defaults=True),
        "event": [
            {"provider": dev_id, "kind": {"event"}, **event.dict(exclude_defaults=True)}
        ],
    }


def test_device_data_json():
    dev = DeviceData(id="testing123json", type="PLC")
    res = dev.json()
    assert isinstance(res, str)
    assert "PLC" in res
    assert json.loads(res)["type"] == "PLC"

    indent_res = dev.json(indent=4)
    assert isinstance(indent_res, str)
    assert "PLC" in indent_res
    assert json.loads(indent_res)["type"] == "PLC"
    assert "    " in indent_res


def test_device_data_export_to_elastic(mocker):
    mocker.patch.dict(config["CONFIG"], {"ELASTIC_TIMEOUT": 0.1})
    dev = DeviceData(id="test_es_export")
    assert dev.export_to_elastic() is False
    assert dev.export_to_elastic(elastic=Elastic("localhost:56789")) is False


def test_device_data_gen_elastic_content():
    dev = DeviceData(type="PLC", id="gen_elastic_test")
    content = dev.gen_elastic_content()
    assert content["@timestamp"]
    assert content["message"]
    assert content["tags"]
    assert content["host"] == dev.elastic()


def test_device_data_get_id():
    populated_dev = DeviceData(ip="192.168.2.2", name="hello")
    assert populated_dev.get_id() == "192.168.2.2"
    empty_dev = DeviceData()
    assert empty_dev.get_id()
    assert empty_dev._cache.get("_rand_id")


def test_device_data_get_comm_id():
    dev = DeviceData()
    dev.serial_port = "port"
    dev.ip = "192.0.2.3"
    assert dev.get_comm_id() == "port"
    assert dev.get_id() != dev.get_comm_id()


def test_device_data_populate_fields():
    # Test network interfaces are being added
    net_dev = DeviceData(serial_port="test_serial_port")
    assert net_dev.populate_fields(network_only=True) is None
    assert net_dev.interface[0].serial_port == "test_serial_port"

    # Test vendor and description fields are being populated
    v = Vendor(id="vendorid")
    desc = Description(brand="somebrand", vendor=v)
    dev = DeviceData(description=desc)
    assert dev.populate_fields() is None
    assert "vendorid" in dev.description.full
    assert "somebrand" in dev.description.full
    assert dev.description.vendor.name == "vendorid"


def test_device_data_write_file(mocker, tmp_path):
    mocker.patch.dict(config["CONFIG"], {"DEVICE_DIR": tmp_path})

    base = Path(tmp_path, "write_test")
    assert not base.exists()

    dev = DeviceData(id="write_test")

    write_result = dev.write_file("789", filename="fname.f")
    assert write_result.name == "fname.f"
    assert base.is_dir()
    assert write_result.is_file()
    assert Path(base, "fname.f").read_text("utf-8") == "789"

    sub_dir = base / "test_sub_dir"
    sub_result = dev.write_file(
        data="testingsubdir123", filename="testingsubdir.f", out_dir=sub_dir
    )
    assert sub_result.name == "testingsubdir.f"
    assert sub_result.parent.name == "test_sub_dir"
    assert sub_dir.is_dir()
    assert sub_result.is_file()


@pytest.mark.parametrize("typ", ["logic", "firmware", "boot_firmware"])
def test_device_data_file_read_original(datapath, text_data, typ):
    dev = DeviceData()
    getattr(dev, typ).file.local_path = datapath("test_data.txt")
    dev.populate_fields()
    data = text_data("test_data.txt")
    data = data.encode("utf-8") if typ != "logic" else data
    assert getattr(dev, typ).original == data


@pytest.mark.parametrize(
    ("typ", "ext", "data"),
    [
        ("logic", "txt", "logic_testing123"),
        ("firmware", "bin", b"firmware_testing123"),
        ("boot_firmware", "bin", b"boot_firmware_testing123"),
    ],
)
def test_device_data_file_save_original(mocker, tmp_path, typ, ext, data):
    mocker.patch.dict(config["CONFIG"], {"DEVICE_DIR": tmp_path})
    dev = DeviceData(id="store_test")
    getattr(dev, typ).original = data

    dev.populate_fields()

    res = Path(tmp_path, "store_test", f"{typ.replace('_', '-')}.{ext}")
    assert res.is_file()

    assert res.read_text("utf-8") if ext == "txt" else res.read_bytes() == data
    assert getattr(dev, typ).original == data


def test_device_data_retrieve():
    dev = DeviceData(id="retrieve_test")
    with pytest.raises(PeatError):
        dev.retrieve("attrthatdoesnotexist", {})
    assert dev.retrieve("interface", {}) is None
    ip = "192.168.223.223"
    iface_type = "ethernet"
    dev.store("interface", Interface(ip=ip, type=iface_type))
    assert dev.retrieve("interface", {"ip": ip}).ip == ip
    assert dev.retrieve("interface", {"ip": "10.11.12.13"}) is None
    # Ensure it still returns right result when there are multiple entries
    dev.store("interface", Interface(ip="172.16.17.18", type=iface_type))
    assert dev.retrieve("interface", {"ip": ip}).ip == ip
    # Retrieving multiple values (in this case, all ethernet interfaces)
    assert len(dev.retrieve("interface", {"type": iface_type})) == 2


def test_device_data_store_bad_value():
    """test value is not base model raises exception."""
    dev = DeviceData()
    with pytest.raises(PeatError):
        dev.store("event", {"bad": "bad"})


def test_device_data_store_interface_autopopulate(mocker):
    mocker.patch.dict(config["CONFIG"], {"RESOLVE_HOSTNAME": True, "RESOLVE_IP": True})
    mgr_ip = DeviceData(name="test_int_ip")
    ip = "127.0.0.1"
    # NOTE (cegoes): VMWare Horizon messes with hosts file on Windows (*sigh*)\
    # NOTE 2 (cegoes, 12/12/2022): on Windows server, 127.0.0.1 resolves to
    # hostname on the Windows CI server. Just disabling check for now.
    # (03/14/2022): k8s does as well
    # localhosts = ["localhost", "view-localhost", "kubernetes.docker.internal"]

    mgr_ip.store("interface", Interface(ip=ip))
    assert mgr_ip.id == ip
    assert mgr_ip.ip == ip
    # assert mgr_ip.hostname in localhosts
    assert len(mgr_ip.interface) == 1

    mgr_host = DeviceData(name="test_int_host")
    mgr_host.store("interface", Interface(hostname="localhost"))
    assert mgr_host.id == ip
    assert mgr_host.ip == ip
    # assert mgr_host.hostname in localhosts
    assert len(mgr_host.interface) == 1


def test_device_data_store_service():
    dev = DeviceData(name="test_int_svc")
    ip = "127.0.0.1"
    test_svc = Service(protocol="http", port=80, transport="tcp", enabled=True)

    dev.store("interface", Interface(ip=ip))
    dev.store(
        key="service",
        value=test_svc,
        interface_lookup={"ip": ip},  # Interface for the service
    )

    assert len(dev.service) == 1
    assert len(dev.interface[0].services) == 1
    svc = dev.interface[0].services[0]
    # ensure service on interface matches that in dev.services
    assert svc == dev.service[0]
    assert svc == test_svc  # check it matches original


def test_device_data_store_register():
    dev = DeviceData(name="test_store_register")
    dev.store("registers", Register(protocol="dnp3", address="10000"))
    assert len(dev.registers) == 1
    assert dev.registers[0].protocol == "dnp3"
    reg = Register(address="23", tag="var_rtu-8_IO")
    dev.store("registers", reg)
    assert len(dev.registers) == 2
    assert dev.registers[1] == reg


def test_device_data_store_tag():
    dev = DeviceData(name="test_store_tag")
    dev.store("tag", Tag(name="var_rtu-8_I0", type="analog"))
    assert len(dev.tag) == 1
    assert dev.tag[0].type == "analog"
    tag = Tag(io="rtu-8_I0")
    dev.store("tag", tag)
    assert len(dev.tag) == 2
    assert dev.tag[1] == tag


def test_device_data_store_module():
    dev = DeviceData()
    dev.id = "testing"
    io_module = DeviceData(name="digitalIO", type="I/O", slot="1")
    dev.store("module", io_module)
    assert dev.module[0] == io_module
    assert "digitalIO" in str(dev)


def test_device_data_store_append():
    dev = DeviceData(name="test_store_append")
    dev.store(key="tag", value=Tag(name="test_append_tag", type="digital"), append=True)
    assert len(dev.tag) == 1
    assert dev.tag[0].type == "digital"
    tag = Tag(io="append_tag_2")
    dev.store("tag", tag, append=True)
    assert len(dev.tag) == 2
    assert dev.tag[1] == tag


def test_device_data_is_duplicate():
    assert DeviceData().is_duplicate(DeviceData()) is False
    dupe_1 = DeviceData()
    dupe_1.serial_port = "test_port"
    dupe_2 = DeviceData()
    dupe_2.serial_port = "test_port"
    assert dupe_1.is_duplicate(dupe_2) is True
    non_dupe_1 = DeviceData()
    non_dupe_1.ip = "192.0.2.20"
    non_dupe_2 = DeviceData()
    non_dupe_2.ip = "10.0.0.20"
    assert non_dupe_1.is_duplicate(non_dupe_2) is False


def test_device_data_validation_failures():
    dev = DeviceData()
    with pytest.raises(ValueError):
        dev.ip = 0
    with pytest.raises(ValueError):
        dev.ip = "thisisn't a valid IP"
    iface = Interface()
    with pytest.raises(ValueError):
        iface.mtu = -1
    with pytest.raises(ValueError):
        iface.description = "hello"


def test_device_data_validation_clean():
    dev = DeviceData()
    dev.ip = "    192.0.2.1   "
    assert dev.ip == "192.0.2.1"


def test_device_data_label_autopopulate(mocker, examples_path):
    """Hacky test but gets the job done."""
    yml_config = yaml.safe_load(examples_path("peat-config.yaml").read_text())
    mocker.patch.dict(config["CONFIG"], {"HOSTS": yml_config["hosts"]})

    dev = DeviceData(ip="192.168.0.1")
    assert dev.label == "example-host"
    assert dev.comment.startswith("User-specified text")

    assert DeviceData(mac="00:00:00:00:00:00").label == "example-host"
    assert DeviceData(serial_port="COM0").label == "example-host"
    assert DeviceData(name="some-device-name").label == "example-host"
    assert DeviceData(hostname="a-hostname").label == "example-host"

    assert DeviceData(label="test-label").label == "test-label"

    assert not DeviceData(ip="192.168.0.2").label
    assert not DeviceData(ip="192.168.0.2").comment
    assert not DeviceData().label
    assert not DeviceData().comment

import datetime

import pytest

from peat import DeviceData, config
from peat.parsing import command_parsers

# to get data artifacts:
#   run the test
#   look in: /tmp/pytest-of-<username>/pytest-current/...
#   just keep tab-completing to the path that has "current" in it
#   to get to the file output for your test.


def test_command_parser_edge_cases(mocker, tmp_path, caplog):
    mocker.patch.dict(config["CONFIG"], {"DEVICE_DIR": tmp_path})
    dev = DeviceData(id="test_command_parser_edge_cases")

    assert not command_parsers.VarLogMessagesParser.parse_and_process("", dev)
    assert "WARNING" in caplog.text

    with pytest.raises(ValueError):
        command_parsers.NixParserBase.parse_and_process("data", dev)

    with pytest.raises(ValueError):
        assert command_parsers.NixParserBase.type()

    assert command_parsers.VarLogMessagesParser.parse("blahblah") == []
    assert not command_parsers.VarLogMessagesParser.parse_and_process("blahblah", dev)
    assert not command_parsers.VarLogMessagesParser.parse_and_process("", dev)

    assert command_parsers.VarLogMessagesParser.__name__ == "VarLogMessagesParser"
    assert command_parsers.VarLogMessagesParser.type() == "file"
    assert command_parsers.DateParser.type() == "command"

    assert command_parsers.NixParserBase.parse("") is None
    assert command_parsers.NixParserBase.process("", dev) is None


def test_parse_env(text_data, json_data, mocker, tmp_path, assert_no_errors):
    mocker.patch.dict(config["CONFIG"], {"DEVICE_DIR": tmp_path})

    assert command_parsers.EnvParser.parse("") == {}

    input_data = text_data("env.txt")
    results = command_parsers.EnvParser.parse(input_data)
    expected = json_data("expected_env.json")
    assert results == expected

    dev = DeviceData(id="test_parse_env")
    assert command_parsers.EnvParser.parse_and_process(input_data, dev)
    assert dev.extra["env"] == expected
    assert_no_errors()


def test_parse_proc_cmdline(mocker, tmp_path, text_data, json_data, assert_no_errors):
    mocker.patch.dict(config["CONFIG"], {"DEVICE_DIR": tmp_path})
    assert command_parsers.ProcCmdlineParser.parse("") == {}

    results = command_parsers.ProcCmdlineParser.parse(text_data("proc_cmdline.txt"))
    assert results == json_data("expected_proc_cmdline.json")

    dev = DeviceData(id="test_parse_proc_cmdline")
    command_parsers.ProcCmdlineParser.process(results, dev)
    assert dev.extra["/proc/cmdline"] == results

    assert_no_errors()


def test_parse_proc_cpuinfo(text_data, json_data, assert_no_errors):
    assert command_parsers.ProcCpuinfoParser.parse("") == {}

    results = command_parsers.ProcCpuinfoParser.parse(text_data("proc_cpuinfo.txt"))
    assert results == json_data("expected_proc_cpuinfo.json")
    assert_no_errors()


def test_process_proc_cpuinfo(json_data, mocker, tmp_path, assert_no_errors):
    mocker.patch.dict(config["CONFIG"], {"DEVICE_DIR": tmp_path})

    assert not command_parsers.ProcCpuinfoParser.process({}, DeviceData())

    dev = DeviceData(id="process_proc_cpuinfo")
    data = json_data("expected_proc_cpuinfo.json")
    command_parsers.ProcCpuinfoParser.process(data, dev)
    assert dev.hardware.cpu.model == "e500v2"
    assert dev.hardware.cpu.full == "P1020 RDB e500v2"
    assert (
        dev.hardware.cpu.description
        == "P1020 RDB e500v2 799.999992MHz revision 5.1 (pvr 8021 2051)"
    )
    assert_no_errors()


def test_parse_proc_meminfo(text_data, json_data, assert_no_errors):
    assert command_parsers.ProcMeminfoParser.parse("") == {}

    results = command_parsers.ProcMeminfoParser.parse(text_data("proc_meminfo.txt"))
    assert results == json_data("expected_proc_meminfo.json")
    assert_no_errors()


def test_process_proc_meminfo(json_data, mocker, tmp_path, assert_no_errors):
    mocker.patch.dict(config["CONFIG"], {"DEVICE_DIR": tmp_path})

    assert not command_parsers.ProcMeminfoParser.process({}, DeviceData())

    dev = DeviceData(id="process_proc_meminfo")
    data = json_data("expected_proc_meminfo.json")
    command_parsers.ProcMeminfoParser.process(data, dev)
    assert dev.hardware.memory_total == 193191936
    assert dev.hardware.memory_available == 118960128
    assert_no_errors()


def test_parse_proc_modules(mocker, tmp_path, text_data, json_data, assert_no_errors):
    mocker.patch.dict(config["CONFIG"], {"DEVICE_DIR": tmp_path})

    assert command_parsers.ProcModulesParser.parse("") == []

    results = command_parsers.ProcModulesParser.parse(text_data("proc_modules.txt"))
    assert results == json_data("expected_proc_modules.json")

    dev = DeviceData(id="test_parse_proc_modules")
    command_parsers.ProcModulesParser.process(results, dev)
    assert dev.extra["/proc/modules"] == results

    assert_no_errors()


def test_parse_proc_uptime(text_data, mocker, tmp_path, assert_no_errors):
    mocker.patch.dict(config["CONFIG"], {"DEVICE_DIR": tmp_path})

    input_data = text_data("proc_uptime.txt")
    expected = datetime.timedelta(seconds=21165.34)

    results = command_parsers.ProcUptimeParser.parse(input_data)
    assert results == expected

    dev = DeviceData(id="test_parse_proc_uptime")
    assert command_parsers.ProcUptimeParser.parse_and_process(input_data, dev)
    assert dev.uptime == expected
    assert_no_errors()


def test_proc_net_dev_parser(text_data, json_data, mocker, tmp_path, assert_no_errors):
    mocker.patch.dict(config["CONFIG"], {"DEVICE_DIR": tmp_path})

    assert not command_parsers.ProcNetDevParser.parse("")

    input_data = text_data("dev")
    expected = json_data("expected_dev.json")

    results = command_parsers.ProcNetDevParser.parse(input_data)
    assert results == expected

    dev = DeviceData(id="test_procnetdevparser")
    assert command_parsers.ProcNetDevParser.parse_and_process(input_data, dev)
    assert dev.extra["/proc/net/dev"] == expected
    assert len(dev.interface) == 7
    assert dev.interface[0].type == "loopback"
    assert dev.interface[1].type == "ethernet"
    assert_no_errors()


def test_dateparser(text_data, mocker, tmp_path, assert_no_errors):
    mocker.patch.dict(config["CONFIG"], {"DEVICE_DIR": tmp_path})

    assert not command_parsers.DateParser.parse("")

    assert command_parsers.DateParser.parse(text_data("date.txt")).year == 2019

    dev = DeviceData(id="test_dateparser")
    assert command_parsers.DateParser.parse_and_process(text_data("date.txt"), dev)
    assert dev.geo.timezone == "UTC"
    assert dev.extra["current_time"].year == 2019
    assert_no_errors()


def test_parse_etc_passwd(text_data, json_data, assert_no_errors):
    assert command_parsers.EtcPasswdParser.parse("") == []

    results = command_parsers.EtcPasswdParser.parse(text_data("etc_passwd.txt"))
    assert results == json_data("expected_etc_passwd.json")
    assert_no_errors()


def test_process_etc_passwd(json_data, mocker, tmp_path, assert_no_errors):
    mocker.patch.dict(config["CONFIG"], {"DEVICE_DIR": tmp_path})

    assert not command_parsers.EtcPasswdParser.process([], DeviceData())

    dev = DeviceData(id="process_etc_passwd")
    data = json_data("expected_etc_passwd.json")
    command_parsers.EtcPasswdParser.process(data, dev)
    assert len(dev.users) == 5
    assert len(dev.related.user) == 5
    assert len(dev.related.files) == 3
    assert "/bin/sh" in dev.related.files
    assert "ftp" in dev.related.user
    assert dev.users[4].name == "admin"
    assert dev.users[4].description == "Linux User"
    assert_no_errors()


# TODO: WIP on IpAddrParser
# def test_parse_ipaddr(text_data, json_data, assert_no_errors):
#     assert command_parsers.IpAddrParser.parse("") == {}
#
#     parsed = command_parsers.IpAddrParser.parse(text_data("ip_addr.txt"))
#     assert parsed == {}
#     # assert parsed == json_data("expected_parsed_ip_addr.json")
#     assert_no_errors()


def test_sshd_config_parser(text_data, json_data, assert_no_errors):
    assert not command_parsers.SshdConfigParser.parse("")

    results = command_parsers.SshdConfigParser.parse(text_data("sshd_config"))
    assert results == json_data("expected_sshd_config.json")
    assert_no_errors()

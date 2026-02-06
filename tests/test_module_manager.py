import shutil
from pathlib import Path

import pytest

from peat import (
    M340,
    SCEPTRE,
    SELRTAC,
    WDW2301E,
    ControlLogix,
    DeviceModule,
    MicroNet,
    Sage,
    SELRelay,
    Siprotec,
    module_api,
)

module_compares = [
    ("ControlLogix", ControlLogix),
    ("controllogix", ControlLogix),
    ("M340", M340),
    ("MICRONET", MicroNet),
    ("selrelay", SELRelay),
    ("selrtac", SELRTAC),
    ("sceptre", SCEPTRE),
    ("sage", Sage),
    ("siprotec", Siprotec),
    ("WDW2301E", WDW2301E),
]


def test_names():
    assert all(isinstance(x, str) for x in module_api.names)
    assert "M340" in module_api.names


def test_classes():
    assert all(module_api.is_valid_module(x) for x in module_api.classes)
    assert M340 in module_api.classes


def test_filter_names():
    assert all(isinstance(x, str) for x in module_api.filter_names("vendor"))
    # NOTE: this test might fail if a module doesn't set a default for "device_type"
    assert len(module_api.filter_names("device_type")) == len(module_api.modules)
    assert "ControlLogix" in module_api.filter_names("ip_methods")
    assert not module_api.filter_names("WHATARETHESE")


def test_import_module():
    assert module_api.import_module([]) is False
    assert module_api.import_module(Path("404HEALERNOTFOUND")) is False
    assert module_api.import_module(["DROIDSTHATDONOTEXIST"]) is False


@pytest.mark.parametrize("cls", [x[1] for x in module_compares])
def test_import_module_parameterized(cls):
    assert module_api.import_module(cls)
    assert cls.__name__ in module_api.names


def test_import_module_path_invalid_modules(tmp_path):
    assert module_api.import_module_path(Path("404HEALERNOTFOUND")) is False
    empty_module_dir = tmp_path / "empty_module_dir"
    empty_module_dir.mkdir()
    assert module_api.import_module_path(empty_module_dir) is False
    empty_module_file = empty_module_dir / "somemodule.py"
    empty_module_file.write_text("#nothing here\n")
    assert module_api.import_module_path(empty_module_file) is False
    with pytest.raises(AttributeError):
        module_api.import_module_path(None)


def test_import_module_path_valid_module_file(mocker, tmp_path, example_module_file):
    # TODO: mock the import so we can test valid_module_dir
    #  (currently it will pass if this test passes)
    # Mock the imported modules so this test doesn't affect other module tests
    mocker.patch.object(module_api, "modules", {})
    mocker.patch.object(module_api, "module_aliases", {})
    mocker.patch.object(module_api, "runtime_imports", set())
    mocker.patch.object(module_api, "runtime_paths", set())
    mod_dir = tmp_path / "valid_module_file"
    mod_dir.mkdir()
    mod_path = mod_dir / "awesome_module.py"
    shutil.copyfile(example_module_file("awesome_module.py"), mod_path)
    assert module_api.import_module(mod_path) is True
    assert "awesometool" in module_api.runtime_imports
    assert mod_path in module_api.runtime_paths

    # List of modules (TODO: move this to separate test)
    assert module_api.import_module([mod_path]) is True


def test_import_module_path_valid_module_dir(mocker, tmp_path, example_module_file):
    # Mock the imported modules so this test doesn't affect other module tests
    mocker.patch.object(module_api, "modules", {})
    mocker.patch.object(module_api, "module_aliases", {})
    mocker.patch.object(module_api, "runtime_imports", set())
    mocker.patch.object(module_api, "runtime_paths", set())
    mod_dir = tmp_path / "valid_module_dir"
    mod_dir.mkdir()
    mod_path = mod_dir / "awesome_module.py"
    shutil.copyfile(example_module_file("awesome_module.py"), mod_path)
    assert module_api.import_module(mod_dir) is True


@pytest.mark.parametrize("cls", [x[1] for x in module_compares])
def test_import_module_cls(cls):
    assert module_api.import_module_cls(cls)
    assert cls.__name__ in module_api.names


def test_import_module_cls_special_cases():
    assert module_api.import_module_cls(M340)
    assert module_api.import_module_cls(SELRelay, False)
    assert module_api.import_module_cls(None) is False
    assert module_api.import_module_cls("") is False
    assert module_api.import_module_cls(DeviceModule) is False
    assert module_api.import_module_cls(M340()) is False
    assert module_api.import_module_cls("DROIDSTHATDONOTEXIST") is False


@pytest.mark.parametrize(("name", "cls"), module_compares)
def test_get_module(name, cls):
    assert module_api.get_module(name) is cls


def test_get_module_special_cases():
    assert module_api.get_module("allen-bradley") is None
    assert module_api.get_module("INVALIDMODULE") is None


@pytest.mark.parametrize(("name", "cls"), module_compares)
def test_get_modules(name, cls):
    assert module_api.get_modules(name) == [cls]


def test_get_modules_filter():
    assert ControlLogix in module_api.get_modules("ControlLogix", "ip_methods")
    assert ControlLogix not in module_api.get_modules("ControlLogix", "serial_methods")


def test_get_modules_special_cases():
    assert module_api.get_modules("allen-bradley") == [ControlLogix]
    assert module_api.get_modules("sandia") == [SCEPTRE]
    assert module_api.get_modules("INVALIDMODULE") == []


@pytest.mark.parametrize(("name", "cls"), module_compares)
def test_lookup_types(name, cls):
    assert module_api.lookup_types(name) == [cls]
    assert module_api.lookup_types([name]) == [cls]
    assert module_api.lookup_types([name], filter_attr="vendor_id") == [cls]


def test_lookup_names():
    assert module_api.lookup_names("controllogix") == ["ControlLogix"]
    assert module_api.lookup_names("ControlLogix") == ["ControlLogix"]
    assert module_api.lookup_names(["controllogix"]) == ["ControlLogix"]
    assert module_api.lookup_names(ControlLogix) == ["ControlLogix"]
    assert module_api.lookup_names([ControlLogix]) == ["ControlLogix"]
    assert module_api.lookup_names(["controllogix"], filter_attr="vendor_id") == ["ControlLogix"]
    assert module_api.lookup_names("all") == module_api.names


def test_process_types_special_cases():
    assert module_api.lookup_types() == module_api.classes
    assert module_api.get_modules("INVALIDMODULE") == []
    assert module_api.lookup_types("INVALIDMODULE") == []
    assert module_api.lookup_types(["allen-bradley", "clx", "controllogix"]) == [ControlLogix]
    assert module_api.lookup_types(M340) == [M340]  # Class
    assert module_api.lookup_types([M340]) == [M340]  # Class
    assert module_api.lookup_types(M340()) == [M340]  # Instance
    assert module_api.lookup_types([M340()]) == [M340]  # Instance
    assert SELRelay in module_api.lookup_types(
        filter_attr="filename_patterns", subclass_method="_parse"
    )
    ip_mods = module_api.lookup_types(filter_attr="ip_methods")
    assert ControlLogix in ip_mods
    assert WDW2301E not in ip_mods

    file_mods = module_api.lookup_types(module_api.classes, "filename_patterns")
    parse_mods = module_api.lookup_types(module_api.classes, subclass_method="_parse")
    assert set(file_mods) <= set(parse_mods)

    # NOTE: GERelay has _parse() implemented but not filename_patterns
    dir_mods = module_api.lookup_types(module_api.classes, "can_parse_dir")
    assert set(file_mods + dir_mods) == set(parse_mods)


def test_alias_to_names():
    assert module_api.alias_to_names("clx") == ["ControlLogix"]
    assert module_api.alias_to_names("all") == module_api.names
    assert module_api.alias_to_names("ALL") == module_api.names
    assert module_api.alias_to_names("INVALIDALIAS") == []


@pytest.mark.parametrize("cls", [x[1] for x in module_compares])
def test_is_valid_module(cls):
    assert module_api.is_valid_module(cls)


def test_is_valid_module_special_cases():
    assert module_api.is_valid_module(DeviceModule) is False
    assert module_api.is_valid_module(ControlLogix()) is False
    assert module_api.is_valid_module("INVALIDMODULE") is False
    assert module_api.is_valid_module(Path) is False


def test_extract_members():
    assert module_api._extract_members("invalid.path") == []

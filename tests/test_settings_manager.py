"""
This module is sort of implicitly tested via other tests, notably the CLI tests
and anything that mocks out the config. These tests ensure edge cases don't break
things, as well as verifying that breakages in other tests aren't due to breakages
in the config or state.
"""

import json
import os
from pathlib import Path
from typing import Literal

import pytest
import yaml
from pydantic import ValidationError

from peat.consts import PeatError, lower_dict
from peat.settings_manager import SettingsManager


@pytest.fixture
def settings_cls() -> type[SettingsManager]:
    class TestSettings(SettingsManager):
        TEST_OPTION: str = "default_value"
        ALPHA: bool = False

    return TestSettings


@pytest.fixture  # scope="function"
def settings_instance(settings_cls: type[SettingsManager]) -> SettingsManager:
    return settings_cls(label="configuration", env_prefix="TEST_", init_env=False)


def test_load_from_dict(settings_instance):
    settings_instance.load_from_dict({"ALPHA": True, "test_option": "string"})
    assert settings_instance.ALPHA
    assert settings_instance.TEST_OPTION == "string"


def test_load_from_environment(settings_instance, mocker):
    mocker.patch.dict(os.environ, {"TEST_ALPHA": "true"})
    settings_instance.load_from_environment()
    assert settings_instance.ALPHA


def test_defaults_ignore_unprefixed_environment_variables(settings_cls, mocker):
    # Regression test: defaults must ignore real, un-prefixed env vars/.env files/secrets.
    mocker.patch.dict(os.environ, {"ALPHA": "true", "TEST_OPTION": "not-the-real-default"})

    inst = settings_cls(label="configuration", env_prefix="TEST_", init_env=False)

    assert inst._field_defaults()["ALPHA"] is False
    assert inst._field_defaults()["TEST_OPTION"] == "default_value"
    assert inst.ALPHA is False
    assert inst.TEST_OPTION == "default_value"


@pytest.mark.parametrize("file_ext", ["json", "yaml"])
def test_load_from_file(settings_instance, datapath, file_ext):
    assert settings_instance.load_from_file(datapath(f"test_load_from_file.{file_ext}"))
    assert settings_instance.export() == {
        "ALPHA": False,
        "ENV_PREFIX": "TEST_",
        "TEST_OPTION": "default_value",
    }


def test_save_to_file(settings_instance, tmp_path, assert_glob_path):
    settings_instance.save_to_file(outdir=tmp_path)

    json_path = assert_glob_path(tmp_path, "peat_configuration.json")
    assert json.loads(json_path.read_text()) == settings_instance.export()

    yaml_path = assert_glob_path(tmp_path, "peat_configuration.yaml")
    assert yaml.safe_load(yaml_path.read_text()) == lower_dict(settings_instance.export())


def test_save_to_file_no_yaml(settings_instance, tmp_path, assert_glob_path):
    settings_instance.save_to_file(outdir=tmp_path, save_yaml=False)

    json_path = assert_glob_path(tmp_path, "peat_configuration.json")  # only a JSON file
    assert json.loads(json_path.read_text()) == settings_instance.export()


def test_save_to_file_no_json(settings_instance, tmp_path, assert_glob_path):
    settings_instance.save_to_file(outdir=tmp_path, save_json=False)

    yaml_path = assert_glob_path(tmp_path, "peat_configuration.yaml")
    assert yaml.safe_load(yaml_path.read_text()) == lower_dict(settings_instance.export())


def test_save_to_file_raises(settings_instance, tmp_path):
    with pytest.raises(PeatError):
        settings_instance.save_to_file(outdir=tmp_path, save_yaml=False, save_json=False)


def test_export(settings_instance):
    assert settings_instance.export() == {
        "ALPHA": False,
        "ENV_PREFIX": "TEST_",
        "TEST_OPTION": "default_value",
    }
    settings_instance.TEST_OPTION = "non-default_value"
    assert settings_instance.export() == {
        "ALPHA": False,
        "ENV_PREFIX": "TEST_",
        "TEST_OPTION": "non-default_value",
    }
    settings_instance.TEST_OPTION = None
    assert settings_instance.export() == {"ALPHA": False, "ENV_PREFIX": "TEST_"}


def test_yaml(settings_instance):
    assert settings_instance.yaml()
    assert yaml.safe_load(settings_instance.yaml()) == lower_dict(settings_instance.export())


def test_json(settings_instance):
    assert settings_instance.json()
    assert json.loads(settings_instance.json()) == settings_instance.export()


def test_json_dict(settings_instance):
    assert settings_instance.json_dict() == {
        "ALPHA": False,
        "ENV_PREFIX": "TEST_",
        "TEST_OPTION": "default_value",
    }
    settings_instance.TEST_OPTION = "non-default_value"
    assert settings_instance.json_dict() == {
        "ALPHA": False,
        "ENV_PREFIX": "TEST_",
        "TEST_OPTION": "non-default_value",
    }
    settings_instance.TEST_OPTION = None
    assert settings_instance.json_dict() == {"ALPHA": False, "ENV_PREFIX": "TEST_"}


def test_get_serialized_value(settings_instance):
    assert settings_instance.get_serialized_value("ALPHA") is False
    settings_instance.ALPHA = True
    assert settings_instance.get_serialized_value("ALPHA") is True


def test_typecast(tmp_path):
    class TestTypecast(SettingsManager):
        TEST_OPTION: str = "default_value"
        ALPHA: bool = False
        PTH: Path = Path("somepath")
        PATHS: list[str | Path] = []
        OPTS: str | None = None

    inst = TestTypecast(label="configuration", env_prefix="TEST_", init_env=False)
    assert inst.typecast("ALPHA", False) is False
    assert inst.typecast("ALPHA", "yes") is True
    assert inst.typecast("ALPHA", "false") is False
    assert inst.typecast("ALPHA", "yes") is True
    assert inst.typecast("PTH", tmp_path) == tmp_path
    assert inst.typecast("PTH", tmp_path.as_posix()) == tmp_path
    assert inst.typecast("TEST_OPTION", "1") == "1"
    # str fields are validated by pydantic, so non-string values are rejected
    # instead of being loosely stringified (catches config mistakes early).
    with pytest.raises(ValidationError):
        inst.typecast("TEST_OPTION", 1)
    assert inst.typecast("PATHS", []) == []
    assert inst.typecast("PATHS", ["/some/path/", "somefile.txt"]) == [
        "/some/path/",
        "somefile.txt",
    ]
    assert inst.typecast("OPTS", None) is None
    assert inst.typecast("OPTS", "{'one': 1}") == "{'one': 1}"


def test_typecast_path_disabled_sentinel(tmp_path):
    class TestSentinelPath(SettingsManager):
        PTH: Path | Literal[""] = Path("somepath")

    inst = TestSentinelPath(label="configuration", env_prefix="TEST_", init_env=False)
    assert inst.typecast("PTH", tmp_path.as_posix()) == tmp_path
    assert inst.typecast("PTH", "~") == Path(os.path.expanduser("~"))
    assert inst.typecast("PTH", "") == ""


def test_typecast_container_json_string():
    class TestContainerTypecast(SettingsManager):
        PATHS: list[str] = []
        OPTIONS: dict = {}
        TAGS: set[str] = set()

    inst = TestContainerTypecast(label="configuration", env_prefix="TEST_", init_env=False)

    assert inst.typecast("PATHS", '["a", "b"]') == ["a", "b"]
    assert inst.typecast("OPTIONS", '{"one": 1}') == {"one": 1}
    assert inst.typecast("TAGS", '["a", "b"]') == {"a", "b"}

    # A string that isn't valid JSON is passed through as-is, so pydantic's own
    # validation error is raised instead of a JSON decode error.
    with pytest.raises(ValidationError):
        inst.typecast("PATHS", "not-json-and-not-a-list")


def test_typecast_invalid_values_raise():
    class TestInvalidTypecast(SettingsManager):
        ALPHA: bool = False
        PTH: Path = Path("somepath")
        PATHS: list[str] = []

    inst = TestInvalidTypecast(label="configuration", env_prefix="TEST_", init_env=False)

    with pytest.raises(ValidationError):
        inst.typecast("ALPHA", "notabool")
    with pytest.raises(ValidationError):
        inst.typecast("PTH", 12345)
    with pytest.raises(ValidationError):
        inst.typecast("PATHS", "not-json-and-not-a-list")

    # The failed attempts above must not have left the shared scratch instance with a
    # corrupted/partial value for the key that failed.
    assert inst._scratch.ALPHA is False
    assert inst.typecast("ALPHA", "yes") is True


def test_typecast_no_state_leak_across_keys(tmp_path):
    class TestLeakTypecast(SettingsManager):
        ALPHA: bool = False
        BETA: bool = False
        PTH: Path = Path("somepath")

    inst = TestLeakTypecast(label="configuration", env_prefix="TEST_", init_env=False)

    assert inst.typecast("ALPHA", "yes") is True
    assert inst.typecast("BETA", "no") is False
    assert inst.typecast("PTH", tmp_path) == tmp_path

    # Re-validating ALPHA must still reflect what was set earlier, not something
    # influenced by BETA/PTH having since been validated against the same shared scratch.
    assert inst.typecast("ALPHA", "yes") is True
    scratch = inst._scratch
    assert scratch.ALPHA is True
    assert scratch.BETA is False
    assert scratch.PTH == tmp_path

    # Setting BETA afterwards must not retroactively affect ALPHA or PTH.
    assert inst.typecast("BETA", "yes") is True
    assert scratch.ALPHA is True
    assert scratch.PTH == tmp_path


def test_non_default(settings_instance):
    assert not settings_instance.non_default("TEST_OPTION")
    settings_instance.TEST_OPTION = "some new value"
    assert settings_instance.non_default("TEST_OPTION")


def test_is_default_value(settings_instance):
    assert settings_instance.is_default_value("TEST_OPTION")
    settings_instance.TEST_OPTION = "some other non-default value"
    assert not settings_instance.is_default_value("TEST_OPTION")

import pytest
import yaml

from peat.consts import lower_dict
from peat.data import DeviceData
from peat.settings import Configuration


@pytest.fixture
def yml_config(examples_path) -> dict:
    return yaml.safe_load(examples_path("peat-config.yaml").read_text())


def test_example_yaml_config_matches_settings(yml_config):
    conf = Configuration("configuration", env_prefix="TEST_CONF_", init_env=False)
    exported = lower_dict(conf.json_dict(include_none_vals=True))
    assert sorted(exported.keys()) == sorted(yml_config.keys())


def test_device_options_defaults(yml_config, deep_compare):
    deep_compare(
        DeviceData().options.to_dict(),
        yml_config["device_options"],
        exclude_regexes=r"\['(user|pass|users|passwords|creds|pull_delay|ec)'\]",
    )


def test_simple_example_yaml_config_matches_settings(examples_path):
    conf = Configuration("configuration", env_prefix="TEST_CONF_", init_env=False)
    exported = lower_dict(conf.json_dict(include_none_vals=True))
    yml_config = yaml.safe_load(examples_path("peat-config-simple.yaml").read_text())
    assert sorted(exported.keys()) == sorted(yml_config.keys())

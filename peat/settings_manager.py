import json
import os
from collections import ChainMap
from pathlib import Path
from typing import Any, Union, get_args, get_origin, get_type_hints

import yaml
from loguru import logger as log

from .consts import PeatError, convert, lower_dict, str_to_bool


# Source: https://github.com/python-discord/bot
def _env_var_constructor(loader, node):
    """
    Implements a custom YAML tag for loading optional environment variables.

    If the environment variable is set, returns the value of it.
    Otherwise, returns :obj:`None`.

    Example usage in the YAML configuration:

       .. code-block:: yaml

          key: !ENV 'MY_APP_KEY'
    """
    default = None

    # Check if the node is a plain string value
    if node.id == "scalar":
        value = loader.construct_scalar(node)
        key = str(value)
    else:
        # The node value is a list
        value = loader.construct_sequence(node)
        if len(value) >= 2:
            # If we have at least two values, then we have both a key and a default value
            default = value[1]
            key = value[0]
        else:
            # Otherwise, we just have a key
            key = value[0]

    return os.getenv(key, default)


def _join_var_constructor(loader, node):
    """
    Implements a custom YAML tag for concatenating other tags in the document to strings.

    This allows for a much more DRY (Don't Repeat Yourself) configuration file.
    """
    return "".join(str(x) for x in loader.construct_sequence(node))


yaml.SafeLoader.add_constructor("!ENV", _env_var_constructor)
yaml.SafeLoader.add_constructor("!JOIN", _join_var_constructor)


class SettingsManager(dict):
    """
    Stores and manages configuration values from multiple sources.

    Typical usage is to subclass this class and configure the possible
    variables and default values as class attributes, much like :mod:`dataclasses`.

    .. warning::
       All class attributes MUST have a type! Otherwise, they will
       be skipped over and not appear in the list of defaults. This is
       due to the implementation being a hack on top of ``__annotations__``.

    Order of precedence for configurations

    - Runtime changes (example: ``config.DEBUG = 2``), including CLI arguments
    - Environment variables (example: ``export PEAT_DEBUG=2``)
    - Configuration file (YAML or JSON)
    - Default values set in subclasses of this class (example: ``DEBUG: int = 0``)

    Precedence is managed by a :class:`collections.ChainMap`.

    Args:
        label: The type of information being stored
        env_prefix: Prefix to use for environment variables
        init_env: Load values from environment variables during object initialization
    """

    def __init__(self, label: str, env_prefix: str, init_env: bool = True) -> None:
        # Initialize the "dict" parent class
        super().__init__()

        # Label is used to refer to this instance
        self["label"] = label

        # NOTE(cegoes): dict preserves order in CPython 3.6+ and Python 3.7+
        self["runtime_configs"] = {}
        self["env_configs"] = {}
        self["file_configs"] = {}

        # Use the class's variable attributes and annotations for defaults,
        # much like a dataclass (In fact, it's exactly what a dataclass does!).
        # https://github.com/python/cpython/blob/3.7/Lib/dataclasses.py#L828
        annotations: dict = getattr(self, "__annotations__", {})
        defaults: dict = {
            anno_name: dict.__getattribute__(self, anno_name)
            for anno_name in annotations.keys()
        }
        self["default_configs"] = defaults

        # Set the environment variable prefix
        self.env_prefix: str = env_prefix

        # ChainMap dynamically manages the lookup order. Changes to the
        # underlying objects will be immediately reflected in the map.
        self["CONFIG"] = ChainMap(
            self["runtime_configs"],
            self["env_configs"],
            self["file_configs"],
            self["default_configs"],
        )

        # NOTE: this must occur AFTER the ChainMap (self["CONFIG"]) has been set
        if init_env:
            self.load_from_environment(env_prefix=env_prefix)

    def _load_values(
        self, conf: dict[str, Any], load_to: str, key_prefix: str = ""
    ) -> None:
        """
        Read and set configuration values from a input dictionary.

        .. note::
           Any values that are :obj:`None` are skipped and will NOT be loaded

        Args:
            conf: Configuration to load
            load_to: Where in the Settings object the loaded configuration
                should be stored. Valid options are: ``runtime_configs``,
                ``env_configs``, and ``file_configs``.
            key_prefix: Optional value to prepend to the keys being looked up.
                Example use case is for loading environment variables
                prefixed with ``PEAT_``, where ``config=dict(os.environ)``.
        """
        # Convert input config keys to upper case
        # for consistent case-insensitive key lookups.
        upper_conf = {k.upper(): v for k, v in conf.items()}  # type: dict[str, Any]

        # Check if each possible option is in the input object,
        # since the input set is likely larger than the default set.
        # Furthermore, we do NOT want to accidentally add new
        # options that are not in the defaults to the object.
        for set_key in self["default_configs"].keys():
            key = f"{key_prefix}{set_key}".upper()

            # Skip values that are None
            if upper_conf.get(key) is not None:
                try:
                    self[load_to][set_key] = self.typecast(set_key, upper_conf[key])
                except Exception as ex:
                    log.critical(f"Failed to load config '{key}': {ex}")

        # !! Hack to make metadata directory configuration seamless and flexible !!
        if self["label"] == "configuration" and upper_conf.get("OUT_DIR"):
            self.OUT_DIR = self.OUT_DIR
        if self["label"] == "configuration" and upper_conf.get("RUN_DIR"):
            self.RUN_DIR = self.RUN_DIR

    def load_from_dict(self, conf: dict[str, Any]) -> None:
        """
        Update runtime configuration values from a dictionary.

        Args:
            conf: Configuration values to load

        Raises:
            AttributeError: If a configuration option in ``conf``
                is not already defined on the class
        """
        self._load_values(conf=conf, load_to="runtime_configs")

    def load_from_environment(self, env_prefix: str | None = None) -> None:
        """
        Update configuration values from environment variables.

        Args:
            env_prefix: String prefixing the environment variable names, e.g.
                ``PEAT_`` to load variables such as ``PEAT_DEBUG`` into ``DEBUG``.
                If :obj:`None`, then this is set to ``self.env_prefix``.

        Raises:
            AttributeError: If a configuration option in the environment
                is not already defined on the class
        """
        if env_prefix is None:
            env_prefix = self.env_prefix

        self._load_values(
            conf=dict(os.environ), load_to="env_configs", key_prefix=env_prefix
        )

    def load_from_file(self, file: Path) -> bool:
        """
        Load stored values from a YAML or JSON file.

        Note that these settings can be overridden by environment
        variables or values set at runtime.

        Args:
            file: Path to a YAML or JSON file to load settings from

        Returns:
            If the load was successful

        Raises:
            AttributeError: If a configuration option loaded from the file
                is not already defined on the class
        """
        log.info(f"Loading configuration from file '{file.name}'...")

        if not file.is_file():
            log.error(
                f"Configuration file '{file.name}' is not a file or does not exist"
            )
            return False

        if file.suffix.lower() in [".yml", ".yaml"]:
            log.debug(f"Loading configuration from YAML file '{file.name}'")
            with file.open(encoding="utf-8") as yaml_file:
                file_config = yaml.safe_load(yaml_file)
        elif file.suffix.lower() == ".json":
            log.debug(f"Loading configuration from JSON file '{file.name}'")
            with file.open(encoding="utf-8") as json_file:
                file_config = json.load(json_file)
        else:
            log.error(
                f"Unknown extension '{file.suffix}' for configuration file "
                f"'{file.name}', it should be '.json', '.yaml', or '.yml'. "
                f"You might have accidentally selected the wrong file."
            )
            return False

        # Legacy config structure that allowed multi-app configs (other tools)
        if "PEAT" in file_config:
            file_config = file_config["PEAT"]

        self._load_values(file_config, load_to="file_configs")

        return True

    def save_to_file(
        self, outdir: Path, save_yaml: bool = True, save_json: bool = True
    ) -> None:
        """
        Save the currently stored values to YAML and JSON files.

        Args:
            outdir: Directory path to save the files to
            save_yaml: set to False to disable YAML file saving
            save_json: if settings should be saved as JSON
        """
        if not save_yaml and not save_json:
            raise PeatError(
                "Either save_yaml or save_json must be true for save_to_file"
            )

        if save_yaml:
            yaml_file = outdir / f"peat_{self['label']}.yaml"
        else:
            yaml_file = None

        if save_json:
            json_file = outdir / f"peat_{self['label']}.json"
        else:
            json_file = None

        # Hack to ensure the "state" and "configuration" files get included
        # in the set of files written by PEAT.
        # NOTE: this is done before the files are written to ensure
        # state.written_files includes the state paths as well.
        try:
            import peat

            if yaml_file:
                peat.state.written_files.add(yaml_file.as_posix())
            if json_file:
                peat.state.written_files.add(json_file.as_posix())
        except ImportError:
            pass

        # YAML format
        if yaml_file:
            if yaml_file.is_file():
                log.warning(
                    f"YAML {self['label'].capitalize()} file already exists "
                    f"at {yaml_file.name}, overwriting existing data..."
                )
            elif not yaml_file.parent.exists():
                yaml_file.parent.mkdir(parents=True, exist_ok=True)

            # NOTE: newline argument to Path.write_text() requires Python 3.10+
            with yaml_file.open("w", encoding="utf-8", newline="\n") as outfile:
                outfile.write(self.yaml())

        # JSON format
        if json_file:
            data_to_save = self.export()  # type: dict

            if json_file.is_file():
                log.warning(
                    f"JSON {self['label'].capitalize()} file already exists "
                    f"at {json_file.name}, overwriting existing data..."
                )
            elif not json_file.parent.exists():
                json_file.parent.mkdir(parents=True, exist_ok=True)

            with json_file.open("w", encoding="utf-8", newline="\n") as outfile:
                json.dump(data_to_save, outfile, indent=4)

    def export(self) -> dict[str, Any]:
        """
        Current values in a deterministic format that can be exported.

        Returns:
            JSON-serializable :class:`dict` with uppercase keys, sorted
            "alphabetically" by key (well, technically UNICODE order).
        """
        dict_config = dict(self.json_dict())
        sorted_config = sorted(dict_config.items(), key=lambda x: str(x[0]))

        return dict(sorted_config)

    def yaml(self) -> str:
        """
        Export the current settings as YAML text.
        """
        return yaml.dump(lower_dict(self.export()), line_break="\n")

    def json(self) -> str:
        """
        Export the current settings as JSON text.
        """
        return json.dumps(self.export(), indent=4)

    def json_dict(self, include_none_vals: bool = False) -> dict[str, Any]:
        """
        Convert the current settings to a JSON dictionary.

        Returns:
            The current setting values as a JSON-serializable
            :class:`dict` with uppercase keys.
        """
        return {
            key.upper(): self._serialize_value(value)
            for key, value in self["CONFIG"].items()
            if include_none_vals or value is not None  # Strip Nones
        }

    def get_serialized_value(self, item: str) -> Any:
        """
        Get a configuration value in a JSON-serializable format.

        Args:
            item: Case-sensitive name of the attribute to get

        Returns:
            The configuration value in a JSON-serializable format

        Raises:
            KeyError: If the attribute named by ``item`` doesn't exist
        """
        return self._serialize_value(self["CONFIG"][item])

    @staticmethod
    def _serialize_value(value: Any) -> Any:
        # This allows nesting of SettingsManager instances as values
        if isinstance(value, SettingsManager):
            return value.export()
        else:
            return convert(value)

    def typecast(self, key: str, value: Any) -> Any:
        """
        Convert and store a value as the appropriate Python data type.

        Store the variable as the appropriate Python data type,
        such as bool, int, float, str, Path, list, etc.
        This converts "0.5" to 0.5, "/home/" to Path("/home/"), etc.

        If the type is properly annotated (e.g. VAR: str = 'stuff'),
        then we use the annotation, otherwise try to infer the
        type from the default value. However, the backup method
        does not work if the default value is :obj:`None`.

        Args:
            key: Case-sensitive name of the value
                (what attribute will be changed)
            value: The raw value to typecast (e.g. a string from an
                environment variable)

        Returns:
            The typecasted value as a valid Python datatype matching the annotation

        Raises:
            KeyError: If the attribute named by ``key`` doesn't exist
        """
        fallback: type = type(self["default_configs"][key])
        typecast: type = get_type_hints(self.__class__).get(key, fallback)

        # Handle complex types, e.g. typing.Union, typing.List, typing.Set, etc.
        # Resolves the type to it's container class, e.g:
        #   get_origin(typing.List) => list
        #   get_origin(typing.Union[str, Path]) => typing.Union
        og = get_origin(typecast)

        # Resolves arguments to the type, e.g:
        #   get_args(Union[str, Path]) => (str, Path)
        #   get_args(Optional[Union[Path, str]]) => (Path, str, None)
        args = get_args(typecast)

        if og and og is Union:
            if type(None) in args and value is None:
                # Value is None, don't accidentally return the string "None"
                return None
            elif Path in args:  # If Path is in a Union, make it the typecast
                typecast = Path
            else:
                # Set typecast to the first type class in a Union that isn't "None"
                typecast = next(
                    iter(filter(lambda x: not isinstance(x, type(None)), args))
                )
        # The typing container is a base Python type, e.g. list, set, dict, etc.
        elif og and isinstance(og, type):
            # TODO: typecast items in a container, e.g. a list of path strings
            #   should be type-casted to a list of Path objects
            typecast = og
        elif og:
            log.warning(
                f"Unknown type container '{og}' for setting '{key}', "
                f"type casting to '{fallback}' as a fallback "
                f"(value being typecast: '{repr(value)}')"
            )
            typecast = fallback

        # Expand paths
        if typecast is Path and isinstance(value, str):
            if value == "":  # If value is empty string, don't set the path
                casted = ""
            else:
                casted = Path(os.path.realpath(os.path.expanduser(value)))
        # Handle boolean strings (e.g environment variable "true")
        elif typecast is bool and isinstance(value, str):
            # Accepts: yes, no, true, false, 0, 1 (case-insensitive)
            casted = str_to_bool(value)
        else:
            casted = typecast(value)  # type: ignore

        return casted

    def non_default(self, key: str) -> bool:
        """
        If an item was sourced by a non-default method (env, file, runtime).

        Args:
            key: Name of the item to check

        Returns:
            If the item has a value that *overrides* the default value. Note that
            this method will also return :class:`False` if the key isn't valid.
        """
        return any(
            key in self[k] for k in ["runtime_configs", "env_configs", "file_configs"]
        )

    def is_default_value(self, key: str) -> bool:
        """
        If an item's current value matches the default value.

        Args:
            key: Name of the item to check

        Returns:
            If the item has a value that *matches* the default value

        Raises:
            AttributeError: If the attribute named by ``key`` doesn't exist
        """
        return getattr(self, key) == self["default_configs"][key]

    def fixup_dirs(
        self,
        new_parent: str | Path | None,
        dir_name: str,
        override_all: bool = False,
    ) -> None:
        if dir_name == "OUT_DIR":
            dirs = ["RUN_DIR"]
        elif dir_name == "RUN_DIR":
            dirs = [
                "DEVICE_DIR",
                "ELASTIC_DIR",
                "META_DIR",
                "LOG_DIR",
                "SUMMARIES_DIR",
                "TEMP_DIR",
                "ZEEK_LOGDIR",
                "HEAT_ARTIFACTS_DIR",
            ]
        else:
            raise ValueError(f"invalid dir_name {dir_name}")

        for d in dirs:
            if new_parent is None and override_all:
                setattr(self, d, None)
                continue

            # Only change values that are still at their default values
            if not override_all and self.non_default(d):
                continue

            if new_parent is None:
                new_path = None
            else:
                old = getattr(self, d)  # type: Path
                new_path = Path(os.path.realpath(Path(new_parent, old.name)))

            setattr(self, d, new_path)

    def __getattribute__(self, item: str) -> Any:
        if not item.startswith("__") and item in self["CONFIG"]:
            return self["CONFIG"][item]
        else:
            return dict.__getattribute__(self, item)

    def __setattr__(self, key: str, value: Any) -> None:
        # !! Hack to make metadata directory configuration seamless and flexible !!
        if self["label"] == "configuration":
            if key in ["OUT_DIR", "RUN_DIR"]:
                self.fixup_dirs(value, key)

        # This makes class attribute assignments put stuff in the
        # runtime configs, which makes "config.DEBUG = 1" equivalent
        # to "config["runtime_configs"]["DEBUG"] = 1".
        self["runtime_configs"][key] = value


__all__ = ["SettingsManager"]

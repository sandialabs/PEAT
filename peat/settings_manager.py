import json
import os
from collections.abc import Iterator, MutableMapping
from pathlib import Path
from types import UnionType  # NOTE: won't be needed once minimum python is 3.14
from typing import Any, Union, get_args, get_origin

import yaml
from loguru import logger as log
from pydantic import PrivateAttr, ValidationInfo, field_validator
from pydantic_settings import (
    BaseSettings,
    JsonConfigSettingsSource,
    SettingsConfigDict,
    YamlConfigSettingsSource,
)

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


# These helpers determine PEAT coercion from resolved annotations before Pydantic validation.
def _unwrap_optional_type(annotation: Any) -> Any:
    """
    Return the non-``None`` member of an ``Optional``/``Union`` annotation.

    Any other annotation is returned unchanged.
    """
    origin = get_origin(annotation)
    if origin is Union or origin is UnionType:
        remaining = [arg for arg in get_args(annotation) if arg is not type(None)]
        if len(remaining) == 1:
            return remaining[0]
    return annotation


def _is_container_type(annotation: Any) -> bool:
    """If a already ``Optional``-unwrapped annotation is a plain or subscripted list/dict/set."""
    return annotation in (list, dict, set) or get_origin(annotation) in (list, dict, set)


def _annotation_includes_path(annotation: Any) -> bool:
    """
    If an annotation is :class:`~pathlib.Path`, or a ``Union`` that includes it, e.g.
    ``Path | None`` or ``Path | Literal[""]``.

    This ensures path conversion still applies when sentinel values are allowed
    (see ``DEVICE_DIR``, ``LOG_DIR``, etc. in :mod:`peat.settings`).
    """
    if annotation is Path:
        return True
    origin = get_origin(annotation)
    if origin is Union or origin is UnionType:
        return Path in get_args(annotation)
    return False


def _decode_json_string(value: Any) -> Any:
    """
    Parses string values into lists, dicts, or sets if they look like JSON.

    This allows environment variables such as ``PEAT_HASH_ALGORITHMS='["md5", "sha1"]'``
    to be parsed as a real list, rather than as a single string.
    """
    if isinstance(value, str):
        try:
            return json.loads(value)
        except ValueError:
            return value
    return value


def _coerce_bool_string(value: Any) -> Any:
    """
    Accept the extended set of truthy/falsy words PEAT has always supported,
    e.g. "enable"/"disable"/"up"/"down", in addition to pydantic's own built-in
    boolean parsing. Non-string values are returned unchanged.
    """
    if isinstance(value, str):
        return str_to_bool(value)
    return value


def _coerce_path_string(value: Any) -> Any:
    """
    Expand ``~`` and resolve a path string to an absolute path.
    An empty string is passed through as-is, since it's
    a documented sentinel meaning the path/directory setting is disabled.

    Non-string values are returned unchanged.
    """
    if isinstance(value, str) and value != "":
        return Path(os.path.realpath(os.path.expanduser(value)))
    return value


class SettingsManager(BaseSettings):
    """
    Stores and manages configuration values from multiple sources.

    Typical usage is to subclass this class and configure the possible
    variables and default values as class attributes, much like :mod:`dataclasses`.

    .. warning::
       All class attributes MUST have a type! Otherwise, they will be skipped over and
       not appear in the list of defaults, since this is built directly from pydantic's
       own ``model_fields``.

    Order of precedence for configurations

    - Runtime changes (example: ``config.DEBUG = 2``), including CLI arguments
    - Environment variables (example: ``export PEAT_DEBUG=2``)
    - Configuration file (YAML or JSON)
    - Default values set in subclasses of this class (example: ``DEBUG: int = 0``)

    Each of the first three is tracked in its own internal dict (populated whenever
    :meth:`load_from_dict`/:meth:`load_from_environment`/:meth:`load_from_file` is
    called, or a value is assigned directly, e.g. ``config.DEBUG = 2``), so precedence
    stays fixed regardless of the order those sources actually get loaded in.

    Validation and typecasting of values is powered directly by
    :mod:`pydantic`/:mod:`pydantic_settings`.

    Args:
        label: The type of information being stored
        env_prefix: Prefix to use for environment variables
        init_env: Load values from environment variables during object initialization
    """

    model_config = SettingsConfigDict(
        extra="ignore",
        case_sensitive=False,
        arbitrary_types_allowed=True,
        validate_assignment=True,
    )

    env_prefix: str = ""
    """Prefix used when loading values from environment variables, e.g. ``"PEAT_"``."""

    _label: str = PrivateAttr(default="")
    _runtime_configs: dict[str, Any] = PrivateAttr(default_factory=dict)
    _env_configs: dict[str, Any] = PrivateAttr(default_factory=dict)
    _file_configs: dict[str, Any] = PrivateAttr(default_factory=dict)
    _scratch: Any = PrivateAttr(default=None)

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls,
        init_settings,
        env_settings,
        dotenv_settings,
        file_secret_settings,
    ):
        # This class handles its own env vars/files/runtime overrides,
        # so only `init_settings` is used. Other sources are ignored.
        #
        # NOTE: must be spelled "customise" (British) or this silently fails to override
        # `BaseSettings.settings_customise_sources`.
        del settings_cls, env_settings, dotenv_settings, file_secret_settings
        return (init_settings,)

    @field_validator("*", mode="wrap")
    @classmethod
    def _coerce_raw_value(cls, value: Any, handler, info: ValidationInfo) -> Any:
        """
        Preprocess raw field values before Pydantic validation.

        - :obj:`None` is always accepted as-is, bypassing further validation.
          This is a universal "no value"/"disabled" sentinel PEAT honors for every
          field regardless of its annotation.
        - :class:`bool` fields accept the extended set of truthy/falsy words
          :func:`~peat.consts.str_to_bool` supports (e.g. "yes", "enable", "up"),
          not just pydantic's own built-in boolean parsing.
        - :class:`~pathlib.Path` fields (including ``Path | Literal[""]``) get ``~``
          expanded and are resolved to an absolute path, except for an empty string.
        - :class:`list`/:class:`dict`/:class:`set` fields decode JSON-encoded strings
          (e.g. from env vars like ``PEAT_HASH_ALGORITHMS='["md5", "sha1"]'``).

        A single wildcard ("*") validator handles all of this, since
        ``SettingsManager`` subclasses are Pydantic models with fully
        resolved annotations (available via ``cls.model_fields``).
        """
        if value is None:
            return None

        field = cls.model_fields.get(info.field_name)
        if field is not None:
            annotation = field.annotation
            unwrapped = _unwrap_optional_type(annotation)
            if unwrapped is bool:
                value = _coerce_bool_string(value)
            elif _annotation_includes_path(annotation):
                value = _coerce_path_string(value)
            elif _is_container_type(unwrapped):
                value = _decode_json_string(value)

        return handler(value)

    def __init__(self, label: str, env_prefix: str, init_env: bool = True) -> None:
        super().__init__()

        self._label = label
        self._scratch = type(self).model_construct()

        self._runtime_configs["env_prefix"] = env_prefix
        self._rebuild()

        # NOTE: must run after _rebuild() so env vars are validated against (and take
        # precedence over) the new defaults.
        if init_env:
            self.load_from_environment(env_prefix=env_prefix)

    def _field_defaults(self) -> dict[str, Any]:
        """Resets all fields to a fresh default state."""
        return {
            name: field.get_default(call_default_factory=True)
            for name, field in type(self).model_fields.items()
        }

    def _rebuild(self) -> None:
        """
        Recompute every field by combining the class
        defaults, file layer, environment layer, and runtime layer.

        Bypass custom :meth:`__setattr__` (and therefore pydantic's validation),
        since values are already validated on load (see `typecast`/`_load_values`).

        Triggered by bulk updates (:meth:`load_from_dict`, :meth:`load_from_environment`,
        :meth:`load_from_file`), so a lower-precedence layer changing later
        (e.g. a config file loaded after environment variables in :meth:`__init__`)
        never overrides higher-precedence values.
        """
        merged = {
            **self._field_defaults(),
            **self._file_configs,
            **self._env_configs,
            **self._runtime_configs,
        }
        for name, value in merged.items():
            object.__setattr__(self, name, value)

    def _load_values(self, conf: dict[str, Any], load_to: str, key_prefix: str = "") -> None:
        """
        Read and set configuration values from a input dictionary.

        .. note::
           Any values that are :obj:`None` are skipped and will NOT be loaded

        Args:
            conf: Configuration to load
            load_to: Which layer the loaded configuration should be stored in. Valid
                options are: ``runtime_configs``, ``env_configs``, and ``file_configs``.
            key_prefix: Optional value to prepend to the keys being looked up.
                Example use case is for loading environment variables
                prefixed with ``PEAT_``, where ``config=dict(os.environ)``.
        """
        # Convert input config keys to upper case
        # for consistent case-insensitive key lookups.
        upper_conf = {k.upper(): v for k, v in conf.items()}  # type: dict[str, Any]

        target: dict[str, Any] = getattr(self, f"_{load_to}")

        # Check if each possible option is in the input object,
        # since the input set is likely larger than the default set.
        # Furthermore, we do NOT want to accidentally add new
        # options that are not in the defaults to the object.
        for set_key in type(self).model_fields:
            key = f"{key_prefix}{set_key}".upper()

            # Skip values that are None
            if upper_conf.get(key) is not None:
                try:
                    target[set_key] = self.typecast(set_key, upper_conf[key])
                except Exception as ex:
                    log.critical(f"Failed to load config '{key}': {ex}")

        self._rebuild()

        # !! Hack to make metadata directory configuration seamless and flexible !!
        if self._label == "configuration" and upper_conf.get("OUT_DIR"):
            self.OUT_DIR = self.OUT_DIR
        if self._label == "configuration" and upper_conf.get("RUN_DIR"):
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

        self._load_values(conf=dict(os.environ), load_to="env_configs", key_prefix=env_prefix)

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
                is not already defined on the class, or if the file doesn't
                contain a mapping/dictionary at all (e.g. an encrypted config)
        """
        log.info(f"Loading configuration from file '{file.name}'...")

        if not file.is_file():
            log.error(f"Configuration file '{file.name}' is not a file or does not exist")
            return False

        try:
            if file.suffix.lower() in [".yml", ".yaml"]:
                log.debug(f"Loading configuration from YAML file '{file.name}'")
                file_config = YamlConfigSettingsSource(type(self), yaml_file=file)()
            elif file.suffix.lower() == ".json":
                log.debug(f"Loading configuration from JSON file '{file.name}'")
                file_config = JsonConfigSettingsSource(type(self), json_file=file)()
            else:
                log.error(
                    f"Unknown extension '{file.suffix}' for configuration file "
                    f"'{file.name}', it should be '.json', '.yaml', or '.yml'. "
                    f"You might have accidentally selected the wrong file."
                )
                return False
        except json.JSONDecodeError:  # Invalid JSON syntax
            raise
        except (TypeError, ValueError) as ex:
            # Content isn't a mapping (e.g. an encrypted/non-PEAT file). Normalize to
            # AttributeError so callers (e.g. the encrypted-config fallback in
            # `peat.init.initialize_peat`) can detect and handle it, same as before.
            raise AttributeError(
                f"Configuration file '{file.name}' does not contain a valid mapping/dictionary"
            ) from ex

        if not isinstance(file_config, dict):
            raise AttributeError(
                f"Configuration file '{file.name}' does not contain a valid mapping/dictionary"
            )

        # Legacy config structure that allowed multi-app configs (other tools)
        if "PEAT" in file_config:
            file_config = file_config["PEAT"]

        self._load_values(file_config, load_to="file_configs")

        return True

    def save_to_file(self, outdir: Path, save_yaml: bool = True, save_json: bool = True) -> None:
        """
        Save the currently stored values to YAML and JSON files.

        Args:
            outdir: Directory path to save the files to
            save_yaml: set to False to disable YAML file saving
            save_json: if settings should be saved as JSON
        """
        if not save_yaml and not save_json:
            raise PeatError("Either save_yaml or save_json must be true for save_to_file")

        if save_yaml:
            yaml_file = outdir / f"peat_{self._label}.yaml"
        else:
            yaml_file = None

        if save_json:
            json_file = outdir / f"peat_{self._label}.json"
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
                    f"YAML {self._label.capitalize()} file already exists "
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
                    f"JSON {self._label.capitalize()} file already exists "
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
        result: dict[str, Any] = {}
        for key in type(self).model_fields:
            value = getattr(self, key)
            if include_none_vals or value is not None:  # Strip Nones
                result[key.upper()] = self._serialize_value(value)
        return result

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
        if item not in type(self).model_fields:
            raise KeyError(item)
        return self._serialize_value(getattr(self, item))

    @staticmethod
    def _serialize_value(value: Any) -> Any:
        # This allows nesting of SettingsManager instances as values
        if isinstance(value, SettingsManager):
            return value.export()
        else:
            return convert(value)

    def typecast(self, key: str, value: Any) -> Any:
        """
        Convert a value to the appropriate Python data type using Pydantic.

        Validates and coerces a value to match the class attribute
        annotation for ``key`` (e.g. ``bool``, ``int``, ``float``, ``str``,
        :class:`~pathlib.Path`, :class:`list`, etc.), the same way any other
        :class:`~pydantic_settings.BaseSettings` field would be, but with
        PEAT-specific behaviors:

        - :class:`bool` fields accept the extended set of truthy/falsy words
          :func:`~peat.consts.str_to_bool` supports (e.g. "yes", "enable", "up"),
          not just pydantic's own built-in boolean parsing.
        - :class:`~pathlib.Path` fields have ``~`` expanded and are resolved to an
          absolute path (e.g. "/home/" becomes ``Path("/home")``), except for an
          empty string (``""``).

        Args:
            key: Case-sensitive name of the value
                (what attribute will be changed)
            value: The raw value to typecast (e.g. a string from an
                environment variable)

        Returns:
            The typecasted value as a valid Python datatype matching the annotation

        Raises:
            KeyError: If the attribute named by ``key`` doesn't exist
            pydantic.ValidationError: If ``value`` isn't valid/convertible for the
                annotated type of ``key``
        """
        if key not in type(self).model_fields:
            raise KeyError(key)

        scratch = self._scratch
        type(self).__pydantic_validator__.validate_assignment(scratch, key, value)

        return getattr(scratch, key)

    def non_default(self, key: str) -> bool:
        """
        If an item was sourced by a non-default method (env, file, runtime).

        Args:
            key: Name of the item to check

        Returns:
            If the item has a value that *overrides* the default value. Note that
            this method will also return :class:`False` if the key isn't valid.
        """
        return (
            key in self._runtime_configs or key in self._env_configs or key in self._file_configs
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
        value = getattr(self, key)
        default = type(self).model_fields[key].get_default(call_default_factory=True)
        return value == default

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
                old = getattr(self, d)
                if not isinstance(old, Path):
                    # Keep disabled sentinels as-is instead of treating them as real paths.
                    continue
                new_path = Path(os.path.realpath(Path(new_parent, old.name)))

            setattr(self, d, new_path)

    def __setattr__(self, name: str, value: Any) -> None:
        if name not in type(self).model_fields:
            super().__setattr__(name, value)
            return

        # !! Hack to make metadata directory configuration seamless and flexible !!
        if self._label == "configuration" and name in ("OUT_DIR", "RUN_DIR"):
            self.fixup_dirs(value, name)

        # Assignments are validated and recorded as a
        # runtime override, i.e. "config.DEBUG = 1" == "config['runtime_configs']['DEBUG'] = 1".
        super().__setattr__(name, value)
        self._runtime_configs[name] = getattr(self, name)

    def __getitem__(self, key: str) -> Any:
        # Back-compat: Keep `instance["CONFIG"]` as a live view (`_ConfigView`)
        # so `mocker.patch.dict(config["CONFIG"], {...})` keeps working.
        if key == "CONFIG":
            return _ConfigView(self)
        raise KeyError(key)


class _ConfigView(MutableMapping):
    """
    Live, mutable mapping view returned by ``instance["CONFIG"]``.

    Bypasses validation on item assignment, ensuring legacy tests using
    ``unittest.mock.patch.dict(config["CONFIG"], {...})`` keep working like it
    did when ``instance["CONFIG"]`` was a raw, unvalidated :class:`~collections.ChainMap`.
    """

    def __init__(self, owner: SettingsManager) -> None:
        self._owner = owner

    def __getitem__(self, key: str) -> Any:
        if key not in type(self._owner).model_fields:
            raise KeyError(key)
        return getattr(self._owner, key)

    def __setitem__(self, key: str, value: Any) -> None:
        if key not in type(self._owner).model_fields:
            raise KeyError(key)
        object.__setattr__(self._owner, key, value)
        self._owner._runtime_configs[key] = value

    def __delitem__(self, key: str) -> None:
        # Fields always "exist", so "delete" means reset to the class default
        # this exists so `mock.patch.dict`'s reset-then-restore teardown behaves sanely (`clear`).
        field = type(self._owner).model_fields[key]
        default = field.get_default(call_default_factory=True)
        object.__setattr__(self._owner, key, default)
        self._owner._runtime_configs.pop(key, None)

    def __iter__(self) -> Iterator[str]:
        return iter(type(self._owner).model_fields)

    def __len__(self) -> int:
        return len(type(self._owner).model_fields)

    def copy(self) -> dict[str, Any]:
        return {key: self[key] for key in self}

    def clear(self) -> None:
        # NOTE: MutableMapping's default `clear()` calls `popitem()` until the mapping
        # shrinks, which never happens here.
        for key in list(self):
            del self[key]


__all__ = ["SettingsManager"]

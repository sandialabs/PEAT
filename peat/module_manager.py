import importlib
import inspect
import pkgutil
import sys
from pathlib import Path
from typing import Any
from collections.abc import Iterable

from peat import log, utils
from peat.device import DeviceData, DeviceModule, IPMethod, SerialMethod


class ModuleManager:
    """
    Manager for PEAT modules that implement functionality of a device.

    Attributes:
        modules: All currently imported device modules, keyed by module name
        module_aliases: Mapping of alias keys to device modules
        runtime_imports: Modules that were imported at runtime
        runtime_paths: Paths of modules imported at runtime,
            if they were imported from a path.
    """

    def __init__(self) -> None:
        # Initialize with the modules included with PEAT
        self.modules: dict[str, Any] = self._get_static_modules()
        self.module_aliases: dict[str, set[type[DeviceModule]]] = {}

        for module in self.modules.values():
            self._update_aliases(module)

        # Track modules added at runtime (using import_module)
        self.runtime_imports: set[str] = set()
        self.runtime_paths: set[Path] = set()  # If any were imported from files

    @property
    def names(self) -> list[str]:
        """
        Sorted list of class names of all imported modules.
        """
        return self._mods_to_names(self.modules.values())

    @property
    def classes(self) -> list[type[DeviceModule]]:
        """
        Sorted list of classes of all imported modules.
        """
        return self._sort(list(self.modules.values()))

    @property
    def aliases(self) -> list[str]:
        """
        Sorted list of all currently registered module aliases.
        """
        return sorted(self.module_aliases.keys())

    @property
    def alias_mappings(self) -> dict[str, list[str]]:
        """
        Dict of aliases and the module names they map to.
        """
        return {x: [z.__name__ for z in y] for x, y in self.module_aliases.items()}

    def filter_names(self, filter_attr: str) -> list[str]:
        """
        Return module names for which the attribute exists and is truthy.

        Example: set filter_attr to ``"ip_methods"`` to get all
        of the modules that support IP identification
        (:attr:`~peat.device.DeviceModule.ip_methods`).

        Args:
            filter_attr: Class attribute string to filter using

        Returns:
            Module names for which the attribute exists and is truthy.
        """
        return self._mods_to_names(self._filter(self.modules.values(), filter_attr))

    def import_module(self, module: Any, remove_aliases: bool = True) -> bool:
        """
        Import a PEAT module.

        Args:
            module: module to import. Can be a path (:class:`str` or
                :class:`~pathlib.Path`, class, or list of paths.
            remove_aliases: if aliases for an existing module should be removed

        Returns:
            If the import was successful
        """
        # List of module paths
        if isinstance(module, list):
            was_successful = False

            for mod in module:
                module_path = utils.check_file(mod)

                if module_path and self.import_module(mod, remove_aliases):
                    was_successful = True
                    self.runtime_paths.add(module_path)
                else:
                    log.warning(f"Import failed for module '{mod!s}'")

            return was_successful
        elif isinstance(module, (str, Path)):
            return self.import_module_path(Path(module).resolve(), remove_aliases)
        else:
            return self.import_module_cls(module, remove_aliases)

    def _extract_members(self, module_path: str) -> list[type[DeviceModule]]:
        """
        Import a Python module e.g. ``module.path``.

        Note that the module's parent folder (and if there's a package, the
        package's parent) must be in :const:`sys.path`.
        """
        try:
            pymod = importlib.import_module(module_path)
        except ModuleNotFoundError as ex:
            log.debug(f"Failed to import {module_path}: {ex}")
            return []
        else:
            members = inspect.getmembers(pymod, inspect.isclass)
            return [m for _, m in members if ModuleManager.is_valid_module(m)]

    def import_module_path(self, path: Path, remove_aliases: bool = True) -> bool:
        """
        Import all modules from a directory.

        .. note::
           The module CANNOT be "hidden" by placing the contents in an
           ``__init__.py`` file, and must reside in it's own .py file
           (e.g. ``mymodule.py``).

        Args:
            path: :class:`~pathlib.Path` to the directory containing modules to import
            remove_aliases: If aliases for an existing module should be removed

        Returns:
            If the import was successful
        """
        log.trace(f"Attempting to import module(s) from file path {path!s}")

        # Unsure if needed, leaving to be safe
        importlib.invalidate_caches()

        # Tell Python where to find the module by adding it to the path
        sys.path.append(path.resolve().parent.as_posix())

        if path.is_file():
            found = self._extract_members(path.stem)
        elif path.is_dir():
            sources = pkgutil.iter_modules([path.as_posix()], prefix=f"{path.name}.")
            found = [m for s in sources for m in self._extract_members(s.name)]
        else:
            log.error(f"Module import path does not exist: '{path!s}'")
            return False

        if found:
            log.trace3(f"Found modules: {found}")
            log.info(
                f"Attempting to import {len(found)} device modules from {path.name}"
            )
            valid = 0

            for module in found:
                if self.import_module_cls(module, remove_aliases):
                    valid += 1

            if valid:
                log.info(
                    f"Finished importing {valid} valid device modules from {path.name}"
                )
                self.runtime_paths.add(path)
                return True

        log.error(f"No valid modules found in path: {path!s}")
        return False

    def import_module_cls(
        self, module: type[DeviceModule], remove_aliases: bool = True
    ) -> bool:
        """
        Adds the module object to the registered PEAT device modules.

        Args:
            module: The module class to import
            remove_aliases: If aliases for an existing module should be removed

        Returns:
            If the import was successful
        """
        if not ModuleManager.is_valid_module(module):
            log.error(f"Invalid PEAT module: {module!s}")
            return False

        name = module.__name__.lower()

        if name in self.modules:
            log.warning(
                f"Overwriting existing module {self.modules[name].__name__} "
                f"defined in {self.modules[name].__module__} with the module "
                f"defined in {module.__module__}."
            )

            if remove_aliases:
                log.debug(f"Removing aliases for module {self.modules[name].__name__}")
                # Remove the old module from the aliases
                for alias in self.module_aliases:
                    if self.modules[name] in self.module_aliases[alias]:
                        self.module_aliases[alias].remove(self.modules[name])

        self.modules[name] = module
        self._update_aliases(module)
        self.runtime_imports.add(name)

        return True

    def get_module(self, name: str) -> type[DeviceModule] | None:
        """
        Get module by name.

        Args:
            name: Exact name of a PEAT module

        Returns:
            The PEAT module object (subclass of :class:`~peat.device.DeviceModule`),
            or :class:`None` if the module isn't imported or doesn't exist.
        """
        return self.modules.get(self._norm_name(name))

    def get_modules(
        self, name: str, filter_attr: str | None = None
    ) -> list[type[DeviceModule]]:
        """
        Get PEAT device module classes.

        Args:
            name: Module name or alias
            filter_attr: Only return modules for which this attribute is true

        Returns:
            List of module classes (subclasses of  :class:`~peat.device.DeviceModule`)
        """
        mods: list[type[DeviceModule]] = []

        if self._norm_name(name) in self.modules:
            mods.append(self.modules[self._norm_name(name)])
        elif self._norm_alias(name) in self.module_aliases:
            mods.extend(self.module_aliases[self._norm_alias(name)])

        if filter_attr:  # Only include if the attribute is Truthy
            mods = self._filter(mods, filter_attr)

        return self._sort(mods)

    def lookup_types(
        self,
        dev_types: Any | None | list[str | type[DeviceModule] | DeviceModule] = None,
        filter_attr: str | None = None,
        subclass_method: str | None = None,
        filter_values: dict | None = None,
    ) -> list[type[DeviceModule]]:
        """
        Process strings and classes into a sorted :class:`list` of module classes.

        Args:
            dev_types: DeviceModule names, aliases, classes, or instances
                to use and resolve into a list of module classes. If :obj:`None`,
                all currently imported modules searched.
            filter_attr: Only return modules for which this attribute is true
            subclass_method: Filter modules that have implemented a method
                from the base  :class:`~peat.device.DeviceModule` class, e.g.
                :meth:`~peat.device.DeviceModule.identify_ip`.
            filter_values: Values to filter modules by, with :class:`dict` keys
                being names of module class attributes and values being the values
                to compare. Comparisons must be exact matches and strings
                are therefore case-sensitive. Example: ``{"device_type": "PLC"}``

        Returns:
            List of module classes (subclasses of :class:`~peat.device.DeviceModule`)
        """
        # Default to searching all imported modules
        if dev_types is None:
            dev_types = self.classes

        mods: set[type[DeviceModule]] = set()  # set to prevent duplicates

        if not isinstance(dev_types, list):
            dev_types = [dev_types]

        for dev in dev_types:
            if isinstance(dev, str):
                if self._norm_name(dev) in self.modules:
                    mods.add(self.modules[self._norm_name(dev)])
                elif self._norm_alias(dev) in self.module_aliases:
                    mods.update(self.module_aliases[self._norm_alias(dev)])
            elif inspect.isclass(dev) and issubclass(dev, DeviceModule):
                mods.add(dev)  # Just add the class that was passed
            elif isinstance(dev, DeviceModule):
                mods.add(type(dev))  # Extract the class from the instance
            else:
                log.error(f"Invalid device type: {dev}")

        if filter_attr:  # Only include if the attribute is Truthy
            mods: list[type[DeviceModule]] = self._filter(mods, filter_attr)

        if subclass_method:  # If the method has been overridden in the module
            subl: list[type[DeviceModule]] = []

            for m in mods:
                if subclass_method in m.__dict__:
                    subl.append(m)
                else:  # Subclasses, e.g. for the SELs
                    base = m.__bases__[0]
                    if base is not DeviceModule and subclass_method in base.__dict__:
                        subl.append(m)

            mods: list[type[DeviceModule]] = subl

        if filter_values:
            val_filtered: list[type[DeviceModule]] = []

            for m in mods:
                for key, value in filter_values.items():
                    if getattr(m, key, None) == value:
                        val_filtered.append(m)
                        break

            mods: list[type[DeviceModule]] = val_filtered

        return self._sort(mods)

    def lookup_names(
        self,
        dev_types: Any | None | list[str | type[DeviceModule] | DeviceModule],
        filter_attr: str | None = None,
        subclass_method: str | None = None,
        filter_values: dict | None = None,
    ) -> list[str]:
        """
        Process strings and classes into a sorted :class:`list` of module names.

        This is a thin wrapper around
        :meth:`~peat.module_manager.ModuleManger.lookup_types`.

        Args:
            dev_types: DeviceModule names, aliases, classes, or instances
                to use and resolve into a list of module classes. If :obj:`None`,
                all currently imported modules searched.
            filter_attr: Only return modules for which this attribute is true
            subclass_method: Filter modules that have implemented a method
                from the base  :class:`~peat.device.DeviceModule` class, e.g.
                :meth:`~peat.device.DeviceModule.identify_ip`.
            filter_values: Values to filter modules by, with :class:`dict` keys
                being names of module class attributes and values being the values
                to compare. Comparisons must be exact matches and strings
                are therefore case-sensitive. Example: ``{"device_type": "PLC"}``

        Returns:
            List of module names
        """
        types = self.lookup_types(
            dev_types, filter_attr, subclass_method, filter_values
        )
        return self._mods_to_names(types)

    def alias_to_names(self, alias: str) -> list[str]:
        """
        Resolve an alias into names of modules it corresponds to.

        Args:
            alias: The alias to resolve

        Returns:
            List of names of modules that the alias resolved to,
            or an empty list if it didn't resolve to anything.
        """
        alias = self._norm_alias(alias)

        if alias not in self.module_aliases:
            log.error(f"Alias {alias} is not present")
            return []

        return self._mods_to_names(self.module_aliases[alias])

    @staticmethod
    def _sort(mods: set | list) -> list:
        """
        Improve the determinism of repeated operations (e.g. scanning).
        """
        return sorted(mods, key=lambda x: x.__name__)

    @staticmethod
    def _norm_alias(alias: str) -> str:
        """
        Normalize module alias.
        """
        return alias.strip().lower()  # Any characters are fine in aliases

    @staticmethod
    def _norm_name(name: str) -> str:
        """
        Normalize module name.
        """
        return name.strip().lower().replace("-", "").replace(" ", "")

    @staticmethod
    def _filter(
        mods: Iterable[type[DeviceModule]], filter_attr: str
    ) -> list[type[DeviceModule]]:
        """
        Filter modules to those with a 'truthy' class attribute.
        """
        return [m for m in mods if bool(getattr(m, filter_attr, False))]

    @staticmethod
    def _mods_to_names(mods: Iterable[type[DeviceModule]]) -> list[str]:
        """
        Convert modules to a sorted list of string names.
        """
        return sorted(x.__name__ for x in mods)

    @staticmethod
    def _get_static_modules() -> dict[str, Any]:
        """
        Get all modules included with PEAT in ``/peat/modules/``.
        """
        if "peat.modules" not in sys.modules:
            importlib.invalidate_caches()
            importlib.import_module("peat.modules")

        mods = inspect.getmembers(sys.modules["peat.modules"], inspect.isclass)

        return {n.lower(): m for n, m in mods if ModuleManager.is_valid_module(m)}

    def _update_aliases(self, module: type[DeviceModule]) -> None:
        """
        Make the module resolvable by any aliases that apply to it.

        The default aliases are the device's vendor and ``"all"``.
        """
        # Pull aliases from device class attributes and various other things
        # "all" makes the CLI magically work for scan/pull
        sources = [
            "all",
            module.device_type,
            module.vendor_id,
            module.vendor_name,
            module.brand,
            module.model,
            *module.module_aliases,  # Add all the aliases defined in the module
        ]

        # Normalize, remove empty values, and deduplicate using Set comprehension
        normalized_aliases: set[str] = {self._norm_alias(a) for a in sources if a}
        for alias in normalized_aliases:
            if alias not in self.module_aliases:
                self.module_aliases[alias] = set()  # type: set[Type[DeviceModule]]
            self.module_aliases[alias].add(module)

    @classmethod
    def is_valid_module(cls, module: Any) -> bool:
        """
        Checks if a Python object is a PEAT device module.
        """
        if module in [DeviceModule, DeviceData, IPMethod, SerialMethod]:
            # This hack is used to filter the PEAT core classes
            # out of a few areas, so don't log when it fails.
            return False
        elif not inspect.isclass(module):
            reason = "module object is not a Python class"
        elif not issubclass(module, DeviceModule):
            reason = "module is not a subclass of peat.DeviceModule"
        else:
            return True

        log.debug(f"Module validation failed for '{module}': {reason}")
        return False


module_api = ModuleManager()


__all__ = ["ModuleManager", "module_api"]

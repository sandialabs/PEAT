************
Contributing
************

This page is for PEAT team members as well as anyone contributing to PEAT's codebase or collaborating with the PEAT team.

.. note::
   The source code for documented classes and functions is available by clicking the ``source`` button on the top right of the documentation for the class or function.


PEAT developer guide
====================
For the core PEAT development team. May also be of use to others trying to understand the code.

.. seealso::

   :doc:`developer_reference`
      Details on development of device modules (aka "PEAT modules"), and the design decisions related to them

   :ref:`test-docs`
      Setting up a testing environment, running the tests, and writing new tests

   :doc:`data_model`
      Data model documentation


Getting started and development basics
--------------------------------------

Editors
^^^^^^^
The recommended editor for hacking on PEAT is `Visual Studio Code (VSCode) <https://code.visualstudio.com/>`__. On Ubuntu, it can be easily installed using `snap <https://snapcraft.io/code>`__:

.. code-block:: bash

   sudo snap install code --classic

VSCode's Remote Development extensions make life easier if you prefer the interface of an IDE when working on a remote server or device that's behind a remote server (e.g. a :term:`SCEPTRE` environment). This feature enables use of the :term:`GUI` and most of VSCode's numerous extensions while working on code on a remote server or in `Windows Subsystem for Linux (WSL) <https://docs.microsoft.com/en-us/windows/wsl/>`__. See the VSCode documentation for details: `VS Code Remote Development <https://code.visualstudio.com/docs/remote/remote-overview>`__ and `Remote Development tutorials <https://code.visualstudio.com/docs/remote/remote-tutorials>`__

Setting up a development environment
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. note::
   These steps are the same for Windows, MacOS, and Linux.

1. `Install PDM <https://pdm-project.org/en/stable/>`__
2. Clone PEAT repo

   .. code-block:: bash

      git clone https://github.com/sandialabs/peat.git
      cd peat

3. Create environment and install dependencies

   .. code-block:: bash

      pdm install -d

4. Ensure the install worked

   .. code-block:: bash

      pdm run peat --version
      pdm run peat --help


Helpful PDM commands
^^^^^^^^^^^^^^^^^^^^
.. code-block:: bash

   # Run PEAT. If you make changes to the code, these will be picked up automatically.
   pdm run peat

   # List available scripts. "scripts" are helpers to do things like format code, build executables, etc
   pdm run -l

   # Run lint checks
   pdm run lint

   # Format code
   pdm run format

   # Run unit tests
   pdm run test

   # Run unit tests, including slow tests
   # This takes significantly longer, but is more comprehensive
   pdm run test-full

   # Run tests for a specific version of Python
   # For example, Python 3.12
   pdm use -f 3.12
   pdm install -d
   pdm run test

   # Build Windows executable with PyInstaller
   pdm run build-exe

   # Build Linux executable to be fully portable.
   # This runs staticx to include system libraries.
   # This WILL NOT work on Windows, and probably won't work with Mac.
   # make sure you have the following dependencies (linux) if you run into build issues
   sudo apt install -qyf python3-dev patchelf binutils scons libpq-dev libpq5 graphviz
   pdm run build-linux-exe

   # Sneakypeat
   pdm run build-sneakypeat
   pdm run build-linux-sneakypeat

   # Build Python packages
   pdm build
   ls -lAht ./dist/
   # View files in the package
   pdm run wheel-files

   # Build docker
   pdm run build-docker


Logging and printing
--------------------
The `Loguru <https://loguru.readthedocs.io/en/stable/>`__ library is used module is used for *all* logging messages (in other words, messages intended to be read by by a human user). Log messages are configured to write to stderr (not stdout), a log file, and Elasticsearch (if configured). The writing to stderr is intentional, enabling users to easily filter output from commands from the logging messages.

The use of :func:`print` and :func:`~pprint.pprint` is forbidden for user messages, and should only be used for printing final results (e.g. scan result summary for a scan). In these cases, add ``# noqa: T001`` to exclude it from linting (and ``# noqa: T002`` for :func:`~pprint.pprint`).

Logging levels
^^^^^^^^^^^^^^
- ``CRITICAL``: Something went really wrong. This is usually indiciative of a bug in PEAT or a unusual system error. If something is logged at CRITICAL, it usually results in premature termination of a run of PEAT.
- ``ERROR``: bad user input (e.g. a input file doesn't exist), a high-level action failed (e.g. a pull from a device was unsuccessful when it was supposed to succeed), general system error. Issues logged at error often result in a failed PEAT run, but may not warrant terminating the run early. For example, if performing a pull from five devices, if one of the devices fail, the other four may succeed, and PEAT will proceed with finishing the pull from those devices.
- ``WARNING``: anything the user should be aware of, but may not have an impact on the run or necessarily be a failure. For example, if PEAT is retrieving ten different data points, and one of the best-effort data points is unsuccessful (e.g. "battery statistics"), that may be a WARNING instead of an ERROR.
- ``INFO``: General messages about how a run is progressing. These should provide enough information for the user to be aware of what is happening, without being overly verbose. If additional information is desirable, log at DEBUG level instead, then the user can enable it with the ``-v`` argument.
- ``DEBUG``: verbose messages, with additional information useful for troubleshooting issues or gaining a deeper understanding of the actions PEAT is taking. These are always saved to the log file, but will only be printed to the terminal if ``-v`` (``--verbose``) argument is set.
- ``TRACE``, ``TRACE2``, ``TRACE3``, ``TRACE4``: four levels of very verbose logging for debugging and troubleshooting purposes. These are enabled by the ``-V`` argument, e.g. ``-VVV`` will set debugging level to 3 and enable TRACE, TRACE2, and TRACE3 messages to be logged. If DEBUG level is 0, messages logged at TRACE levels are not saved anywhere.

Logging usage
^^^^^^^^^^^^^
Using logging is fairly straightforward:

.. code-block:: python
   :caption: Logging examples

   from peat import log

   log.info("This is a Informational message")
   log.trace("DEBUG level 1 message")
   log.trace4("This will only be logged if config.DEBUG == 4, e.g. with -vVVVV arguments")

   # DeviceModule classes have a log attribute, that will add the classes's name as metadata
   # This example comes from m340.py
   @classmethod
   def _verify_snmp(cls, dev: DeviceData) -> bool:
       ...
       cls.log.trace(f"Verifying {dev.ip}:{port} via SNMP (timeout: {timeout})")

   # To add information about the target of an action, such as IP address, serial port,
   # hostname, etc., bind a new logger with "target" set.
   # This example comes from ab_push.py
   _log = log.bind(target=ip)
   _log.info(
       f"Pushing firmware to {ip}:{port} (size: {utils.fmt_size(len(firmware))})"
   )

Advanced logging
^^^^^^^^^^^^^^^^
Logging format can be customized at runtime using `Loguru's environment variables <https://loguru.readthedocs.io/en/stable/api/logger.html#env>`__. The main reason you'd need to use this is if there are color issues with certain terminals. Instead of disabling colors entirely with ``--no-color``, you can customize the problematic color with ``LOGURU_<LEVEL>_COLOR``, e.g. ``LOGURU_DEBUG_COLOR`` to set the color for ``DEBUG``-level messages.


Guidelines and policies
-----------------------

Code style
^^^^^^^^^^
- `PEP8 <https://www.python.org/dev/peps/pep-0008/>`__ should be adhered to, with the exception of line length can go up to 88 characters, and certain lines can be excluded with ``# noqa: E501``.
- Run ``pdm run format`` to format your code before pushing. There's no longer a need to worry about formatting, it's all handled for you. Under the hood, `black <https://github.com/psf/black>`__ is used for formatting and `isort <https://pycqa.github.io/isort/index.html>`__ is used for import sorting.
- Docstrings should follow `PEP-257 <https://www.python.org/dev/peps/pep-0257/>`__.
- Argument and Returns in function docstrings should follow the `Googleformat <http://google.github.io/styleguide/pyguide.html>`_ (`Examples <https://www.sphinx-doc.org/en/1.8/usage/extensions/example_google.html>`_).
- ``TODO`` comments are permitted. However, if the ``TODO`` is significant you should discuss it with the team or open a issue on GitHub.

Git
^^^
- All changes to PEAT should be worked on in a Git branch. Changes directly to the main branch (``develop``) will be rejected.
- All branches are merged using a GitHub Pull Request (PR).
- When work is nearing completion, create a Pull Request, and prefix the title with ``"Draft: "``. This increases visibility in advance of the reviewing phase, and enables discussion.
- All Pull Requests should have a code review by another PEAT developer. Reviewers should check that the change is reasonable and complete, check for potential issues or edge cases, and look for anything that jumps out at them or seems "fishy".
- Requirements before *merging* an PR:

  #. Add your name and any other contributors to the feature to ``AUTHORS``
  #. Add and/or update the list of authors in the relevant module-level docstring(s) for your changing, including email addresses. This makes it clear who to contact about a particular portion of the codebase.
  #. There is a minimal set of tests for the change (if applicable)
  #. GitHub Actions CI pipeline passes
  #. Code has been been reviewed by a PEAT maintainer (if committer is not a PEAT maintainer)

Versioning
^^^^^^^^^^
Versions are manually tagged with a calendar version, e.g. ``2024.5.6`` for a tag on May 6th, 2024. The version used for the package internally will be a automatically generated version, e.g. ``2024.5.6.dev801+gf79832d6.d20240506``.

Type annotations
^^^^^^^^^^^^^^^^
Python type annotations are used for all methods and functions, and when it makes sense for variables (e.g. if there's ambiguity about the type of a variable). While at first glance it seems overly verbose and "unpythonic" (after all, one of Python's core strengths is it's dynamic "duck" typing), there are a number of reasons we use them:

- They document expected types, which has been especially useful for the deep device-level code, which is difficult to untangle if you aren't the original developer (the ControlLogix code is the nastiest example of this).
- They are used as part of the documentation generation process to add the types (instead of putting the types in the docstrings, which are often not updated).
- The `mypy <https://github.com/python/mypy>`__ static analyzer is used to catch typing errors.
- Linters (e.g. Pylance in VSCode) can help you avoid silly mistakes, like providing arguments in the wrong order.

.. seealso::

   The :mod:`typing` module

   `PEP 484 - Type Hints <https://www.python.org/dev/peps/pep-0484>`__

   `PEP 526 - Syntax for Variable Annotations <https://www.python.org/dev/peps/pep-0526>`__

   `The mypy homepage <http://mypy-lang.org>`__

Exception handling
^^^^^^^^^^^^^^^^^^
The methodology for exception handling in PEAT differs somewhat from Python's guidance and common practices. It can be summed up as this: "get as much data as possible and fail safely". If a function or function to collect some data fails, then log that it failed and continue trying other methods. This can be implemented by wrapping code that may fail in a ``try/except`` statement and handle the generic ``Exception`` class. If the failure is critical to the continued operation of the collection or has the potential to affect the device's operation, then log the issue in detail and re-raise the exception so that device's run is terminated. This methodology is why ``try: ...; except Exception: ...`` is used in various places.

Other conventions
^^^^^^^^^^^^^^^^^
- Timestamps are assumed to be in the :term:`UTC` timezone unless there is a specific reason for them not to be, e.g value recovered from device with a unknown timezone.
- :py:class:`~datetime.datetime` objects *should be* timezone-aware
- UTF-8 encoding is used for all files (unless required and documented otherwise)
- All hashes *should be* SHA 256
- Strings

  - Strings should be either :class:`str` or :class:`bytes`
  - Raw data should be :class:`bytes` type. Use of :class:`bytearray` or other related types should be avoided, *except* for intermediate representations (e.g. building a binary file chunk by chunk).
  - Convert from :class:`str` to :class:`bytes` using :meth:`str.encode`, and vice-versa using :class:`bytes.decode`
  - :class:`str` objects should be ``"utf-8"``
  - `Refer to this guide <https://stackoverflow.com/a/36149089>`__ for converting escaped hex to hex, and vice-versa

Project structure
-----------------
- ``.dockerignore``   Files to ignore when building the Docker containers (`Syntax reference <https://docs.docker.com/engine/reference/builder/#/dockerignore-file>`__)
- ``.editorconfig``   Consistent configuration baseline used by many editors and IDEs (`Reference <https://editorconfig.org/>`__)
- ``.gitattributes``  Controls how Git treats file types and line endings (for example, it ensures Bash scripts always have ``LF`` line endings, even when the repository is cloned on Windows)
- ``.gitignore``      Anything that shouldn't be pushed to GitHub, like temp files and virtual environments
- ``AUTHORS``         Everyone who has contributed to PEAT
- ``Dockerfile``      Used to build a Docker image for the PEAT CLI
- ``LICENSE``         Licensing
- ``pdm.lock``        Used by PDM to pin the versions of dependencies based on what's defined in ``pyproject.toml``, and ensure their SHA256 hashes match when installing.
- ``pyproject.toml``  Configuration for the project, including Python packaging metadata, configurations for tools such as ``pytest``, ``ruff``, ``black``, ``isort``, and ``mypy``, and dependencies. It also controls how the PEAT python package is built and installed. This is what ``pip`` uses when you run ``pip install .``.
- ``README.md``       Basic documentation that shows up on GitHub project homepage

distribution
^^^^^^^^^^^^
Anything related to installing, packaging, or distributing PEAT. See the :ref:`distribution` for further details.

- ``build-docker.sh``  Builds the :term:`Container` image.
- ``build-linux-package.sh``  Creates a portable PEAT executable on Linux. This is the preferred method of distributing and installing PEAT on Linux.
- ``file_version_info.txt``   Used by `PyInstaller <https://pyinstaller.readthedocs.io/en/stable/usage.html#windows-specific-options>`__ to add `metadata to the final Windows executable <https://stackoverflow.com/a/14626175>`__. DO NOT MODIFY unless you know what you're doing.
- ``linux-install-script.sh``  Installs the PEAT executable in ``/usr/local/bin``, the man page in ``/usr/local/share/man/man1/``, and updates the ``mandb``. Intended to be distributed with the Linux executable and the man page (``peat.1``).
- ``peat.spec``  `PyInstaller spec <https://pyinstaller.readthedocs.io/en/stable/spec-files.html>`__ for building portable PEAT executables (for both Linux and Windows)
- ``tbird.ico``  Icon file used for the Windows executable

examples
^^^^^^^^
Example output from PEAT runs, examples of device input files and parsed outputs, example PEAT module, etc.

peat
^^^^
Python source code for the ``peat`` module.

- ``api/*``  High-level "wrapper" APIs, e.g. :mod:`~peat.api.pull_api`
- ``data/*``  Data model implementation
- ``modules/*``  Device modules included with PEAT
- ``parsing/*``  General parsing-related code, including Structured Text TC6 XML logic parsing functions
- ``protocols/*`` General network-related code, including protocol implementations, typecode definitions, wrapper classes (e.g. :class:`~peat.protocols.http.HTTP`) and utility functions
- ``__init__.py``  Top-level imports for the ``peat`` Python package (Further reading: `What is init.py for? <https://stackoverflow.com/a/4116384/2214380>`__)
- ``__main__.py``  Entrypoint for the Command Line Interface (CLI)
- ``cli_args.py``  Command line interface argument definitions, help messages, usage examples, and parsing functions
- ``cli_main.py``  Core logic for the CLI (this gets called by ``__main__.py``)
- ``consts.py``  Constants (global variables) such as system information, as well as functions that need to be "import-safe" without cross-dependencies on other PEAT modules
- ``device.py``  Defines the :class:`~peat.device.DeviceModule` base class used (subclassed) by all PEAT device modules (everything in ``peat/modules/``)
- ``elastic.py``  Elasticsearch interface implementation, including :class:`~peat.elastic.Elastic`
- ``es_mappings.py``  Elasticsearch type mappings
- ``init.py``  Initialization functions, including loading of configurations and Elasticsearch initialization
- ``log_utils.py``  Logging-related functions
- ``module_manager.py``  The special sauce behind PEAT's dynamic device module API (``peat.module_api``). The :class:`~peat.module_manager.ModuleManager` manages all imported PEAT :class:`~peat.device.DeviceModule` modules and provides methods to lookup a module or import a new module.
- ``settings.py``  Configuration and state definitions, including :data:`~peat.settings.config` and :data:`~peat.settings.state`
- ``settings_manager.py``  The :class:`~peat.settings_manager.SettingsManager` class
- ``utils.py``  Various utility functions that are used throughout PEAT

tests
^^^^^
Anything related to testing, including unit tests and test infrastructure (such as Docker containers). Refer to the :ref:`test-docs` for further details on testing.

- ``modules/``  Unit tests for PEAT :class:`~peat.device.DeviceModule` modules (``peat/modules/``)
- ``protocols/``  Unit tests for protocols (``peat/protocols/``)
- ``conftest.py``  Configuration for ``pytest``

Kibana Dashboards and Visualizations
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
**Principles**

- Be deliberate, know your user and the questions they are asking
- Keep it simple, don't force users to scroll and remember
- Make more linked dashboards if needed
- Put important information in important places
- Use a grid and favor charts that are a bit wider than tall

**Recommended reading**

- `Structure and Layout in System Dashboard Design <http://onemogin.com/observability/dashboards/practitioners-guide-to-system-dashboard-design.html>`__
- `Presentation and Accessibility in System Dashboard Design <http://onemogin.com/observability/dashboards/practitioners-guide-to-system-dashboard-design-p2.html>`__


.. _config-state-deepdive:

Configuration and state deep dive
---------------------------------
Before proceeding, make sure you're familiar with the regular methods of configuring PEAT, such as environment variables, configuration file, and CLI arguments. Refer to :doc:`operate` for details.

PEAT uses global singletons ("`registries <https://martinfowler.com/eaaCatalog/registry.html>`__") to manage it's configuration and state. These singletons are :data:`~peat.settings.config`, which is an instance of :class:`~peat.settings.Configuration`, and :data:`~peat.settings.state`, which is an instance of :class:`~peat.settings.State`, and both are subclasses (inherit from) :class:`~peat.settings_manager.SettingsManager`. Refer to the :ref:`settings-api` section for details on the APIs of these classes.

These singletons can be safely imported and used anywhere in PEAT or in third party code. Examples:

.. code-block:: python

   from peat import config
   from peat import state

Changes are applied and available immediately, regardless of when imports occur, as you may be used to from other systems or methods of configuration. This provides flexibility and safety to read and write values from anywhere in the code and at any phase of execution.

.. code-block:: python

   >>> from peat import config
   >>> config.DEBUG
   0
   >>> config.DEBUG = 2
   >>> config.DEBUG
   2

Modifications to the configuration or state can be performed via runtime changes, environment variables, or a JSON config file. These changes are always saved in the object in a :class:`~collections.ChainMap` stored in the special ``"CONFIG"`` key on the object. The value that actually gets used when accessed at runtime depends on the *order of precedence*, which is documented in the :ref:`settings-api` section.

The data types of values are automatically checked and converted when loaded from environment variables or JSON files. The data type is defined via Python type annotation syntax on the class variable. The checking and conversion is implemented in :meth:`~peat.settings_manager.SettingsManager.typecast`. Some example type conversions:

- Variables with a type of :class:`~pathlib.Path` accept filesystem path strings in most input methods (e.g. config file), and gets massaged to a :class:`~pathlib.Path` object internally.
- :class:`bool` variables accept various forms of truth, including "1", "0", "yes", "no", "false", and others.

.. warning::
   Runtime changes directly to attributes (e.g. ``config.DEBUG = 2``) are NOT type checked or automatically converted. Ensure you are using the proper type!

Configuration changes from command line arguments
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
**Command line arguments with a name matching the value's name are automatically loaded into the configuration** and assigned as **runtime changes**. For example, a command line argument with the name ``--print-results`` will modify the value for :attr:`config.PRINT_RESULTS <peat.settings.Configuration.PRINT_RESULTS>`. Note that only the configuration is automatically modified by command line arguments, the state cannot be changed via the CLI by default. This automatic loading occurs in :func:`peat.init.initialize_peat`, with the `conf` argument containing a dictionary of the CLI arguments passed from :func:`peat.cli_main.run_peat`

Adding a attribute to the configuration or state
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
To add a new value to the state or configuration, simply add an attribute to the appropriate class (:class:`~peat.settings.Configuration` or :class:`~peat.settings.State`). The attribute MUST include a type annotation and a default value, as well as a comment describing the attribute. For example:

.. code-block:: python

   class Configuration(SettingsManager):
       ...
       # Modifies the coolness of a run
       COOLNESS_FACTOR: int = 0
       ...

The variable can now be set via environment variables or JSON configuration files, for example:

.. code-block:: bash

   # Traditional export
   export PEAT_COOLNESS_FACTOR=9001
   peat parse examples/

   # Modify only for this command execution
   PEAT_COOLNESS_FACTOR=9001 peat parse examples/

**The corresponding command line argument is not added automatically**, and must be manually added to :func:`~peat.cli_args.build_argument_parser` in :mod:`peat.cli_args`. If the argument should be available to all commands, add it to the ``'general arguments'`` ``group`` in the ``subparsers`` ``for`` loop, e.g. ``group.add_argument(...)``. Otherwise, add it to the appropriate command parser, e.g. ``scan_parser.add_argument(...)`` or to a ``for`` loop for multiple command parsers (e.g. for ``scan`` and ``pull``).

.. code-block:: python

   group.add_argument(
       '-o', '--out-dir', type=str, metavar='PATH', default=None,
       help='Output directory for any files PEAT creates. '
            'Defaults to "peat_results" in the current directory.'
   )

Refer to the Usage documentation :ref:`output-structure` section for details on PEAT's file output and examples of the structure.

Landmines
---------
Some areas of the code are more sensitive or complex than others. If you are confused or unsure about a change, talk to the other developers (git history can help determine who to talk to). I'll try to document here anything that is sensitive or is using advanced Python features that may not be obvious to someone not immersed in the language.

Areas of note:

- ``peat/__init__.py``: Special setup for Loguru, including custom logging levels, handler for Elasticsearch, and customizing log levels for third-party loggers (e.g. Scapy). The order of imports matters in this file!
- ``peat/device.py`` : The :class:`~peat.device.DeviceModule` base class overrides some "magic methods" (``__<method>__``) and provides methods that are overridden by subclasses.
- ``peat/settings.py`` : :mod:`~peat.settings` **absolutely cannot** import or rely on other ``peat`` Python modules, since it is imported by practically everything else (``state`` and ``config``). There is a heavy amount of advanced Python hackery happening here, some of which is explained with comments. The only changes most developers will need to make in here are adding/changing configuration or state variables.
- ``peat/consts.py`` : must be mostly static at runtime and **absolutely cannot** import other Python modules from ``peat``, since it contains values that are imported and used across the codebase. Use this for anything that is determined at runtime or never changes. Several examples are string formats and platform information (e.g. the OS PEAT is running on).
- ``peat/init.py`` : :func:`~peat.init.initialize_peat` is a workaround for the fact we support multiple independent ways of using PEAT (the CLI, the HTTP server, and as a Python package).
- Multiple classes use the Python ``@property`` feature, read the official documentation for details: `Python docs - Property <docs.python.org/3/library/functions.html#property>`__
- Multiple classes implement Python built-in methods, commonly known as "magic" or "dunder" methods. These include ``__str__``, ``__repr__``, and others. Check the Python documentation for more details and a full listing: `Python docs - Data Model <https://docs.python.org/3/reference/datamodel.html>`__
- ``peat/data/*`` : the data models use Pydantic to provide a nice interface for working with data from devices. They process, store and manage device data and provide the structure/schema and associated documentation for said data. **Changes here have the potential to affect every module in PEAT**. Therefore, as with anything critical, think twice, write tests, and ask questions.

Class hierarchy
---------------
.. automod-diagram:: peat

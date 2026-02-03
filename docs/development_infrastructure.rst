**************************
Development Infrastructure
**************************

.. _distribution:

Packaging and distribution of PEAT
==================================

Linux
-----

Portable Linux Executable
^^^^^^^^^^^^^^^^^^^^^^^^^
`PyInstaller <https://pyinstaller.readthedocs.io/en/stable/index.html>`__ is used to create a portable executable version of PEAT. The package is portable across distribution versions, e.g. a package built on Ubuntu 18.10 will work on Ubuntu 14.04. This is accomplished by using `StaticX <https://github.com/JonathonReinhart/staticx/>`__ to include the system libraries in the package. NOTE: this does NOT work with Pythons installed using `pyenv <https://github.com/pyenv/pyenv/>`__ or compiled manually. It must be a system Python, e.g. included in distro or installed with `apt <https://wiki.debian.org/AptCLI>`__ or `yum <https://man7.org/linux/man-pages/man8/yum.8.html>`__.

Building the executable
~~~~~~~~~~~~~~~~~~~~~~~
.. code-block:: bash

   # Ensure PDM has initialized venv
   pdm install -d

   # Some tools may be needed
   sudo apt install -qyf python3-dev patchelf binutils scons libpq-dev libpq5

   # Build
   pdm run build-linux-exe

   # Test
   ./dist/peat --version
   ./dist/peat --help

Windows
-------

Windows Portable Executable using PyInstaller
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
The Windows version of PEAT that's distributed to end users is a bundled executable file created by `PyInstaller <https://pyinstaller.readthedocs.io/en/stable/index.html>`__. PyInstaller uses a number of files, depending on the options used:

- ``peat.spec``: Describes the install configuration for PyInstaller
- ``file_version_info.txt``: File metadata for the resulting ``.exe``
- ``tbird.ico``: Icon for the resulting ``.exe``

Building the Windows EXE on a Windows system
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
#. Install a version of Python supported by PEAT: `python.org <https://www.python.org/downloads/windows/>`__
#. Install `Microsoft Visual C++ 2015 Redistributable Update 3 RC <https://www.microsoft.com/en-us/download/details.aspx?id=52685>`_ (which provides ``VCRuntime140.dll``)
#. Open PowerShell and run the build script:

   .. code-block:: powershell

      pdm install -d
      pdm run build-exe
      .\dist\peat.exe --version

If you wish to build manually step by step, open the build script in a text editor and run the commands individually.

Setting up a Windows development environment
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
How to setup a local Python environment if you will be developing PEAT and need to edit and test the code.

#. Install Python 3.10 or newer (download from `python.org <https://www.python.org/>`__). During install, ensure the option "Add Python to environment variables" or "Add Python to system PATH" is checked (you may need to click "Next" to see this option).
#. Install `Npcap <https://nmap.org/npcap/>`_ 0.99 or newer (Skip this step if Wireshark, Nmap, or Winpcap is already installed)
#. Open a PowerShell or Command Prompt window
#. Run ``py -3 -V``, and verify it is 3.10 or newer.
#. Install `PDM <https://pdm-project.org/en/stable/>`__
#. Run the following commands to setup a development environment:

.. code-block:: ps1con

   # Clone the PEAT Git repository
   git clone https://github.com/sandialabs/peat.git
   cd peat

   # Install dependencies and create environment
   pdm install -d

Docker
------
NOTE: the GitHub Actions CI pipeline automatically builds and pushes containers if all the tests pass in the ``main`` branch. Build locally to test changes, but you cannot push to GitHub.

.. code-block:: bash

   bash distribution/build-docker.sh
   docker run -it ghcr.io/sandialabs/peat --help


.. _test-docs:

Test documentation
==================
Regressions are a menance, and especially so for PEAT due to it's complexity. Our goal is to cover the major features with a minimal amount of effort to ensure future changes don't cause major breakages (e.g. a change in the parsing logic breaks scanning).

There are three forms of testing:

- Quality: linting and code quality checks
- Unit tests: uses ``pytest`` to test the CLI interface and individual functions and methods in the code. There are also unit tests that only run against live devices in CI, these are marked with ``@pytest.mark.gitlab_ci_only``.
- Live tests: run the PEAT executable against live devices and Elasticsearch server in the GitLab Continuous Integration (CI) pipeline. This validates the "end to end" user experience. However, it won't catch logic failures (e.g. bad output or missing files) and failures are more time consuming to debug than with unit tests. **NOTE: these tests are not run on GitHub**.

Running the tests
-----------------
NOTE: you must be in the root directory of the repository ("PEAT").

.. code-block:: bash

   # Ensure environment is up to date
   pdm install -d

   # Linting
   pdm run lint

   # Run just pytest. This is fast, but not comprehensive.
   pdm run pytest

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

   # pytest can be configured via arguments at runtime
   pdm run pytest -h  # Available pytest arguments
   pdm run pytest --durations=10

   # Run specific tests
   pdm run pytest -k "test_some_code"

   # Increase output (-vv shows detailed diff on failures)
   pdm run pytest -v
   pdm run pytest -vv

   # Stop after failures
   pdm run pytest -x           # stop after first failure
   pdm run pytest --maxfail=2  # stop after two failures
   pdm run pytest --lf         # rerun only the tests that failed at the last run
   pdm run pytest --ff         # run all tests, but run the last failures first

   # Run any test marked as "slow" with the decorator "@pytest.mark.slow"
   # This includes the CLI, SEL parsing, and a few other tests
   pdm run pytest -v --run-slow
   pdm run pytest -k "test_some_code" -vv --run-slow


Testing tools
-------------
- `pytest <https://docs.pytest.org/en/latest/>`__ is used for composing and running the Python unit tests. It is an robust and powerful framework that makes writing Python tests easier and at times enjoyable. There are a lot of things ``pytest`` makes easy that are difficult, onerous, or even impossible to accomplish with :mod:`unittest`.
- `pyenv <https://github.com/pyenv/pyenv>`__ is used to download, compile, and manage multiple versions of Python on the same system without affecting the system Pythons. Installation is easy, just follow the guide on the `pyenv-installer page <https://github.com/pyenv/pyenv-installer>`__.

Organization of tests
---------------------

.. code-block::

   tests/
       conftest.py -> Configuration of pytest
       test_module_manager.py -> Unit tests for peat/module_manager.py
       test_utils.py -> Unit tests for peat/utils.py
       api/
          data_files/
          ...
       data_files/  -> Files used by tests at the current directory level (e.g. test_utils.py)
       modules/
           <vendor>/
               data_files/
               test_<device>.py
               ...
           ...
       protocols/
           data_files/
           test_<protocol>.py
           ...

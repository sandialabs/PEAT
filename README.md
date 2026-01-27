# Process Extraction and Analysis Tool (PEAT)

[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/11835/badge)](https://www.bestpractices.dev/projects/11835)
[![pdm-managed](https://img.shields.io/endpoint?url=https%3A%2F%2Fcdn.jsdelivr.net%2Fgh%2Fpdm-project%2F.github%2Fbadge.json)](https://pdm-project.org)

PEAT is a Operational Technology (OT) device interrogator, including pulling, parsing and uploading artifacts (configuration, firmware, process logic, etc.) and network discovery ("scanning"). It runs on most systems, including Linux, Windows, and as a Docker container.

Documentation about installation, usage, development, and other information is in the PEAT documentation.

## Basic install

Notes

- These steps make a lot of assumptions, and are meant if you find/clone/whatever the repo without context or SRN access. Refer to the documentation for complete information about installation and setup.
- If you're on Windows, make sure you're using PowerShell.
- Edits to the code (`.py` files) don't necessitate a reinstall. You only need to install on first setup, or if the dependencies change (these are defined in `pyproject.toml`).
- [PDM](https://pdm-project.org) is used for tooling and dependency management
- Tests are run using `pytest`

### Install PDM

Full instructions: https://pdm-project.org/en/stable/

#### Linux

Installer method:

```bash
curl -sSL https://pdm-project.org/install-pdm.py | python3 -
```

[pipx](https://pipx.pypa.io/stable/) method:

```bash
pipx install pdm
```

#### Windows

Installer method:

```powershell
[System.Text.Encoding]::UTF8.GetString((Invoke-WebRequest -Uri https://pdm-project.org/install-pdm.py).Content) | python -
```

[Scoop](https://scoop.sh/) method:

```shell
scoop bucket add frostming https://github.com/frostming/scoop-frostming.git
scoop install pdm
```

#### Mac

Installer method:

```bash
curl -sSL https://pdm-project.org/install-pdm.py | python3 -
```

Homebrew method:

```bash
brew install pdm
```

### Setup development environment

```bash
# Ensure PDM is installed
# Clone repo, if it hasn't been already
git clone https://github.com/sandialabs/peat.git

# Change directory
cd peat

# Disable update checks (faster and reduces chances for proxy-related errors)
pdm config check_update false

# Install dependencies and create virtual environment (in "./.venv/")
pdm install -d

# The virtual environment ("venv") contains PEAT's dependencies and development
# tools, and is automatically used and managed by PDM.
# There is NO need to "activate" the venv, use "pdm run" for any commands.

# Ensure the environment is working
pdm run peat --version
pdm run peat --help
pdm run python --version
pdm run pip --version

# List available scripts
pdm run -l
```

### Basic development commands

```shell
# List available scripts
pdm run -l

# Run lint checks
pdm run lint

# Automatically format code files
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
```

## Building distributions

```bash
# make sure you have the following dependencies (linux) if you run into build issues
sudo apt install -qyf python3-dev patchelf binutils scons libpq-dev libpq5 graphviz

# Build Windows executable with PyInstaller
pdm run build-exe

# Build Linux executable
# This runs staticx to include system libraries and be fully portable.
# This WILL NOT work on Windows, and probably won't work with Mac.
# Also, you may need to install some tools:
# sudo apt install -qyf python3-dev patchelf binutils scons libpq-dev libpq5
pdm run build-linux-exe

# Sneakypeat (Windows and Linux)
pdm run build-sneakypeat
pdm run build-linux-sneakypeat

# Build Python packages
pdm build
ls -lAht ./dist/
# View files in the package
pdm run wheel-files

# Build docker
pdm run build-docker

# Update dependencies, but don't bump as many versions (pdm.lock)
pdm lock --update-reuse -d
pdm sync -d

# Update dependencies and versions
pdm lock -d
pdm sync -d
```

## License

Copyright 2026 National Technology & Engineering Solutions of Sandia, LLC (NTESS). Under the terms of Contract DE-NA0003525 with NTESS, the U.S. Government retains certain rights in this software.

This software is licensed under a GPLv3 license. Please see [LICENSE](LICENSE) and [COPYRIGHT.md](COPYRIGHT.md) for more information.

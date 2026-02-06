# Process Extraction and Analysis Tool (PEAT)

[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/11835/badge)](https://www.bestpractices.dev/projects/11835)
[![GitHub Actions Pipeline Status](https://github.com/sandialabs/PEAT/actions/workflows/tests.yml/badge.svg)](https://github.com/sandialabs/PEAT/actions)

![Python Version](https://img.shields.io/badge/Python-3.11|3.12|3-13-blue.svg)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)
[![PDM-managed](https://img.shields.io/endpoint?url=https%3A%2F%2Fcdn.jsdelivr.net%2Fgh%2Fpdm-project%2F.github%2Fbadge.json)](https://pdm-project.org)

PEAT is a Operational Technology (OT) device interrogator, including pulling, parsing and uploading artifacts (configuration, firmware, process logic, etc.) and network discovery ("scanning"). It runs on most systems, including Linux, Windows, and as a Docker container.

Documentation about installation, usage, development, and other information is in the [PEAT documentation](https://sandialabs.github.io/PEAT/).

## Quickstart

1. Download the [latest release](https://github.com/sandialabs/PEAT/releases) for your platform
1. Open a terminal in the folder you downloaded PEAT to
1. Run help to list subcommands
    - Windows: `.\peat.exe --help`
    - Linux: `./peat --help`
1. Get help for a subcommand, e.g. `scan`
    - Windows: `.\peat.exe scan --help`
    - Linux: `./peat scan --help`
1. Run a basic scan:
    - Windows: `.\peat.exe scan -i 192.0.2.0/24`
    - Linux: `./peat scan -i 192.0.2.0/24`

## Basic install

PEAT is distributed in several formats, including executable files for Linux and Windows and a Docker Container. The format you want to install depends on your use case. Typically, you'll want the executable format, which is `peat` on Linux and `peat.exe` on Windows. These can be downloaded from the [releases page](https://github.com/sandialabs/PEAT/releases) or from [CI/CD builds](https://github.com/sandialabs/PEAT/actions).

Python is NOT required to run PEAT if using the executable or container. PEAT is designed to be portable and brings it's own dependencies for the most part, requiring minimal or no configuring on the target system. Refer to the [system requirements page](https://sandialabs.github.io/PEAT/system_requirements.html) for further details.

NOTE: Refer to the [installation guide](https://sandialabs.github.io/PEAT/install.html) for installation instructions and [operation docs](https://sandialabs.github.io/PEAT/operate.html) for usage. The commands in the [quickstart](#quickstart) section are intended to get you going quickly, and are not comprehensive.

## Development

Refer to the [contributing guide](https://sandialabs.github.io/PEAT/contributing.html) and [development infrastructure](https://sandialabs.github.io/PEAT/development_infrastructure.html) documentation for details, including setting up a development environment, testing, and building on your local system.

The commands below are a basic "quick start" for development. Ensure [PDM is installed](https://pdm-project.org/en/stable/#installation) before proceeding.

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

## License

Copyright 2026 National Technology & Engineering Solutions of Sandia, LLC (NTESS). Under the terms of Contract DE-NA0003525 with NTESS, the U.S. Government retains certain rights in this software.

This software is licensed under a GPLv3 license. Please see [LICENSE](LICENSE) and [COPYRIGHT.md](COPYRIGHT.md) for more information.

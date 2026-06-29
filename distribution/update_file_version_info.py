#!/usr/bin/env python3

"""
Update the copyright year and version numbers in distribution/file_version_info.txt
This information is used by PyInstaller to set the Windows executable metadata.
Reference: https://pyinstaller.org/en/stable/usage.html#capturing-windows-version-data
"""

import re
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

INFO_PATH = Path(Path(__file__).parent, "file_version_info.txt")
if len(sys.argv) > 1:
    NEW_VERSION = sys.argv[1]
else:
    try:
        # Attempt to grab the latest release tag
        raw_version = subprocess.check_output(
            args=["git", "describe", "--tags", "--abbrev=0"], encoding="utf-8"
        )
        NEW_VERSION = raw_version.strip().strip("v")
    except subprocess.CalledProcessError:
        # Fallback to a clean numeric version so PyInstaller doesn't crash during build
        print(
            "Warning: No Git tags found in this context. Falling back to default '0.0.0'.", 
            file=sys.stderr, 
            flush=True
        )
        NEW_VERSION = "0.0.0"

print(f"New version: {NEW_VERSION}\nInfo path: {INFO_PATH}", flush=True)  # noqa: T201
data = INFO_PATH.read_text(encoding="utf-8")

# Ensure copyright year is current
curr_year = f"2016-{datetime.now(tz=UTC).year}"
if curr_year not in data:
    print(f"NOTE: Updating copyright year to '{curr_year}'", flush=True)  # noqa: T201
    data = re.sub(r"2016-\d{4}", curr_year, data)

# Update version strings. This should update 'FileVersion' and 'ProductVersion'
data = re.sub(r"Version', u'([\d\.]+)'\)", f"Version', u'{NEW_VERSION}')", data)

# Write the changes
INFO_PATH.write_text(data, encoding="utf-8", newline="")

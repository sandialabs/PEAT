#!/usr/bin/env python3

import sys
import re
from datetime import datetime, timezone
from pathlib import Path

new_version = sys.argv[1]
info_path = Path(Path(__file__).parent, "file_version_info.txt")

print(f"New version: {new_version}\nInfo path: {info_path}", flush=True)  # noqa: T201

data = info_path.read_text(encoding="utf-8")

# Ensure copyright year is current
curr_year = datetime.now(tz=timezone.utc).year
old_year = f"2016-{curr_year - 1}"
if old_year in data:
    new_year = f"2016-{curr_year}"
    print(f"NOTE: Updating year from '{old_year}' to '{new_year}'", flush=True)  # noqa: T201
    data = data.replace(old_year, new_year)

# Update version strings. This should update 'FileVersion' and 'ProductVersion'
data = re.sub(r"Version', u'([\d\.]+)'\)", f"Version', u'{new_version}')", data)

# Write the changes
info_path.write_text(data, encoding="utf-8", newline="")

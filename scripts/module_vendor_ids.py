#!/usr/bin/env python3

import json

from peat import module_api

identifiers = {
    name: {"id": device.vendor_id, "name": device.vendor_name}
    for name, device in module_api.modules.items()
}
print(json.dumps(identifiers, indent=4))

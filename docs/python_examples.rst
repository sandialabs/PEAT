***************
Python examples
***************

Device interaction
==================

Pull from a M340 PLC
--------------------
.. code-block:: python

   from pprint import pprint
   from peat import M340, datastore, initialize_peat

   # Calling initialize_peat is not required, but recommended.
   # It initializes logging, as well as file output folders.
   initialize_peat({"DEBUG": 1, "VERBOSE": True})

   dev = datastore.get("192.0.2.230")
   pull_succeeded = M340.pull(dev)
   print(pull_succeeded)  # bool, true if pull was successful
   pprint(device.export())  # print the data

Push firmware to a ControlLogix PLC
-----------------------------------
This uploads ("pushes") a new firmware image to a Allen-Bradley ControlLogix PLC.

.. code-block:: python

   from pathlib import Path
   from peat import ControlLogix, datastore

   fw_path = Path("clx-firmware.dmk")
   dev = datastore.get("192.0.2.200")
   push_succeeded = ControlLogix.push(dev, fw_path, "firmware")
   print(push_succeeded)  # bool, true if push was successful


Parsing
=======

Parsing a SEL project file
--------------------------
RDB file exported from SEL ACCelerator.

.. code-block:: python

   from pathlib import Path
   from peat import SELRelay

   input_file = Path("examples/devices/sel/sel_351s/351S5_106.rdb")
   dev = SELRelay.parse(input_file)
   print(dev.export())

Parsing a M340 project file
---------------------------
Extracts the Structured Text configuration from a M340 APX project file blob.

.. code-block:: python

   from pathlib import Path
   from peat import M340, datastore

   input_file = Path("project-file.apx")
   dev = M340.parse(input_file)
   print(dev.export())

Parsing a L5X file
------------------
Parse a ``.L5X`` file exported from Rockwell Studio5000.

.. code-block:: python

   from pprint import pprint
   from pathlib import Path
   from peat import L5X

   input_file = Path("examples/devices/l5x/basetest.L5X")
   dev = L5X.parse(input_file)
   pprint(dev.export())


Other examples
==============

Listing supported vendors
-------------------------
Utilize the module API to print the vendor name and ID (short name) for every device module included with PEAT.

.. code-block:: python

   import json
   from peat import module_api

   # This creates a dictionary with the key being the module name,
   # and the value being a dictionary with the vendor id and name.
   # If this Python syntax is unfamiliar, I recommend reading about
   # "python dictionary comprehensions" (and other comprehensions).
   identifiers = {
      name: {"id": device.vendor_id, "name": device.vendor_name}
      for name, device in module_api.modules.items()
   }

   # This converts the dict to JSON format, making it easier to
   # read on the command line, as well as usable by other tools
   print(json.dumps(identifiers, indent=4))


**********
Module API
**********

.. seealso::

   :doc:`module_developer_guide`

   :doc:`data_model`

   :doc:`Python code examples <python_examples>`

Quickstart
==========
The :class:`~peat.device.DeviceModule` class is the implementation of a PEAT "device module", and is the core of the PEAT Device Module :term:`API`. To interact with a device, users of the API instantiate a :class:`~peat.device.DataManager` instance with basic information about the device, then call the standard API functions on the implementation (e.g. :class:`~peat.modules.sandia.sceptre_fcd.SCEPTRE`) and pass them the :class:`~peat.device.DataManager` instance. Here is a simple example demonstrating usage:

.. code-block:: python
   :caption: Pulling data from a SEL relay via the network

   from pathlib import Path
   from pprint import pprint
   from peat import SELRelay, datastore

   # Create a DataManager instance with the device's IP address
   device = datastore.get("192.0.2.22")

   # Pass the instance to the pull_project method on the DeviceModule
   # implementation "SELRelay". The data pulled is added to the DataManager
   # instance created earlier.
   SELRelay.pull_project(device)

   # Export the data from the DataManager as a Python dictionary
   pprint(device.export())

   # Export it as JSON, sorted by key
   print(device.json(sorted=True))

   # Export to files (location set by config.DEVICE_RESULTS_DIR)
   device.export_to_files()


.. code-block:: python
   :caption: Parsing the configuration for a SCEPTRE virtual field device

   from pathlib import Path
   from pprint import pprint
   from peat import SCEPTRE

   config_path = Path("examples/devices/sceptre/config.xml")
   device = SCEPTRE.parse(config_path)
   pprint(device.export())

Further examples of module usage can be found in the `Python examples <python_examples>`_, ``peat/cli_main.py``, and the API implementations in ``peat/api/``.

Overview
========
To implement a module, refer to the :doc:`module_developer_guide`.

Data model
----------
All device data (e.g. firmware version, logic, etc.) is stored in instances of :class:`~peat.data.device_data.DeviceData`. This is known as the "data model". Refer to :doc:`data_model` for further details.

API
===

.. _device-api-reference:

DeviceModule class
------------------
.. warning::
   Not all of the methods defined in the base :class:`~peat.device.DeviceModule` class are guaranteed to be implemented by a module implementation (subclass)

.. automodule:: peat.device
   :members:
   :private-members:

.. _identify-methods:

Identify methods
----------------

IPMethod
^^^^^^^^
.. autopydantic_model:: peat.api.identify_methods.IPMethod
   :model-summary-list-order: alphabetical
   :inherited-members: BaseModel

SerialMethod
^^^^^^^^^^^^
.. autopydantic_model:: peat.api.identify_methods.SerialMethod
   :model-summary-list-order: alphabetical
   :inherited-members: BaseModel

Module manager
--------------
.. automodule:: peat.module_manager
   :members:

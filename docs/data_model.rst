**********
Data model
**********
Documentation on PEAT's internal model for structuring and managing data from devices (a.k.a "device data").

Working with data
=================
There are two ways to store and retrieve data:

- Directly via class attributes: ``dev.os.version = "7"``
- Using :meth:`.DeviceData.store` with a model class instance: ``dev.store("interface", Interface(ip="10.10.10.10"))``

Simple attribute values such as :attr:`~peat.data.models.DeviceData.architecture` or :attr:`~peat.data.models.DeviceData.type` should be assigned directly, e.g. ``dev.architecture = "x86_64"``.

Complex attributes that contain objects, such as ``interfaces`` (which is a :class:`list` of :class:`~peat.data.models.Interface`), should be set using :meth:`.DeviceData.store`.

General data can be retrieved directly via attribute access, e.g. ``os_ver = dev.os.version``. Complex objects (such as "services") are easily accessed using the :meth:`.DeviceData.retrieve` helper method, which will search and filter objects based on the desired attributes, e.g. the IP address or port of a interface. However, they can also be accessed directly as regular lists, if desired.

DeviceData
==========
.. autopydantic_model:: peat.data.models.DeviceData

.. _data-models:

Data Models
===========
.. note::
   Most fields with a type of ``peat.data.models.ConstrainedStrValue`` are just :class:`str` type, but will automatically have any whitespace stripped when assigned to.

.. currentmodule:: peat.data.models

.. autosummary::

   Description
   Event
   File
   Firmware
   Geo
   Hardware
   Hash
   IO
   Interface
   LatLon
   Logic
   Memory
   OS
   Register
   Related
   Service
   SSHKey
   Tag
   Vendor
   X509
   CertEntity

.. automodule:: peat.data.models
   :members:
   :exclude-members: DeviceData

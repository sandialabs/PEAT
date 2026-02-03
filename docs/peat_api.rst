********
PEAT API
********
The general :term:`API` provides a generalized interface to execute the PEAT "verbs": scan, parse, pull, push, pillage, and heat. The purpose of this API is to "wrap" the device module API and provide a consistent and well-tested set of powerful interfaces into PEAT's core functionality and device modules. It is used for implementing the PEAT :term:`CLI`, as well as integration with other :term:`SNL`-developed capabilities.

High-level API
==============
.. automodule:: peat.api.scan_api
   :members: scan
   :noindex:

.. automodule:: peat.api.pull_api
   :members: pull
   :noindex:

.. automodule:: peat.api.push_api
   :members: push
   :noindex:

.. automodule:: peat.api.parse_api
   :members: parse
   :noindex:

.. automodule:: peat.api.pillage_api
   :members: pillage
   :noindex:

Configuration API
=================
Configuration options that are accessible from anywhere in PEAT. These are currently resident in :data:`peat.settings.config` variable, which is a singleton instance of the :class:`~peat.settings.Configuration` class. They can be accessed with ``from peat import config``.

Refer to :doc:`operate` for details on the available configuration options and how to set them, and the :ref:`config-state-deepdive` in the PEAT developer documentation for a deep dive into how the system works internally.

.. autoclass:: peat.settings.Configuration
   :members:

Constants
=========
Constants that are determined at program start, such as platform information, timezone, time of start, and time format.

.. csv-table::
   :name: PEAT Constants
   :header: "Variable", "Type", "Description"
   :widths: auto
   :align: left

   WINDOWS, :class:`bool`, "If running on Windows (not in :term:`WSL`)"
   POSIX, :class:`bool`, "If running on a POSIX :term:`OS`, including Linux and OSX"
   LINUX, :class:`bool`, "If running on Linux"
   WSL, :class:`bool`, "If running in Windows Subsystem for Linux (:term:`WSL`)"
   TIME_FMT, :class:`str`, "Format used for most string timestamps in PEAT"
   LOG_TIME_FMT, :class:`str`, "Time format used for most :mod:`logging` handlers"
   LOG_MESG_FMT, :class:`str`, "Message format used for all :mod:`logging` handlers"
   START_TIME_UTC, :class:`~datetime.datetime`, "Time PEAT started in :term:`UTC` timezone"
   START_TIME_LOCAL, :class:`~datetime.datetime`, "Time PEAT started, as a local timezone :class:`~datetime.datetime` object"
   START_TIME, :class:`str`, "Time PEAT started, as a human-readable formatted string"
   TIMEZONE, :class:`str`, "Timezone of the system, e.g ``America/Denver``"
   RUN_ID, :class:`int`, "Unique integer ID used to distinguish different PEAT runs"
   LOGO, :class:`str`, "The PEAT logo which is printed to the terminal at startup"
   SYSINFO, :class:`dict`, "Information about the system PEAT is running on, such as the hostname, username, and :term:`OS`"

State API
=========
Runtime values that are used to preserve or share state across PEAT. Currently stored in :data:`peat.settings.state` variable, which is a singleton instance of the :class:`~peat.settings.State` class. They can be accessed with ``from peat import state``. The state values are saved to a file when PEAT finishes executing in ``peat_results/metadata/state/peat_state_***.json``.

.. note::
   It is possible to modify the starting state via environment variables. Environment variables beginning with ``PEAT_STATE_`` will be loaded to their corresponding variables in the global state registry. This can be useful if debugging or as a temporary patch for a issue. Modifying the state in this manner should be avoided if possible, as it could cause undefined behavior or a crash.

.. autoclass:: peat.settings.State
   :members:

Exceptions
==========
.. autoclass:: peat.consts.PeatError
   :noindex:

.. autoclass:: peat.consts.ParseError
   :noindex:

.. autoclass:: peat.consts.CommError
   :noindex:

.. autoclass:: peat.consts.DeviceError
   :noindex:

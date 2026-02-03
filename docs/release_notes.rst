*************
Release Notes
*************

.. _known-issues:

Known Issues
============

- ``peat parse`` may have odd results when run with empty files (0 bytes)
- ControlLogix: IP, MAC, services, and other data from multiple communication modules on a single ControlLogix PLC aren't being added to ``host.module`` properly when de-duplication and merging occurs. Additionally, the module that gets selected as the "primary" to represent the device isn't fully deterministic and relies on whatever gets checked first. This issue occurs if a device has 2 or more communication modules *that are queried by PEAT*. For example, if a device has a EWEB at ``192.168.0.10`` and a EN2TR at ``192.168.0.11`` and both are interrogated by PEAT, then some data from the two modules may not be merged properly during the de-duplication process.
- ION module: Sometimes the ION module will mis-parse data scraped from Telnet. This results in a corrupted MAC address with a value that similar to ``"19:2.:16:8.:3.:20:04"`` and a IP that isn't an IP (e.g. ``"Settings"``). It's not consistently reproducible and occurs rarely, but when it occurs, the effects are quite obvious. If it occurs, the issue will be obvious in the following fields: ``interface.*``, ``related.ip``, ``related.mac``.

Resolved issues
---------------

TBD

Releases
========

TBD
---

Added
^^^^^

Changed
^^^^^^^

Removed
^^^^^^^

Other
^^^^^

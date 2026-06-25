Changelog
*********

All notable changes to this project will be documented in this file.

The format is based on `Keep a Changelog <https://keepachangelog.com/en/1.1.0/>`__, and this project uses Calendar Versioning.


.. _known-issues:

Known Issues
============

- ``peat parse`` may have odd results when run with empty files (0 bytes)
- ControlLogix: IP, MAC, services, and other data from multiple communication modules on a single ControlLogix PLC aren't being added to ``host.module`` properly when de-duplication and merging occurs. Additionally, the module that gets selected as the "primary" to represent the device isn't fully deterministic and relies on whatever gets checked first. This issue occurs if a device has 2 or more communication modules *that are queried by PEAT*. For example, if a device has a EWEB at ``192.168.0.10`` and a EN2TR at ``192.168.0.11`` and both are interrogated by PEAT, then some data from the two modules may not be merged properly during the de-duplication process.

Resolved issues
---------------

None yet after open-sourcing!


Releases
========

.. towncrier release notes start

v2026.6.25 (2026-06-25)
=======================

Features
--------

- Added devcontainer to enable quick and reproducible creation of a consistent developer experience regardless of host platform
- Added command for passive forensic analysis of artifacts without touching live devices
- Added minified device-data-full where whitespace is removed from output by default
- Split data models into jsonl files
- Added towncrier to manage CHANGELOG.rst
- Added ``peat pull --skip-scan`` flag to bypass the scan phase and pull directly from hosts defined in a config file. Per-host ``peat_module`` mappings in the ``hosts`` list are respected; a single ``-d`` device type can be used as a fallback. The ``-i``/``-f`` argument is no longer required when a config file with a ``hosts`` list is supplied. (`#60 <https://github.com/sandialabs/PEAT/issues/60>`_)

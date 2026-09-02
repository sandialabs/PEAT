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

v2026.9.2 (2026-09-02)
======================

Features
--------

- Add MySQL/MariaDB protocol class (``peat/protocols/mysql.py``) with unauthenticated server fingerprinting via TCP greeting packet, PyMySQL-backed query helpers, and ``on_connected``/``enumerate`` subclass hooks for device-specific extensions. (`#62 <https://github.com/sandialabs/PEAT/issues/62>`_)
- Added support for encrypting and decrypting PEAT result archives. (`#67 <https://github.com/sandialabs/PEAT/issues/67>`_)
- Added a new built-in PEAT module for the OpenPLC Runtime v4. This natively integrated module enables discovery, fingerprinting, data collection, and program deployment on OpenPLC v4 instances via its REST API. The implementation features optimized API session caching, respects global HTTPS port configurations, and includes dedicated configuration templates (`examples/openplc-config.yaml`). Additionally, a comprehensive live-testing suite has been included, accessible via the new `--run-container` Pytest flag, which tests the module against a live OpenPLC Docker container. (`#72 <https://github.com/sandialabs/PEAT/issues/72>`_)


Bugfixes
--------

- Fixed a bug in the core scanning API that caused default port state pollution. The scanner now strictly maps open services by `(protocol, port)` pairs and safely reverts transient configuration changes, ensuring modules with custom port assignments do not overwrite or pollute global port states during fingerprinting. (`#72 <https://github.com/sandialabs/PEAT/issues/72>`_)
- fix: Added missing encrypt/decrypt examples to CLI and fixed exception when an invalid example is requested (`#83 <https://github.com/sandialabs/PEAT/issues/83>`_)


Misc
----

- `#80 <https://github.com/sandialabs/PEAT/issues/80>`_


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

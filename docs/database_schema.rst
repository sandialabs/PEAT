.. _database-schema:

***************
Database Schema
***************
This section details the Elasticsearch database schema for PEAT. The objective with this schema is to establish common data structures that can be used to build visualizations and dashboards in Kibana.

Elastic Common Schema (`ECS <https://www.elastic.co/guide/en/ecs/current/index.html>`__) version: ``8.10.0``


Notes
=====
- **Elasticsearch is a NoSQL database, why is there a schema?** Because to share data between users and tools, the data should have a predictable format.
- The schemas here are descriptions of the :term:`JSON` fields expected of a "entry" in the Elasticsearch database (also known as a ``doc``).
- "Data Type" values are Elasticsearch data types (`reference <https://www.elastic.co/guide/en/elasticsearch/reference/current/mapping-types.html>`__). When storing as a plain :term:`JSON` file, ensure the format it is stored in either matches or can be cohered to the corresponding Elasticsearch format.
- Fields listed as ``required`` must be included in any docs that contain the parent field. If the field is at the root level, it is required for any docs in that index.
- Fields listed as ``optional`` do not have to be included in a doc push. However, any data that matches that field must use that field and not a custom field.
- Additional fields beyond those defined here are permitted, provided they're internally consistent (e.g. always the same for a version of a tool).
- These schemas follow the Elastic Common Schema (`ECS <https://www.elastic.co/guide/en/ecs/current/index.html>`__). Changes must adhere to the ECS, when possible.


Indices
=======
This section lists the Elasticsearch indices (aka "indexes") used by PEAT, and what they are used for.

- **peat-logs-[year].[month].[day]**: Logs for PEAT. 1 document = 1 event.
- **ot-device-hosts-timeseries-[year].[month].[day]**: Results of PEAT pulls. 1 document = results from 1 device.
- **peat-scan-summaries-[year].[month].[day]**: Results of PEAT scans. 1 document = results from all devices in the scan.
- **peat-pull-summaries-[year].[month].[day]**: Results of PEAT pulls. 1 document = results from all devices in the scan.
- **peat-parse-summaries-[year].[month].[day]**: Results of PEAT parses. 1 document = results from all devices parsed.
- **peat-configs-[year].[month].[day]**: Configuration values used by PEAT for a run. 1 document = config values for a single PEAT run.
- **peat-state-[year].[month].[day]**: Internal state of PEAT for a run. 1 document = state values for a single PEAT run.

Universal Requirements
======================
- **ALL entries MUST include the Base and Agent field sets.**
- ALL timestamps MUST be in the :term:`UTC` timezone, in ISO 8601 format, and use the Elastic ``date`` data type.


Schema Update Process
=====================
There are a few ways the Schema we use will be updated:

- **ECS Schema Updates**: Elasticsearch regularly updates the Elastic Common Schema. We will bring in relevant changes from their updates into our schema.
- **PEAT Updates**: Updates to PEAT comes with new data in the database. Updates to this schema are included in this process.

.. _base-fields:

Base Fields
-----------
.. csv-table:: Base Fields
   :escape: \
   :file: field_references/base_fields.csv
   :header-rows: 1
   :widths: auto
   :align: left

.. _agent-fields:

Agent Fields
------------
Information about the tool that generated the event (PEAT). ECS reference: `Agent Fields <https://www.elastic.co/guide/en/ecs/current/ecs-agent.html>`__

.. csv-table:: Agent Fields
   :escape: \
   :file: field_references/agent_fields.csv
   :header-rows: 1
   :widths: auto
   :align: left


PEAT Logs (``peat-logs-*``)
===========================
Logs from PEAT, such as errors or informational messages. Note that this does not include logs collected from OT devices by PEAT, those fall under ``ot-device-hosts-*``.

Notes
-----
- Index: ``peat-logs-<date>``, where ``date`` is, ``year.month.day`` in UTC. Example: ``peat-logs-2026.01.29``
- ``message``: Human-readable log message. No longer than 80 characters.
- Every entry includes the :ref:`base-fields` and :ref:`agent-fields`.
- The level and complete log entry text is contained in the ``log.*`` field set, defined below.
- Python :class:`logging.LogRecord` objects can be used to populate all of these fields (`logrecord attributes documentation <https://docs.python.org/3/library/logging.html#logrecord-attributes>`__).

Fields
------
ECS reference: `Log Fields <https://www.elastic.co/guide/en/ecs/current/ecs-log.html>`__

.. csv-table:: Log Fields
   :escape: \
   :file: field_references/log_fields.csv
   :header-rows: 1
   :widths: auto
   :align: left


OT Devices (``ot-device-hosts-timeseries-*``)
=============================================
:term:`OT` field device information collected by :term:`PEAT`.

Notes
-----
- Index: ``ot-device-hosts-timeseries-<date>``, where date is, ``year.month.day`` in UTC. Example: ``ot-device-hosts-timeseries-2026.01.29`` (for data collected on Jan 29th, 2026)
- ``message``: Human-readable description or summary of the device.
- Every entry includes the :ref:`base-fields` and :ref:`agent-fields`.
- All fields are nested under the ``host`` field, e.g. ``host.ip``.
- Nested and custom fields attempt to follow the ECS field set names where possible.
- Events that occur on the host and pertain to active status information, e.g. device power on/reset, service up, logic changed, etc, will be put into the ``ot-device-events-*`` index
- Some status attributes, such as system uptime, can be derived from device events or logs.

Fields
------
.. note::
   The ``host.extra`` field has sub-fields dynamically named based on the PEAT device module name (e.g. ``host.extra.selrelay.*``), which does not conform to :term:`ECS`. This is to prevent clashes with a dynamically defined schema. Example: you push a bunch of data from SEL, and a field (say, ``address``) happens to have the same name as a ION field. If the SEL address was a integer, but the ION is a string, when PEAT tries to push the ION data it will fail due to a different data type for the same field name.

.. csv-table:: OT Devices Fields
   :escape: \
   :file: field_references/ot_devices_fields.csv
   :header-rows: 1
   :widths: auto
   :align: left


PEAT scan summaries (``peat-scan-summaries-*``)
===============================================
Results from :term:`PEAT` scans.

Notes
-----
Index: ``peat-scan-summaries-<date>``, where ``date`` is, ``year.month.day`` in UTC. Example: ``peat-scan-summaries-2026.01.01``
- Every entry includes the :ref:`base-fields` and :ref:`agent-fields`.

Fields
------
.. csv-table:: Scan Summary Fields
   :escape: \
   :file: field_references/scan_summaries_fields.csv
   :header-rows: 1
   :widths: auto
   :align: left


PEAT pull summaries (``peat-pull-summaries-*``)
===============================================
Results from :term:`PEAT` pulls.

Notes
-----
Index: ``peat-pull-summaries-<date>``, where ``date`` is, ``year.month.day`` in UTC. Example: ``peat-pull-summaries-2026.01.01``
- Every entry includes the :ref:`base-fields` and :ref:`agent-fields`.

Fields
------
.. csv-table:: Pull Summary Fields
   :escape: \
   :file: field_references/pull_summaries_fields.csv
   :header-rows: 1
   :widths: auto
   :align: left


PEAT parse summaries (``peat-parse-summaries-*``)
=================================================
Results from :term:`PEAT` parses.

Notes
-----
Index: ``peat-parse-summaries-<date>``, where ``date`` is, ``year.month.day`` in UTC. Example: ``peat-parse-summaries-2026.01.01``
- Every entry includes the :ref:`base-fields` and :ref:`agent-fields`.

Fields
------
.. csv-table:: Parse Summary Fields
   :escape: \
   :file: field_references/parse_summaries_fields.csv
   :header-rows: 1
   :widths: auto
   :align: left


References
==========
- `ECS Reference <https://www.elastic.co/guide/en/ecs/current/index.html>`__
- `ECS Conventions <https://www.elastic.co/guide/en/ecs/current/ecs-conventions.html>`__
- `ECS Guidelines <https://www.elastic.co/guide/en/ecs/current/ecs-guidelines.html>`__
- `ECS Changelog <https://github.com/elastic/ecs/blob/master/CHANGELOG.md>`__
- `Field Datatypes <https://www.elastic.co/guide/en/elasticsearch/reference/current/mapping-types.html>`__
- `Multi-Fields <https://www.elastic.co/guide/en/elasticsearch/reference/current/multi-fields.html>`__
- `Elasticsearch Documentation <https://www.elastic.co/guide/en/elasticsearch/reference/current/index.html>`__


Examples/further reading
========================
- `Filebeat ECS fields <https://www.elastic.co/guide/en/beats/filebeat/current/exported-fields-ecs.html>`__
- `Packetbeat ECS fields <https://www.elastic.co/guide/en/beats/packetbeat/current/exported-fields-ecs.html>`__
- `Winlogbeat ECS fields <https://www.elastic.co/guide/en/beats/winlogbeat/current/exported-fields-ecs.html>`__
- `Punch platform ECS example <https://punchplatform.com/2019/03/10/leveraging-the-elastic-common-schema/>`__

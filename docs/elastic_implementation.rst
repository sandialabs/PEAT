***********************
Elasticsearch internals
***********************

.. seealso::

   :ref:`database-schema`
      Elasticsearch index schema definitions and details

   :ref:`peat-index-reference`
      Table of the Elasticsearch indices used by PEAT

   :ref:`peat-elastic-operate`
      Elasticsearch usage and other information.

Notes
=====
- PEAT follows the `Elastic Common Schema (ECS) <https://www.elastic.co/guide/en/ecs/current/ecs-reference.html>`__, and **any changes must adhere to the ECS (when possible)**
- **All indices share the ECS Base and Agent field sets** (refer to :ref:`database-schema`)
- ALL timestamps are in the :term:`UTC` timezone
- Field types (the "Type" column in the tables) are Elasticsearch datatypes (`reference <https://www.elastic.co/guide/en/elasticsearch/reference/current/mapping-types.html>`__). When storing as a plain :term:`JSON` file, ensure the format it is stored in either matches or can be cohered to the corresponding ES format.
- The document's ``_id`` field is unique for each document. The format is: ``peat~<run-id>~<microsecond>``, where ``<microsecond>`` is an integer.
- Sub-fields are nested :term:`JSON` objects. From the `ECS Guidelines <https://www.elastic.co/guide/en/ecs/current/ecs-guidelines.html>`__: "The document structure should be nested JSON objects. If you use Beats or Logstash, the nesting of JSON objects is done for you automatically. If you're ingesting to Elasticsearch using the API, your fields must be nested objects, not strings containing dots."

.. seealso::

   `Elastic Common Schema (ECS) documentation <https://www.elastic.co/guide/en/ecs/current/index.html>`__

   `ECS Overview <https://www.elastic.co/guide/en/ecs/current/ecs-reference.html>`__

   `ECS Field Reference <https://www.elastic.co/guide/en/ecs/current/index.html>`__

   `ECS Guidelines <https://www.elastic.co/guide/en/ecs/current/ecs-guidelines.html>`__

   `Elasticsearch data types <https://www.elastic.co/guide/en/elasticsearch/reference/current/mapping-types.html>`__

Code documentation
==================

Elastic
-------
.. automodule:: peat.elastic
   :members:

Index type mappings
-------------------
.. automodule:: peat.es_mappings
   :members:

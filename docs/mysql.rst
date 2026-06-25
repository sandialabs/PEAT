*****
MySQL
*****

MySQL and MariaDB are widely deployed relational database servers. In OT environments, MySQL/MariaDB instances are commonly found on historian servers, HMI backends, and engineering workstations.

PEAT supports both unauthenticated fingerprinting (via the TCP greeting packet) and authenticated enumeration (via SQL queries) using the :class:`~peat.protocols.mysql.MySQL` protocol class.

.. seealso::

   :class:`~peat.protocols.mysql.MySQL`
      PEAT protocol class for MySQL/MariaDB connections

   `MySQL Documentation <https://dev.mysql.com/doc/>`__

   `MariaDB Documentation <https://mariadb.com/kb/en/documentation/>`__

   `PyMySQL <https://pymysql.readthedocs.io/en/latest/>`__
      The underlying Python library used for authenticated connections

Fingerprinting without credentials
-----------------------------------

MySQL sends an initial handshake packet immediately after a TCP connection is established, before any authentication takes place. This packet includes the server version string (e.g. ``8.0.32`` or ``10.6.12-MariaDB``).

:meth:`~peat.protocols.mysql.MySQL.read_greeting` reads this packet over a raw TCP socket, allowing PEAT to identify a MySQL/MariaDB server and extract its version without credentials.

Data collected
--------------

When credentials are available, PEAT can enumerate the following via SQL queries:

- Server version string and parsed version tuple
- Database names visible to the authenticated user
- Table names per database
- Approximate row counts per table (from ``information_schema``)
- User accounts and their allowed hosts (from ``mysql.user``)
- Grants for each user (``SHOW GRANTS``)
- Global system variables (``SHOW GLOBAL VARIABLES``)
- Active connections and queries (``SHOW FULL PROCESSLIST``)

Configuration
-------------

Credentials and connection options are specified in the PEAT config file under the ``mysql`` key in ``device_options``:

.. code-block:: yaml

   device_options:
     mysql:
       credentials:
         user: root
         pass: secret
       port: 3306
       timeout: 10

Developer notes
---------------

The :class:`~peat.protocols.mysql.MySQL` class uses a lazy connection pattern: the underlying PyMySQL connection is not established when the object is created, but on the first call to any query method. This avoids opening TCP connections to hosts that are later filtered or skipped before enumeration begins.

The class is designed as a base class. The :meth:`~peat.protocols.mysql.MySQL.on_connected` and :meth:`~peat.protocols.mysql.MySQL.enumerate` hooks are intended to be overridden in device-specific subclasses. ``on_connected`` runs immediately after authentication and can be used to run setup queries or populate instance attributes. ``enumerate`` should return a dict of any device-specific table data — for example, a subclass targeting a historian might query proprietary tables that have no meaning in a generic MySQL context. The base class implementations are no-ops that return nothing and an empty dict respectively.

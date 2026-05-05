"""Integration tests for peat.protocols.mysql against a live MySQL instance.

Requires a running MySQL server. Connection details are read from environment
variables (defaults match the docker-compose-mysql-telnet.yaml example):

    MYSQL_HOST      (default: 127.0.0.1)
    MYSQL_PORT      (default: 3306)
    MYSQL_USER      (default: root)
    MYSQL_PASSWORD  (default: testpass)
"""

import os

import pytest

from peat.protocols.mysql import MySQL

HOST = os.environ.get("MYSQL_HOST", "127.0.0.1")
PORT = int(os.environ.get("MYSQL_PORT", "3306"))
USER = os.environ.get("MYSQL_USER", "root")
PASSWORD = os.environ.get("MYSQL_PASSWORD", "testpass")


@pytest.fixture(scope="module")
def mysql():
    m = MySQL(HOST, port=PORT, username=USER, password=PASSWORD)
    assert m.connect(), f"Could not connect to MySQL at {HOST}:{PORT}"
    yield m
    m.disconnect()


@pytest.mark.container
def test_read_greeting():
    version = MySQL.read_greeting(HOST, port=PORT)
    assert version is not None
    assert len(version) > 0


@pytest.mark.container
def test_connect_populates_server_info(mysql):
    assert mysql.connected
    assert mysql.server_info != ""
    assert mysql.server_version >= (8, 0)


@pytest.mark.container
def test_get_databases_includes_information_schema(mysql):
    dbs = mysql.get_databases()
    assert "information_schema" in dbs


@pytest.mark.container
def test_get_tables_returns_results(mysql):
    tables = mysql.get_tables("information_schema")
    assert len(tables) > 0


@pytest.mark.container
def test_get_global_variables(mysql):
    variables = mysql.get_global_variables(like="version%")
    assert "version" in variables


@pytest.mark.container
def test_get_users_includes_root(mysql):
    users = mysql.get_users()
    assert any(u["user"] == "root" for u in users)


@pytest.mark.container
def test_get_process_list(mysql):
    processes = mysql.get_process_list()
    assert isinstance(processes, list)


@pytest.mark.container
def test_context_manager():
    with MySQL(HOST, port=PORT, username=USER, password=PASSWORD) as m:
        assert m.connect()
        assert m.connected
    assert not m.connected

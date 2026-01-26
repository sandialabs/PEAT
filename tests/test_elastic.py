import os
import time
from datetime import datetime

import pytest

from peat import Elastic, config


def test_init():
    assert Elastic()


def test_url():
    unsafe_url = "http://elastic:changeme@localhost:9200"
    safe_url = "http://localhost:9200/"
    es = Elastic(unsafe_url)
    assert es.unsafe_url == f"{unsafe_url}/"
    assert es.safe_url == safe_url
    assert es.host == "localhost:9200"
    assert Elastic(safe_url).safe_url == safe_url


def test_bencode():
    assert Elastic.bencode(b"") == ""
    assert Elastic.bencode(b"1234") == "MTIzNA=="


def test_convert_tstamp():
    exp = "2019-02-25T17:39:11.507Z"
    assert Elastic.convert_tstamp(datetime(2019, 2, 25, 17, 39, 11, 507318)) == exp
    assert Elastic.convert_tstamp("2019-02-25T17:39:11.507318") == exp


def test_gen_id(mocker):
    mocker.patch("peat.consts.RUN_ID", "123456789")
    assert "123456789" in Elastic.gen_id()
    assert "peat" in Elastic.gen_id()


def test_str():
    assert str(Elastic()) == Elastic().host


def test_repr():
    assert isinstance(eval(repr(Elastic())), Elastic)


@pytest.mark.gitlab_ci_only
def test_elastic_live_ci(mocker, tmp_path):
    mocker.patch.dict(
        config["CONFIG"],
        {
            "DEBUG": 1,
            "ELASTIC_DIR": tmp_path,
            "LOG_DIR": tmp_path,
        },
    )

    es = Elastic(os.environ["ES_URL"])

    assert es.ping()
    assert es.info()

    assert not es.index_exists("test-index-that-does-not-exist")
    assert not es.doc_exists("test-index-that-does-not-exist", "test_doc_id")
    assert es.push(
        index="alerts",
        content={"action": "threshold-exceeded"},
        doc_id="test_doc_id",
        no_date=True,
    )
    time.sleep(2)  # the search will fail if query happens too soon after push
    assert len(es.search("alerts")) == 1
    assert not es.doc_exists("alerts", "invalid_doc_id")
    assert es.doc_exists("alerts", "test_doc_id")

    assert es.push("alerts", {"action": "threshold-exceeded-yet-again"})
    time.sleep(2)  # the search will fail if query happens too soon after push
    assert len(es.search("alerts-*")) == 1
    assert len(es.search("alerts*")) == 2
    es.disconnect()

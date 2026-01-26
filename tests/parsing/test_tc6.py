from xml.etree.ElementTree import Element, ElementTree

from peat import config
from peat.parsing.tc6 import TC6


def test_tc6_initialization():
    tc6 = TC6("AwesomeProject")
    assert tc6.main_name == "main"
    assert isinstance(tc6.root, Element)
    assert isinstance(tc6.tree, ElementTree)


def test_make_pou():
    tc6 = TC6("AwesomerProject")
    pou = tc6.make_pou("test_pou")
    assert isinstance(pou, Element)
    assert pou in tc6.pous


def test_generate_xml_string():
    assert "AwesomeXML" in TC6("AwesomeXML").generate_xml_string()
    assert "T#50ms" in TC6().generate_xml_string(sceptre=True)


def test_generate_st():
    assert isinstance(TC6("AwesomeST").generate_st(), str)
    assert isinstance(TC6().generate_st(sceptre=True), str)


def test_prettify_xml(mocker, tmp_path):
    mocker.patch.dict(
        config["CONFIG"],
        {
            "LOG_DIR": tmp_path / "logs",
            "DEBUG": 1,
        },
    )

    assert isinstance(TC6().prettify_xml(Element("DOG")), str)
    assert TC6().prettify_xml(None) == ""


def test_str():
    tc6 = TC6("Lions")
    assert str(tc6) == ""
    assert str(tc6) == tc6.generate_st()


def test_repr():
    tc6 = TC6("Penguins")
    result = repr(tc6)
    assert result
    assert isinstance(result, str)

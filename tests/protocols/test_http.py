import pytest

from peat import config, consts
from peat.protocols.http import HTTP


def test_http_class():
    ip = "127.0.0.1"
    obj = HTTP(ip)
    assert str(obj) == ip
    assert obj.gen_soup("")
    assert obj.gen_soup(b"")
    assert obj.gen_session()


def test_http_decode_ssl_certificate(mocker, datapath, deep_compare, tmp_path, read_text):
    mocker.patch.dict(config["CONFIG"], {"TEMP_DIR": None})

    cert_path = datapath("sage_certificate.cert")
    cert_data = read_text(cert_path)
    expected = {
        "version": 1,
        "serialNumber": "D8796CC54080FB3E",
        "notBefore": "Mar 30 16:54:51 2012 GMT",
        "notAfter": "Mar 30 16:54:51 2042 GMT",
    }

    h = HTTP("127.0.0.1")

    file_res = h.decode_ssl_certificate(cert_path)
    assert file_res[1] == cert_data
    deep_compare(file_res[0], expected, exclude_regexes=r"\['(issuer|subject)'\]")

    text_res = h.decode_ssl_certificate(cert_path.read_text(encoding="utf-8"))
    assert text_res[1] == cert_data
    deep_compare(text_res[0], expected, exclude_regexes=r"\['(issuer|subject)'\]")
    assert file_res == text_res

    # ensure it works with TEMP_DIR set
    mocker.patch.dict(config["CONFIG"], {"TEMP_DIR": tmp_path})
    h2 = HTTP("127.0.0.1")
    tempfile_res = h2.decode_ssl_certificate(cert_path)
    assert tempfile_res[1] == cert_data
    deep_compare(tempfile_res[0], expected, exclude_regexes=r"\['(issuer|subject)'\]")


@pytest.mark.parametrize("device_name", ["sage", "sel_2730m", "sel_3530"])
def test_http_parse_decoded_ssl_certificate(mocker, json_data, datapath, tmp_path, device_name):
    mocker.patch.dict(config["CONFIG"], {"TEMP_DIR": tmp_path})

    expected = json_data(f"expected_parsed_{device_name}_certificate.json")
    cert_pth = datapath(f"{device_name}_certificate.cert")

    h = HTTP("127.0.0.1")
    decoded, raw = h.decode_ssl_certificate(cert_pth)
    parsed = h.parse_decoded_ssl_certificate(decoded, raw)
    parsed.annotate()  # populate hash fields
    data = consts.convert(parsed.dict(exclude_defaults=True, exclude_none=True))
    assert data == expected

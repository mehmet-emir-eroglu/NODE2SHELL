import http.client
import socket
import ssl
from email.message import Message
from io import BytesIO
from unittest.mock import MagicMock, patch
from urllib.error import HTTPError, URLError
from urllib.request import Request

import pytest

from cve_detector.evidence import manifest_url
from cve_detector.exceptions import DetectionError
from cve_detector.network import NoRedirect, fetch_manifest

URL = manifest_url("24.22.1")
PAYLOAD = f"{'a' * 64}  win-x64/node.exe\n".encode()


def response(code=200, payload=PAYLOAD, encoding=None):
    item = MagicMock()
    item.__enter__.return_value = item
    item.status = code
    item.geturl.return_value = URL
    item.headers = Message()
    if encoding:
        item.headers["Content-Encoding"] = encoding
    item.read.return_value = payload
    return item


def test_request_is_fixed_origin_verified_tls_bounded_and_no_proxy():
    item = response()
    with patch("cve_detector.network.build_opener") as build:
        build.return_value.open.return_value = item
        assert fetch_manifest("24.22.1") == PAYLOAD
        request = build.return_value.open.call_args.args[0]
        assert request.full_url == URL
        assert request.get_method() == "GET"
        assert request.data is None
        assert request.get_header("Accept-encoding") == "identity"
        assert build.call_args.args[0].proxies == {}
        context = build.call_args.args[2]._context
        assert context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname
    item.read.assert_called_once_with(65537)
    item.__exit__.assert_called_once()


@pytest.mark.parametrize("code", [301, 302, 307, 308, 401, 403, 404, 429, 500, 503])
def test_http_errors_not_retried_or_redirected(code):
    headers = Message()
    headers["Location"] = "https://outside.invalid/"
    error = HTTPError(URL, code, "message", headers, BytesIO())
    with patch("cve_detector.network.build_opener") as build:
        build.return_value.open.side_effect = error
        with pytest.raises(DetectionError):
            fetch_manifest("24.22.1", retries=2)
        assert build.return_value.open.call_count == 1
    assert error.closed
    assert (
        NoRedirect().redirect_request(
            Request(URL), None, code, "", headers, "https://outside.invalid/"
        )
        is None
    )


@pytest.mark.parametrize(
    "failure",
    [
        URLError(socket.gaierror()),
        URLError(ConnectionRefusedError()),
        TimeoutError(),
        http.client.BadStatusLine("bad"),
        http.client.IncompleteRead(b"partial"),
    ],
)
def test_transport_failure_bounded_retries(failure):
    with (
        patch("cve_detector.network.build_opener") as build,
        patch("cve_detector.network.time.sleep"),
    ):
        build.return_value.open.side_effect = failure
        with pytest.raises(DetectionError):
            fetch_manifest("24.22.1", retries=2)
        assert build.return_value.open.call_count == 3


def test_retry_success():
    with (
        patch("cve_detector.network.build_opener") as build,
        patch("cve_detector.network.time.sleep"),
    ):
        build.return_value.open.side_effect = [TimeoutError(), response()]
        assert fetch_manifest("24.22.1", retries=1) == PAYLOAD


def test_tls_error_not_retried():
    with patch("cve_detector.network.build_opener") as build:
        build.return_value.open.side_effect = URLError(ssl.SSLCertVerificationError())
        with pytest.raises(DetectionError, match="TLS"):
            fetch_manifest("24.22.1", retries=2)
        assert build.return_value.open.call_count == 1


@pytest.mark.parametrize(
    "payload,encoding,code",
    [(b"", None, 200), (b"x" * 65537, None, 200), (PAYLOAD, "br", 200), (PAYLOAD, None, 204)],
)
def test_invalid_payloads(payload, encoding, code):
    with patch("cve_detector.network.build_opener") as build:
        build.return_value.open.return_value = response(code, payload, encoding)
        with pytest.raises(DetectionError):
            fetch_manifest("24.22.1")


def test_changed_final_url_rejected():
    item = response()
    item.geturl.return_value = "https://other.invalid/"
    with patch("cve_detector.network.build_opener") as build:
        build.return_value.open.return_value = item
        with pytest.raises(DetectionError):
            fetch_manifest("24.22.1")


@pytest.mark.parametrize("timeout,retries", [(0, 0), (31, 0), (float("nan"), 0), (1, -1), (1, 3)])
def test_invalid_limits(timeout, retries):
    with pytest.raises(DetectionError):
        fetch_manifest("24.22.1", timeout, retries)

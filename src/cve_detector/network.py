"""Opt-in, fixed-origin retrieval of public Node.js checksum metadata only."""

import http.client
import math
import ssl
import time
from email.message import Message
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, HTTPSHandler, ProxyHandler, Request, build_opener

from .evidence import MAX_MANIFEST_BYTES, manifest_url
from .exceptions import DetectionError


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(
        self, req: Request, fp: Any, code: int, msg: str, headers: Message, newurl: str
    ) -> None:
        return None


def fetch_manifest(version: str, timeout: float = 5, retries: int = 0) -> bytes:
    if not math.isfinite(timeout) or not 0.1 <= timeout <= 30 or not 0 <= retries <= 2:
        raise DetectionError("Timeout must be 0.1..30 seconds and retries 0..2.")
    url = manifest_url(version)
    opener = build_opener(
        ProxyHandler({}), NoRedirect(), HTTPSHandler(context=ssl.create_default_context())
    )
    request = Request(
        url, headers={"User-Agent": "node2shell-detector/1.0", "Accept-Encoding": "identity"}
    )
    for attempt in range(retries + 1):
        try:
            with opener.open(request, timeout=timeout) as response:
                if response.status != 200 or response.geturl() != url:
                    raise DetectionError(
                        "Official metadata response had an unexpected status or URL."
                    )
                if response.headers.get("Content-Encoding", "identity").lower() != "identity":
                    raise DetectionError("Compressed checksum metadata is not accepted.")
                payload = response.read(MAX_MANIFEST_BYTES + 1)
                if not payload or len(payload) > MAX_MANIFEST_BYTES:
                    raise DetectionError("Official checksum response is empty or too large.")
                return bytes(payload)
        except HTTPError as exc:
            exc.close()
            raise DetectionError(
                "Official checksum lookup returned HTTP "
                + str(exc.code)
                + "; verify the release or retry later. Redirects are refused."
            ) from None
        except (URLError, OSError, http.client.HTTPException) as exc:
            reason = exc.reason if isinstance(exc, URLError) else exc
            if isinstance(reason, ssl.SSLError):
                raise DetectionError(
                    "TLS verification failed for official metadata; check certificates."
                ) from None
            if attempt == retries:
                raise DetectionError(
                    "Official checksum lookup failed (DNS, timeout, connection or HTTP framing)."
                ) from None
            time.sleep(0.25 * (attempt + 1))
    raise DetectionError("Official checksum lookup did not complete.")

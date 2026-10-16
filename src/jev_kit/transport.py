"""Transport interface, the labeled mock, and (later) the live HTTPS transport.

The transport is the one injectable dependency (spec Implementation Decisions). Mock
provenance is a property of the transport object, never of the response body, so a scripted
body can never claim to be real (spec story 30; finding R01). The live transport is a private
opener that refuses redirects and never forwards the key (spec story 57; finding R04); it is
implemented in a later slice.
"""

from __future__ import annotations

import email.utils
import math
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import ClassVar, Protocol, runtime_checkable

from jev_kit.deadline import Deadline
from jev_kit.errors import FailReason, fail_reason_for_status


@dataclass(frozen=True)
class TransportResponse:
    status: int
    headers: Mapping[str, str]
    body: bytes


@dataclass(frozen=True)
class TransportFailure:
    reason: FailReason
    detail: str  # short and safe; never a raw server body or matched content
    retry_after: float | None = None  # seconds the server asked us to wait, if any


TransportResult = TransportResponse | TransportFailure


@runtime_checkable
class Transport(Protocol):
    is_mock: ClassVar[bool]

    def send(self, body: bytes, deadline: Deadline) -> TransportResult: ...


@dataclass
class MockTransport:
    """A scripted, recording transport for tests. Never touches the network.

    ``outcomes`` are returned in order, one per ``send``. Every request body is recorded so
    tests can assert exactly one request per call with the exact question set, and that the
    key never appears in the bytes. ``is_mock`` is a fixed class attribute, never a
    constructor field, so a scripted mock can never claim non-mock provenance and reach an
    effective accept (finding C01, spec story 32). Selection and cursor advance are locked so
    a shared mock under a thread pool consumes each scripted outcome exactly once (C22).
    """

    is_mock: ClassVar[bool] = True

    outcomes: list[TransportResult]
    requests: list[bytes] = field(default_factory=list)
    _index: int = 0
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def send(self, body: bytes, deadline: Deadline) -> TransportResult:
        with self._lock:
            self.requests.append(body)
            if self._index >= len(self.outcomes):
                return TransportFailure(FailReason.TRANSPORT, "mock_exhausted")
            outcome = self.outcomes[self._index]
            self._index += 1
            return outcome

    @classmethod
    def replying(
        cls, status: int, body: bytes, headers: Mapping[str, str] | None = None
    ) -> MockTransport:
        return cls(outcomes=[TransportResponse(status, dict(headers or {}), body)])


DEFAULT_ENDPOINT = "https://api.typesafe.ai/v1/systemone"

#: Path appended to a configured base URL to reach the same SystemOne route on another host.
SYSTEMONE_PATH = "/v1/systemone"

#: Hosts this kit will send a live request to. The endpoint is fixed by default (finding C23),
#: so an allowlist is only needed once a base URL is configurable at all; it is the mechanism
#: that keeps "configurable" from meaning "exfiltrate the API key to any host".
#:
#: The operator's own gateway belongs here rather than being trusted implicitly, because the
#: Authorization header is attached to whatever host is configured: an attacker who can set this
#: variable can already read the key, but a typo or a copy-pasted URL should not silently ship
#: the key somewhere unintended. Overriding the allowlist is itself explicit and audited.
DEFAULT_ENDPOINT_ALLOWLIST = ("api.typesafe.ai",)

#: The Flex AI gateway's SystemOne proxy. It speaks the same protocol on the same path, so the
#: only differences from the default endpoint are the host and the model id it expects. Listed
#: as a named constant so an operator recognises it rather than pasting a hostname from a
#: document into configuration.
FLEX_GATEWAY_BASE_URL = "https://litellm.shared.getflex.org/typesafe"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse every redirect. The default handler would forward a normally added
    Authorization header to the new host (finding R04)."""

    def redirect_request(self, *args: object, **kwargs: object) -> None:
        return None


def _build_opener() -> urllib.request.OpenerDirector:
    # ProxyHandler({}) ignores environment proxies unless one is configured explicitly.
    return urllib.request.build_opener(
        _NoRedirect(),
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=ssl.create_default_context()),
    )


MAX_RESPONSE_BYTES = 1_048_576  # 1 MiB cap on any response body read


class LiveTransport:
    """POST to the HTTPS endpoint with bearer auth. One attempt per send; the engine
    owns retries, backoff and the rate budget. The destination is fixed by default (finding
    C23); redirects are refused; the key is attached only as a request header and never appears
    in the body, digests or diagnostics.

    ``base_url`` re-points the request at another host that serves the same SystemOne route,
    which is what lets an operator route through their own gateway. It is refused unless the
    host is on ``endpoint_allowlist``, so the key cannot be sent to an arbitrary destination by
    setting one variable. Passing ``base_url=None`` reproduces the shipped behaviour exactly.
    """

    is_mock: ClassVar[bool] = False

    def __init__(
        self,
        api_key: str,
        base_url: str | None = None,
        endpoint_allowlist: Sequence[str] | None = None,
    ) -> None:
        self._api_key = api_key
        if base_url is None:
            self._endpoint = DEFAULT_ENDPOINT
        else:
            self._endpoint = _resolve_endpoint(base_url, endpoint_allowlist)
        self._opener = _build_opener()

    def send(self, body: bytes, deadline: Deadline) -> TransportResult:
        request = urllib.request.Request(self._endpoint, data=body, method="POST")
        request.add_header("Content-Type", "application/json")
        request.add_header("Authorization", f"Bearer {self._api_key}")
        timeout = deadline.remaining_for_work()
        if timeout <= 0:
            return TransportFailure(FailReason.TIMEOUT, "deadline_before_send")
        try:
            with self._opener.open(request, timeout=timeout) as response:
                status = response.status
                headers = {k.lower(): v for k, v in response.headers.items()}
                payload = response.read(MAX_RESPONSE_BYTES + 1)
            if len(payload) > MAX_RESPONSE_BYTES:
                return TransportFailure(FailReason.RESPONSE_MALFORMED, "response_too_large")
            return TransportResponse(status, headers, payload)
        except urllib.error.HTTPError as exc:
            headers = {k.lower(): v for k, v in exc.headers.items()} if exc.headers else {}
            try:
                exc.read(MAX_RESPONSE_BYTES)  # drain and discard; body never surfaced
            except OSError:
                pass
            finally:
                exc.close()
            if 300 <= exc.code < 400:
                return TransportFailure(FailReason.REDIRECT_REFUSED, "redirect_refused")
            return _http_error_result(exc.code, headers)
        except TimeoutError:
            return TransportFailure(FailReason.TIMEOUT, "read_timeout")
        except (urllib.error.URLError, OSError, ValueError):
            return TransportFailure(FailReason.TRANSPORT, "transport_error")


class EndpointNotAllowed(ValueError):
    """A configured base URL whose host is not on the allowlist. Raised rather than returned
    as a transport failure: it is a configuration error, and the engine must refuse to send
    rather than retry against a destination it will never be permitted to use."""


def _resolve_endpoint(base_url: str, endpoint_allowlist: Sequence[str] | None) -> str:
    """Build the request URL for a configured base URL, refusing a host off the allowlist.

    Fails closed on anything unexpected: a non-HTTPS scheme, a missing host, a host that is not
    on the allowlist, or a base URL carrying userinfo, a query or a fragment. Each of those
    would either downgrade the connection or send the bearer token somewhere other than the
    intended route, so none is a warning.
    """
    allowed = tuple(endpoint_allowlist) if endpoint_allowlist else DEFAULT_ENDPOINT_ALLOWLIST
    try:
        parsed = urllib.parse.urlsplit(base_url.strip())
    except ValueError as exc:
        raise EndpointNotAllowed("base_url_unparseable") from exc
    if parsed.scheme != "https":
        raise EndpointNotAllowed("base_url_not_https")
    if not parsed.hostname:
        raise EndpointNotAllowed("base_url_no_host")
    if parsed.username or parsed.password:
        raise EndpointNotAllowed("base_url_has_userinfo")
    if parsed.query or parsed.fragment:
        raise EndpointNotAllowed("base_url_has_query_or_fragment")
    host = parsed.hostname.lower()
    if host not in {entry.strip().lower() for entry in allowed}:
        raise EndpointNotAllowed("base_url_host_not_allowed")
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path.rstrip('/')}{SYSTEMONE_PATH}"


def parse_retry_after(headers: Mapping[str, str]) -> float | None:
    """Parse retry-after-ms (preferred) or Retry-After (seconds or HTTP date). Malformed
    values are ignored (return None), so the engine falls back to its own backoff."""
    ms = headers.get("retry-after-ms")
    if ms is not None:
        try:
            value = float(ms)
            # A finite, non-negative number only: "inf"/"nan" parse as floats but must never
            # become an unbounded or undefined delay (finding H19).
            if math.isfinite(value) and value >= 0:
                return value / 1000.0
        except ValueError:
            pass
    ra = headers.get("retry-after")
    if ra is not None:
        try:
            value = float(ra)
            if math.isfinite(value) and value >= 0:
                return value
        except ValueError:
            try:
                parsed = email.utils.parsedate_to_datetime(ra)
            except (ValueError, TypeError):
                # parsedate_to_datetime raises on an unparseable date on modern Python; a
                # malformed header must be ignored, not propagated (finding H19).
                return None
            if parsed is not None:
                delta = parsed.timestamp() - time.time()
                return max(0.0, delta)
    return None


def _http_error_result(status: int, headers: Mapping[str, str]) -> TransportResult:
    # A non-2xx status is a failure, never a body to validate as an answer (story 37).
    if 200 <= status < 300:
        return TransportFailure(FailReason.TRANSPORT, "unexpected_2xx_error")
    return TransportFailure(
        fail_reason_for_status(status), f"http_{status}", retry_after=parse_retry_after(headers)
    )

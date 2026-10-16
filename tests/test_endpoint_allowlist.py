"""Endpoint selection and its allowlist (finding C23, extended).

The shipped behaviour is unchanged: with no configuration the transport posts to the fixed
default endpoint, and `test_live_transport_endpoint_is_fixed` still pins that. What these
tests cover is the case that test does not: an operator who *does* configure a base URL.

The property that matters is that "configurable" cannot become "exfiltrate the key". The
Authorization header is attached to whatever host is configured, so a base URL off the
allowlist is refused at construction time rather than warned about, and every shape that could
redirect or downgrade the request (a non-HTTPS scheme, userinfo, a query, a fragment) is
refused on the same terms. Each case below is one way to reach a host other than the intended
one.
"""

from __future__ import annotations

import pytest

from jev_kit.transport import (
    DEFAULT_ENDPOINT,
    FLEX_GATEWAY_BASE_URL,
    SYSTEMONE_PATH,
    EndpointNotAllowed,
    LiveTransport,
)


def test_no_base_url_is_the_shipped_default() -> None:
    # The default must stay exactly what it was: an unset variable cannot move a live request.
    assert LiveTransport("K")._endpoint == DEFAULT_ENDPOINT


def test_allowlisted_base_url_resolves_to_the_systemone_route() -> None:
    transport = LiveTransport(
        "K", base_url=FLEX_GATEWAY_BASE_URL, endpoint_allowlist=("litellm.shared.getflex.org",)
    )
    assert transport._endpoint == f"{FLEX_GATEWAY_BASE_URL}{SYSTEMONE_PATH}"


def test_trailing_slash_does_not_double_the_separator() -> None:
    transport = LiveTransport(
        "K",
        base_url=FLEX_GATEWAY_BASE_URL + "/",
        endpoint_allowlist=("litellm.shared.getflex.org",),
    )
    assert transport._endpoint == f"{FLEX_GATEWAY_BASE_URL}{SYSTEMONE_PATH}"


def test_host_off_the_allowlist_is_refused() -> None:
    # The whole point: a configured base URL is not trusted just because it was configured.
    with pytest.raises(EndpointNotAllowed):
        LiveTransport("K", base_url="https://evil.example/typesafe")


def test_the_allowlist_replaces_the_default_rather_than_adding_to_it() -> None:
    # A narrowed allowlist must actually narrow. If the default host stayed permitted, an
    # operator could not restrict egress to their gateway by configuring one.
    with pytest.raises(EndpointNotAllowed):
        LiveTransport("K", base_url="https://api.typesafe.ai", endpoint_allowlist=("only.example",))


@pytest.mark.parametrize(
    "base_url",
    [
        "http://litellm.shared.getflex.org/typesafe",  # downgraded scheme
        "https://user:pass@litellm.shared.getflex.org/typesafe",  # userinfo
        "https://litellm.shared.getflex.org/typesafe?x=1",  # query
        "https://litellm.shared.getflex.org/typesafe#frag",  # fragment
        "https:///typesafe",  # no host
        "not-a-url",  # no scheme or host
        "",  # blank
    ],
)
def test_shapes_that_could_misroute_are_refused(base_url: str) -> None:
    # Each of these either downgrades the connection or sends the bearer token somewhere other
    # than the intended route, so none is a warning.
    with pytest.raises(EndpointNotAllowed):
        LiveTransport("K", base_url=base_url, endpoint_allowlist=("litellm.shared.getflex.org",))


def test_host_match_is_case_insensitive() -> None:
    # A hostname is case-insensitive, so a mixed-case allowlist entry must still match rather
    # than fail closed on a technicality the operator cannot see.
    transport = LiveTransport(
        "K", base_url="https://LiteLLM.Shared.GetFlex.org/typesafe",
        endpoint_allowlist=("litellm.shared.getflex.org",),
    )
    assert transport._endpoint.startswith("https://LiteLLM.Shared.GetFlex.org")


def test_env_absent_or_blank_means_the_default() -> None:
    # Exercised through the real config path, so the wiring is covered rather than the helper.
    from jev_kit.engine import _config_from_env

    for value in ("", "   "):
        import os

        os.environ["JEV_KIT_BASE_URL"] = value
        try:
            assert _config_from_env().base_url is None
        finally:
            del os.environ["JEV_KIT_BASE_URL"]
    assert _config_from_env().base_url is None

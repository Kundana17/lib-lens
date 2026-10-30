import pytest
import requests

from lib_lens.clients.osv_client import query_osv_batch


def _dependency(name="alpha", version="1.2.3"):
    return {
        "name": name,
        "version": version,
        "dependency_type": "direct",
        "path": f"node_modules/{name}",
    }


def _response(payload):
    class Response:
        def raise_for_status(self):
            pass

        def json(self):
            return payload

    return Response()


def test_sends_npm_batch_query_payload(monkeypatch):
    dependencies = [_dependency("alpha", "1.2.3"), _dependency("@scope/beta", "4.5.6")]
    captured = {}

    def fake_post(url, **kwargs):
        captured["url"] = url
        captured.update(kwargs)
        return _response({"results": [{}, {}]})

    monkeypatch.setattr("lib_lens.clients.osv_client.requests.post", fake_post)

    assert query_osv_batch(dependencies) == []
    assert captured == {
        "url": "https://api.osv.dev/v1/querybatch",
        "json": {
            "queries": [
                {
                    "package": {"name": "alpha", "ecosystem": "npm"},
                    "version": "1.2.3",
                },
                {
                    "package": {"name": "@scope/beta", "ecosystem": "npm"},
                    "version": "4.5.6",
                },
            ]
        },
        "timeout": 10,
    }


def test_maps_advisories_to_their_dependencies(monkeypatch):
    alpha = _dependency("alpha")
    beta = _dependency("beta", "2.0.0")
    advisory = {"id": "GHSA-alpha", "summary": "Alpha issue"}

    monkeypatch.setattr(
        "lib_lens.clients.osv_client.requests.post",
        lambda *args, **kwargs: _response({"results": [{"vulns": [advisory]}, {}]}),
    )

    assert query_osv_batch([alpha, beta]) == [
        {"dependency": alpha, "vulnerability": advisory}
    ]


def test_returns_multiple_vulnerabilities_for_one_dependency(monkeypatch):
    dependency = _dependency()
    first = {"id": "GHSA-one"}
    second = {"id": "GHSA-two"}

    monkeypatch.setattr(
        "lib_lens.clients.osv_client.requests.post",
        lambda *args, **kwargs: _response({"results": [{"vulns": [first, second]}]}),
    )

    assert query_osv_batch([dependency]) == [
        {"dependency": dependency, "vulnerability": first},
        {"dependency": dependency, "vulnerability": second},
    ]


def test_empty_input_does_not_make_an_http_request(monkeypatch):
    def unexpected_post(*args, **kwargs):
        pytest.fail("requests.post should not be called for empty dependencies")

    monkeypatch.setattr("lib_lens.clients.osv_client.requests.post", unexpected_post)

    assert query_osv_batch([]) == []


def test_raises_clear_error_for_http_failure(monkeypatch):
    class ErrorResponse:
        def raise_for_status(self):
            raise requests.HTTPError("503 Server Error")

    monkeypatch.setattr(
        "lib_lens.clients.osv_client.requests.post",
        lambda *args, **kwargs: ErrorResponse(),
    )

    with pytest.raises(RuntimeError, match="HTTP error"):
        query_osv_batch([_dependency()])


def test_raises_clear_error_for_timeout(monkeypatch):
    def timeout(*args, **kwargs):
        raise requests.Timeout("request timed out")

    monkeypatch.setattr("lib_lens.clients.osv_client.requests.post", timeout)

    with pytest.raises(RuntimeError, match="timed out"):
        query_osv_batch([_dependency()])


@pytest.mark.parametrize(
    "response_factory, message",
    [
        (
            lambda: type(
                "Response",
                (),
                {
                    "raise_for_status": lambda self: None,
                    "json": lambda self: (_ for _ in ()).throw(ValueError("bad JSON")),
                },
            )(),
            "invalid JSON",
        ),
        (lambda: _response({}), "missing 'results' list"),
        (lambda: _response({"results": []}), "result count does not match"),
        (lambda: _response({"results": ["not a result"]}), "must be a dictionary"),
        (lambda: _response({"results": [{"vulns": "not a list"}]}), "'vulns' must be a list"),
    ],
)
def test_rejects_malformed_responses(monkeypatch, response_factory, message):
    monkeypatch.setattr(
        "lib_lens.clients.osv_client.requests.post",
        lambda *args, **kwargs: response_factory(),
    )

    with pytest.raises(ValueError, match=message):
        query_osv_batch([_dependency()])


def test_dependencies_without_vulnerabilities_are_omitted(monkeypatch):
    monkeypatch.setattr(
        "lib_lens.clients.osv_client.requests.post",
        lambda *args, **kwargs: _response({"results": [{"vulns": []}]}),
    )

    assert query_osv_batch([_dependency()]) == []

import pytest
import requests

from lib_lens.clients.deps_dev_client import get_package_version_info


def _response(payload):
    class Response:
        def raise_for_status(self):
            pass

        def json(self):
            return payload

    return Response()


def _payload(name="alpha", versions=None):
    return {
        "packageKey": {"system": "NPM", "name": name},
        "versions": [] if versions is None else versions,
    }


def _version(version, **metadata):
    return {"versionKey": {"system": "NPM", "name": "alpha", "version": version}, **metadata}


def test_returns_package_versions_and_identifies_default_without_sorting(monkeypatch):
    payload = _payload(
        versions=[
            _version("10.0.0", isDefault=False),
            _version("2.0.0", isDefault=True),
        ]
    )
    monkeypatch.setattr(
        "lib_lens.clients.deps_dev_client.requests.get",
        lambda *args, **kwargs: _response(payload),
    )

    assert get_package_version_info("alpha") == {
        "package_name": "alpha",
        "versions": [
            {"version": "10.0.0", "isDeprecated": False, "deprecatedReason": None},
            {"version": "2.0.0", "isDeprecated": False, "deprecatedReason": None},
        ],
        "default_version": "2.0.0",
    }


def test_url_encodes_scoped_package_names(monkeypatch):
    captured = {}

    def fake_get(url, **kwargs):
        captured["url"] = url
        captured.update(kwargs)
        return _response(_payload("@babel/core"))

    monkeypatch.setattr("lib_lens.clients.deps_dev_client.requests.get", fake_get)

    assert get_package_version_info("@babel/core")["package_name"] == "@babel/core"
    assert captured == {
        "url": "https://api.deps.dev/v3/systems/npm/packages/%40babel%2Fcore",
        "timeout": 10,
    }


def test_preserves_deprecated_version_metadata(monkeypatch):
    payload = _payload(versions=[_version("1.0.0", isDeprecated=True, deprecatedReason="Use 2.0")])
    monkeypatch.setattr(
        "lib_lens.clients.deps_dev_client.requests.get",
        lambda *args, **kwargs: _response(payload),
    )

    assert get_package_version_info("alpha")["versions"] == [
        {"version": "1.0.0", "isDeprecated": True, "deprecatedReason": "Use 2.0"}
    ]


def test_returns_none_when_no_default_version_is_marked(monkeypatch):
    monkeypatch.setattr(
        "lib_lens.clients.deps_dev_client.requests.get",
        lambda *args, **kwargs: _response(_payload(versions=[_version("1.0.0")])),
    )

    assert get_package_version_info("alpha")["default_version"] is None


def test_returns_empty_versions(monkeypatch):
    monkeypatch.setattr(
        "lib_lens.clients.deps_dev_client.requests.get",
        lambda *args, **kwargs: _response(_payload()),
    )

    assert get_package_version_info("alpha") == {
        "package_name": "alpha",
        "versions": [],
        "default_version": None,
    }


def test_raises_clear_error_for_http_failure(monkeypatch):
    class ErrorResponse:
        def raise_for_status(self):
            raise requests.HTTPError("404")

    monkeypatch.setattr(
        "lib_lens.clients.deps_dev_client.requests.get",
        lambda *args, **kwargs: ErrorResponse(),
    )

    with pytest.raises(RuntimeError, match="HTTP error"):
        get_package_version_info("alpha")


def test_raises_clear_error_for_timeout(monkeypatch):
    def timeout(*args, **kwargs):
        raise requests.Timeout()

    monkeypatch.setattr("lib_lens.clients.deps_dev_client.requests.get", timeout)

    with pytest.raises(RuntimeError, match="timed out"):
        get_package_version_info("alpha")


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
        (lambda: _response([]), "expected an object"),
        (lambda: _response({"versions": []}), "missing packageKey"),
        (lambda: _response(_payload(versions="bad")), "'versions' must be a list"),
        (lambda: _response(_payload(versions=[{}])), "missing versionKey"),
    ],
)
def test_rejects_malformed_responses(monkeypatch, response_factory, message):
    monkeypatch.setattr(
        "lib_lens.clients.deps_dev_client.requests.get",
        lambda *args, **kwargs: response_factory(),
    )

    with pytest.raises(ValueError, match=message):
        get_package_version_info("alpha")

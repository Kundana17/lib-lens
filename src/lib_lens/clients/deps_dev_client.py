"""Client for retrieving npm package version metadata from deps.dev."""

from __future__ import annotations

from urllib.parse import quote

import requests


_API_URL = "https://api.deps.dev/v3/systems/npm/packages"
_REQUEST_TIMEOUT_SECONDS = 10


def get_package_version_info(package_name: str) -> dict:
    """Return version and deprecation metadata for an npm package."""
    if not isinstance(package_name, str) or not package_name:
        raise ValueError("package_name must be a non-empty string")

    encoded_name = quote(package_name, safe="")
    try:
        response = requests.get(
            f"{_API_URL}/{encoded_name}", timeout=_REQUEST_TIMEOUT_SECONDS
        )
        response.raise_for_status()
    except requests.Timeout as exc:
        raise RuntimeError("deps.dev request timed out") from exc
    except requests.HTTPError as exc:
        raise RuntimeError("deps.dev request failed with an HTTP error") from exc
    except requests.RequestException as exc:
        raise RuntimeError("deps.dev request failed") from exc

    try:
        payload = response.json()
    except ValueError as exc:
        raise ValueError("malformed deps.dev response: invalid JSON") from exc

    if not isinstance(payload, dict):
        raise ValueError("malformed deps.dev response: expected an object")
    package_key = payload.get("packageKey")
    if not isinstance(package_key, dict):
        raise ValueError("malformed deps.dev response: missing packageKey")
    returned_name = package_key.get("name")
    if not isinstance(returned_name, str) or not returned_name:
        raise ValueError("malformed deps.dev response: invalid packageKey name")

    api_versions = payload.get("versions")
    if not isinstance(api_versions, list):
        raise ValueError("malformed deps.dev response: 'versions' must be a list")

    versions: list[dict] = []
    default_versions: list[str] = []
    for entry in api_versions:
        if not isinstance(entry, dict):
            raise ValueError("malformed deps.dev response: version entry must be an object")
        version_key = entry.get("versionKey")
        if not isinstance(version_key, dict):
            raise ValueError("malformed deps.dev response: missing versionKey")
        version = version_key.get("version")
        if not isinstance(version, str) or not version:
            raise ValueError("malformed deps.dev response: invalid version string")

        is_default = entry.get("isDefault", False)
        is_deprecated = entry.get("isDeprecated", False)
        deprecated_reason = entry.get("deprecatedReason")
        if not isinstance(is_default, bool) or not isinstance(is_deprecated, bool):
            raise ValueError("malformed deps.dev response: version flags must be booleans")
        if deprecated_reason is not None and not isinstance(deprecated_reason, str):
            raise ValueError(
                "malformed deps.dev response: deprecatedReason must be a string"
            )

        versions.append(
            {
                "version": version,
                "isDeprecated": is_deprecated,
                "deprecatedReason": deprecated_reason,
            }
        )
        if is_default:
            default_versions.append(version)

    if len(default_versions) > 1:
        raise ValueError("malformed deps.dev response: multiple default versions")

    return {
        "package_name": returned_name,
        "versions": versions,
        "default_version": default_versions[0] if default_versions else None,
    }

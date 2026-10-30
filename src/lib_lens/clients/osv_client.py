"""Client for querying npm package vulnerabilities from the OSV API."""

from __future__ import annotations

import requests


_OSV_BATCH_QUERY_URL = "https://api.osv.dev/v1/querybatch"
_REQUEST_TIMEOUT_SECONDS = 10


def query_osv_batch(dependencies: list[dict]) -> list[dict]:
    """Return OSV vulnerabilities paired with their originating dependency.

    Each returned item has ``dependency`` and ``vulnerability`` keys. The
    vulnerability value is the unmodified advisory record returned by OSV.
    """
    if not isinstance(dependencies, list):
        raise ValueError("dependencies must be a list of dependency records")
    if not dependencies:
        return []

    queries = []
    for index, dependency in enumerate(dependencies):
        if not isinstance(dependency, dict):
            raise ValueError(f"dependency at index {index} must be a dictionary")
        name = dependency.get("name")
        version = dependency.get("version")
        if not isinstance(name, str) or not name:
            raise ValueError(f"dependency at index {index} has an invalid name")
        if not isinstance(version, str) or not version:
            raise ValueError(f"dependency at index {index} has an invalid version")
        queries.append(
            {
                "package": {"name": name, "ecosystem": "npm"},
                "version": version,
            }
        )

    try:
        response = requests.post(
            _OSV_BATCH_QUERY_URL,
            json={"queries": queries},
            timeout=_REQUEST_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
    except requests.Timeout as exc:
        raise RuntimeError("OSV batch query timed out") from exc
    except requests.HTTPError as exc:
        raise RuntimeError("OSV batch query failed with an HTTP error") from exc
    except requests.RequestException as exc:
        raise RuntimeError("OSV batch query failed") from exc

    try:
        payload = response.json()
    except ValueError as exc:
        raise ValueError("malformed OSV response: invalid JSON") from exc

    if not isinstance(payload, dict) or not isinstance(payload.get("results"), list):
        raise ValueError("malformed OSV response: missing 'results' list")

    results = payload["results"]
    if len(results) != len(dependencies):
        raise ValueError("malformed OSV response: result count does not match query count")

    matches: list[dict] = []
    for dependency, result in zip(dependencies, results, strict=True):
        if not isinstance(result, dict):
            raise ValueError("malformed OSV response: each result must be a dictionary")
        vulnerabilities = result.get("vulns", [])
        if not isinstance(vulnerabilities, list):
            raise ValueError("malformed OSV response: 'vulns' must be a list")
        for vulnerability in vulnerabilities:
            if not isinstance(vulnerability, dict):
                raise ValueError("malformed OSV response: vulnerability must be a dictionary")
            matches.append(
                {"dependency": dependency, "vulnerability": vulnerability}
            )

    return matches

"""Combine dependency, vulnerability, and package-version information."""

from __future__ import annotations

from packaging.version import InvalidVersion, Version

from lib_lens.clients.deps_dev_client import get_package_version_info
from lib_lens.clients.osv_client import query_osv_batch


def analyze_dependencies(dependencies: list[dict]) -> list[dict]:
    """Analyze parser dependency records while retaining partial API results."""
    if not isinstance(dependencies, list):
        raise ValueError("dependencies must be a list of dependency records")
    records = [_validate(dependency, index) for index, dependency in enumerate(dependencies)]
    vulnerabilities = [[] for _ in records]
    osv_error = None
    try:
        _assign_vulnerabilities(dependencies, query_osv_batch(dependencies), vulnerabilities)
    except Exception as exc:
        osv_error = f"osv: {exc}"

    version_data, deps_errors = {}, {}
    for name in dict.fromkeys(record["name"] for record in records):
        try:
            version_data[name] = get_package_version_info(name)
        except Exception as exc:
            deps_errors[name] = f"deps.dev: {exc}"

    result = []
    for record, advisories in zip(records, vulnerabilities, strict=True):
        errors = ([osv_error] if osv_error else []) + ([deps_errors[record["name"]]] if record["name"] in deps_errors else [])
        latest = deprecated = reason = update = None
        info = version_data.get(record["name"])
        if info is not None:
            latest = info["default_version"]
            installed = next((item for item in info["versions"] if item["version"] == record["version"]), None)
            if installed is not None:
                deprecated, reason = installed["isDeprecated"], installed["deprecatedReason"]
            if latest is not None:
                try:
                    update = Version(record["version"]) < Version(latest)
                except InvalidVersion as exc:
                    errors.append(f"version comparison failed: {exc}")
        result.append({
            "name": record["name"], "installed_version": record["version"],
            "latest_version": latest, "update_available": update,
            "is_deprecated": deprecated, "deprecated_reason": reason,
            "vulnerabilities": advisories, "analysis_errors": errors,
        })
    return result


def _validate(dependency: dict, index: int) -> dict:
    if not isinstance(dependency, dict):
        raise ValueError(f"dependency at index {index} must be a dictionary")
    fields = {field: dependency.get(field) for field in ("name", "version", "path")}
    if any(not isinstance(value, str) or not value for value in fields.values()):
        raise ValueError(f"dependency at index {index} has invalid name, version, or path")
    return fields


def _assign_vulnerabilities(dependencies: list[dict], matches: list[dict], output: list[list[dict]]) -> None:
    by_identity = {id(dependency): index for index, dependency in enumerate(dependencies)}
    by_key = {(item["name"], item["version"], item["path"]): index for index, item in enumerate(dependencies)}
    for match in matches:
        if not isinstance(match, dict) or not isinstance(match.get("dependency"), dict) or not isinstance(match.get("vulnerability"), dict):
            raise ValueError("malformed OSV match")
        dependency = match["dependency"]
        index = by_identity.get(id(dependency), by_key.get((dependency.get("name"), dependency.get("version"), dependency.get("path"))))
        if index is not None:
            output[index].append(match["vulnerability"])

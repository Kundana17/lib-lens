"""Parser for npm package-lock.json files (lockfile versions 2 and 3)."""

from __future__ import annotations


_ROOT_DEPENDENCY_FIELDS = (
    "dependencies",
    "devDependencies",
    "optionalDependencies",
    "peerDependencies",
)


def parse_package_lock(data: dict) -> list[dict]:
    """Return installed packages recorded in an npm v2 or v3 lockfile.

    Each result contains ``name``, ``version``, ``dependency_type`` (``direct``
    or ``transitive``), and the package's lockfile ``path``.
    """
    if not isinstance(data, dict):
        raise ValueError("package-lock data must be a dictionary")

    lockfile_version = data.get("lockfileVersion")
    if isinstance(lockfile_version, bool) or lockfile_version not in (2, 3):
        raise ValueError(
            "unsupported package-lock version; only lockfile versions 2 and 3 are supported"
        )

    packages = data.get("packages")
    if not isinstance(packages, dict):
        raise ValueError("malformed package-lock: 'packages' must be a dictionary")

    root_package = packages.get("")
    if not isinstance(root_package, dict):
        raise ValueError("malformed package-lock: missing root package entry")
    if any(not isinstance(package_path, str) for package_path in packages):
        raise ValueError("malformed package-lock: package paths must be strings")

    direct_dependencies = _root_dependency_names(root_package)
    parsed: list[dict] = []

    for package_path in sorted(packages):
        if package_path == "":
            continue

        entry = packages[package_path]
        if not isinstance(entry, dict):
            raise ValueError(
                f"malformed package-lock: package entry '{package_path}' must be a dictionary"
            )

        # npm represents workspaces at node_modules/<name> as links. Entries
        # outside node_modules are workspace metadata rather than installations.
        if entry.get("link") is True or not package_path.startswith("node_modules/"):
            continue

        name = _package_name_from_path(package_path)
        version = entry.get("version")
        if not isinstance(version, str) or not version:
            raise ValueError(
                f"malformed package-lock: package '{package_path}' has no installed version"
            )

        is_direct = (
            name in direct_dependencies
            and package_path == f"node_modules/{name}"
        )
        parsed.append(
            {
                "name": name,
                "version": version,
                "dependency_type": "direct" if is_direct else "transitive",
                "path": package_path,
            }
        )

    return parsed


def _root_dependency_names(root_package: dict) -> set[str]:
    """Collect dependency names declared by the root package."""
    names: set[str] = set()
    for field in _ROOT_DEPENDENCY_FIELDS:
        declarations = root_package.get(field)
        if declarations is None:
            continue
        if not isinstance(declarations, dict):
            raise ValueError(
                f"malformed package-lock: root '{field}' must be a dictionary"
            )
        for name in declarations:
            if not isinstance(name, str) or not name:
                raise ValueError(
                    f"malformed package-lock: root '{field}' contains an invalid package name"
                )
            names.add(name)
    return names


def _package_name_from_path(package_path: str) -> str:
    """Extract a package name from an npm installation path."""
    leaf = package_path.rsplit("node_modules/", 1)[-1]
    parts = leaf.split("/")
    if (parts[0].startswith("@") and len(parts) == 2 and parts[1]) or (
        not parts[0].startswith("@") and len(parts) == 1 and parts[0]
    ):
        return leaf
    raise ValueError(
        f"malformed package-lock: invalid package path '{package_path}'"
    )

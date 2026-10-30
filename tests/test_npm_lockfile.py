import pytest

from lib_lens.parsers.npm_lockfile import parse_package_lock


def test_parses_valid_lockfile_version_2():
    data = {
        "lockfileVersion": 2,
        "packages": {
            "": {"dependencies": {"alpha": "^1.0.0"}},
            "node_modules/alpha": {"version": "1.2.3"},
        },
    }

    assert parse_package_lock(data) == [
        {
            "name": "alpha",
            "version": "1.2.3",
            "dependency_type": "direct",
            "path": "node_modules/alpha",
        }
    ]


def test_parses_valid_lockfile_version_3_with_direct_and_transitive_packages():
    data = {
        "lockfileVersion": 3,
        "packages": {
            "": {"dependencies": {"alpha": "^1.0.0"}},
            "node_modules/alpha": {"version": "1.2.3"},
            "node_modules/beta": {"version": "4.5.6"},
        },
    }

    packages = parse_package_lock(data)

    assert packages[0]["dependency_type"] == "direct"
    assert packages[1]["dependency_type"] == "transitive"
    assert {package["name"] for package in packages} == {"alpha", "beta"}


def test_handles_scoped_and_nested_packages():
    data = {
        "lockfileVersion": 3,
        "packages": {
            "": {"dependencies": {"@babel/core": "^7.0.0"}},
            "node_modules/@babel/core": {"version": "7.25.0"},
            "node_modules/@babel/core/node_modules/semver": {"version": "7.6.3"},
        },
    }

    assert parse_package_lock(data) == [
        {
            "name": "@babel/core",
            "version": "7.25.0",
            "dependency_type": "direct",
            "path": "node_modules/@babel/core",
        },
        {
            "name": "semver",
            "version": "7.6.3",
            "dependency_type": "transitive",
            "path": "node_modules/@babel/core/node_modules/semver",
        },
    ]


def test_skips_root_and_workspace_link_entries():
    data = {
        "lockfileVersion": 3,
        "packages": {
            "": {"dependencies": {"alpha": "^1.0.0"}},
            "packages/workspace": {"version": "1.0.0"},
            "node_modules/workspace": {"link": True, "resolved": "packages/workspace"},
            "node_modules/alpha": {"version": "1.0.0"},
        },
    }

    assert parse_package_lock(data) == [
        {
            "name": "alpha",
            "version": "1.0.0",
            "dependency_type": "direct",
            "path": "node_modules/alpha",
        }
    ]


@pytest.mark.parametrize("lockfile_version", [1, 4, "3", None])
def test_rejects_unsupported_lockfile_versions(lockfile_version):
    data = {"lockfileVersion": lockfile_version, "packages": {"": {}}}

    with pytest.raises(ValueError, match="unsupported package-lock version"):
        parse_package_lock(data)


@pytest.mark.parametrize(
    "data, message",
    [
        ({"lockfileVersion": 3}, "'packages' must be a dictionary"),
        ({"lockfileVersion": 3, "packages": {}}, "missing root package entry"),
        (
            {"lockfileVersion": 3, "packages": {"": {}, "node_modules/alpha": {}}},
            "has no installed version",
        ),
        (
            {"lockfileVersion": 3, "packages": {"": {}, "node_modules/alpha": "bad"}},
            "must be a dictionary",
        ),
    ],
)
def test_rejects_malformed_or_missing_package_data(data, message):
    with pytest.raises(ValueError, match=message):
        parse_package_lock(data)


def test_returns_packages_in_deterministic_path_order():
    data = {
        "lockfileVersion": 2,
        "packages": {
            "": {},
            "node_modules/zeta": {"version": "1.0.0"},
            "node_modules/alpha": {"version": "2.0.0"},
            "node_modules/alpha/node_modules/beta": {"version": "3.0.0"},
        },
    }

    assert [package["path"] for package in parse_package_lock(data)] == [
        "node_modules/alpha",
        "node_modules/alpha/node_modules/beta",
        "node_modules/zeta",
    ]

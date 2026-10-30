from lib_lens.analyzers.dependency_analyzer import analyze_dependencies


def dep(name, version, path=None):
    return {"name": name, "version": version, "path": path or f"node_modules/{name}", "dependency_type": "direct"}


def info(default, versions):
    return {"package_name": "x", "default_version": default, "versions": versions}


def version(value, deprecated=False, reason=None):
    return {"version": value, "isDeprecated": deprecated, "deprecatedReason": reason}


def test_vulnerable_and_non_vulnerable_dependencies(monkeypatch):
    alpha, beta, advisory = dep("alpha", "1.0.0"), dep("beta", "1.0.0"), {"id": "GHSA-1"}
    monkeypatch.setattr("lib_lens.analyzers.dependency_analyzer.query_osv_batch", lambda ds: [{"dependency": alpha, "vulnerability": advisory}])
    monkeypatch.setattr("lib_lens.analyzers.dependency_analyzer.get_package_version_info", lambda name: info("1.0.0", [version("1.0.0")]))
    result = analyze_dependencies([alpha, beta])
    assert result[0]["vulnerabilities"] == [advisory]
    assert result[1]["vulnerabilities"] == []


def test_updates_and_already_latest(monkeypatch):
    monkeypatch.setattr("lib_lens.analyzers.dependency_analyzer.query_osv_batch", lambda ds: [])
    monkeypatch.setattr("lib_lens.analyzers.dependency_analyzer.get_package_version_info", lambda name: info("2.0.0" if name == "old" else "1.0.0", [version("1.0.0")]))
    result = analyze_dependencies([dep("old", "1.0.0"), dep("current", "1.0.0")])
    assert [item["update_available"] for item in result] == [True, False]


def test_deprecation_and_unique_package_fetches(monkeypatch):
    calls = []
    monkeypatch.setattr("lib_lens.analyzers.dependency_analyzer.query_osv_batch", lambda ds: [])
    def get(name):
        calls.append(name)
        return info("2.0.0", [version("1.0.0", True, "Use 2.0.0")])
    monkeypatch.setattr("lib_lens.analyzers.dependency_analyzer.get_package_version_info", get)
    result = analyze_dependencies([dep("alpha", "1.0.0"), dep("alpha", "1.0.0", "node_modules/x/node_modules/alpha")])
    assert calls == ["alpha"]
    assert result[0]["is_deprecated"] is True
    assert result[0]["deprecated_reason"] == "Use 2.0.0"


def test_osv_failure_keeps_deps_dev_results(monkeypatch):
    monkeypatch.setattr("lib_lens.analyzers.dependency_analyzer.query_osv_batch", lambda ds: (_ for _ in ()).throw(RuntimeError("down")))
    monkeypatch.setattr("lib_lens.analyzers.dependency_analyzer.get_package_version_info", lambda name: info("2.0.0", [version("1.0.0")]))
    result = analyze_dependencies([dep("alpha", "1.0.0")])[0]
    assert result["update_available"] is True
    assert result["analysis_errors"] == ["osv: down"]


def test_deps_dev_failure_keeps_osv_results(monkeypatch):
    item, advisory = dep("alpha", "1.0.0"), {"id": "GHSA-1"}
    monkeypatch.setattr("lib_lens.analyzers.dependency_analyzer.query_osv_batch", lambda ds: [{"dependency": item, "vulnerability": advisory}])
    monkeypatch.setattr("lib_lens.analyzers.dependency_analyzer.get_package_version_info", lambda name: (_ for _ in ()).throw(RuntimeError("down")))
    result = analyze_dependencies([item])[0]
    assert result["vulnerabilities"] == [advisory]
    assert result["update_available"] is None
    assert result["analysis_errors"] == ["deps.dev: down"]


def test_both_fail_invalid_versions_and_input_order(monkeypatch):
    monkeypatch.setattr("lib_lens.analyzers.dependency_analyzer.query_osv_batch", lambda ds: (_ for _ in ()).throw(RuntimeError("osv down")))
    monkeypatch.setattr("lib_lens.analyzers.dependency_analyzer.get_package_version_info", lambda name: info("2.0.0", [version("not-valid")]) if name == "bad" else (_ for _ in ()).throw(RuntimeError("deps down")))
    result = analyze_dependencies([dep("zeta", "1.0.0"), dep("bad", "not-valid")])
    assert [item["name"] for item in result] == ["zeta", "bad"]
    assert result[0]["analysis_errors"] == ["osv: osv down", "deps.dev: deps down"]
    assert result[1]["update_available"] is None
    assert result[1]["analysis_errors"][-1].startswith("version comparison failed:")

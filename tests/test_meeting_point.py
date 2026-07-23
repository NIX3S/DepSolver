from depsolver import api_analyzer as aa


def _set_pip_args(monkeypatch, pip_args):
    monkeypatch.setenv("DEPSOLVER_PIP_EXTRA_ARGS", " ".join(pip_args))


def test_get_package_api_introspects_real_signatures(libc_pip_args, monkeypatch):
    _set_pip_args(monkeypatch, libc_pip_args)
    aa.cleanup_installed_dirs()
    symbols = ["check", "init", "run"]

    api_1_0 = aa.get_package_api("libc", "1.0", symbols=symbols)
    assert set(api_1_0.symbols) == {"check", "init", "run"}
    assert api_1_0.symbols["init"].positional_params == ["mode"]
    assert api_1_0.symbols["run"].positional_params == []

    api_256 = aa.get_package_api("libc", "2.5.6", symbols=symbols)
    assert api_256.symbols["init"].positional_params == ["mode", "strategy"]
    assert api_256.symbols["run"].positional_params == ["config"]

    api_3_0 = aa.get_package_api("libc", "3.0", symbols=symbols)
    assert api_3_0.symbols["init"].positional_params == ["strategy"]
    assert "mode" not in api_3_0.symbols["init"].positional_params


def test_extract_api_calls_from_package(callers):
    calls_a = aa.extract_api_calls_from_package(callers["libA"], "libA")
    calls_b = aa.extract_api_calls_from_package(callers["libB"], "libB")

    symbols_a = {(c.callee_package, c.callee_symbol) for c in calls_a}
    symbols_b = {(c.callee_package, c.callee_symbol) for c in calls_b}

    assert ("libc", "check") in symbols_a
    assert ("libc", "init") in symbols_a
    assert ("libc", "run") in symbols_b
    assert ("libc", "init") in symbols_b


def test_meeting_point_version_is_found(libc_pip_args, callers, monkeypatch):
    """Le coeur de la spec : 1.0 casse pour libB, 3.0 casse pour libA,
    seule 2.5.6 est compatible avec les deux."""
    _set_pip_args(monkeypatch, libc_pip_args)

    calls = aa.extract_api_calls_from_package(callers["libA"], "libA")
    calls += aa.extract_api_calls_from_package(callers["libB"], "libB")
    symbols = sorted({c.callee_symbol for c in calls})

    result_1_0 = aa.is_api_compatible(calls, aa.get_package_api("libc", "1.0", symbols=symbols))
    result_256 = aa.is_api_compatible(calls, aa.get_package_api("libc", "2.5.6", symbols=symbols))
    result_3_0 = aa.is_api_compatible(calls, aa.get_package_api("libc", "3.0", symbols=symbols))

    assert result_1_0.is_compatible is False
    assert result_3_0.is_compatible is False
    assert result_256.is_compatible is True


def test_optimizer_picks_meeting_point(libc_pip_args, callers, monkeypatch):
    from unittest import mock

    from depsolver import cve, optimizer, versions
    from depsolver.models import Requirement

    _set_pip_args(monkeypatch, libc_pip_args)

    calls = aa.extract_api_calls_from_package(callers["libA"], "libA")
    calls += aa.extract_api_calls_from_package(callers["libB"], "libB")

    fake_versions = {"libc": ["3.0", "2.5.6", "1.0"]}

    with mock.patch.object(versions, "list_versions", lambda n: fake_versions.get(n, [])), \
         mock.patch.object(versions, "get_dependencies", lambda n, v: []), \
         mock.patch.object(cve, "get_cves", lambda n, v: []), \
         mock.patch.object(cve, "is_version_acceptable", lambda v, c, p: True):

        result = optimizer.find_best_versions_with_api(
            [Requirement(name="libc", specs=[])],
            policy="cve-no-critical",
            all_calls=calls,
            analyze_api=True,
        )

    assert result.solution == {"libc": "2.5.6"}
    rejected_versions = {r.version for r in result.rejections}
    assert rejected_versions == {"1.0", "3.0"}

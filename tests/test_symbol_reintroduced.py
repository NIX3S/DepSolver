from unittest import mock

from depsolver import api_analyzer as aa
from depsolver import cve, optimizer, versions
from depsolver.models import ApiCall, Requirement


def _set_pip_args(monkeypatch, pip_args):
    monkeypatch.setenv("DEPSOLVER_PIP_EXTRA_ARGS", " ".join(pip_args))


def test_symbol_removed_then_reintroduced_is_checked_per_version(libe_pip_args, monkeypatch):
    """Cas 'pytesseract.main' : un symbole existe en 1.0, disparaît en 2.0
    (renommé), réapparaît en 3.0 (signature différente). Chaque version doit
    être vérifiée indépendamment -- ce n'est ni "toujours la dernière version
    fait foi" ni "toujours la première" : 2.0 doit être rejetée précisément,
    1.0 et 3.0 acceptées précisément, malgré leurs signatures différentes."""
    _set_pip_args(monkeypatch, libe_pip_args)
    aa.cleanup_installed_dirs()

    calls = aa.extract_api_calls_from_source(
        "import libe\ndef process(img):\n    return libe.main(img)\n",
        caller_package="myproject",
    )

    api_1_0 = aa.get_package_api("libe", "1.0", symbols=["main"])
    api_2_0 = aa.get_package_api("libe", "2.0", symbols=["main"])
    api_3_0 = aa.get_package_api("libe", "3.0", symbols=["main"])

    assert aa.is_api_compatible(calls, api_1_0).is_compatible is True
    assert aa.is_api_compatible(calls, api_2_0).is_compatible is False
    assert aa.is_api_compatible(calls, api_3_0).is_compatible is True


def test_optimizer_rejects_only_the_version_missing_the_symbol(libe_pip_args, monkeypatch):
    _set_pip_args(monkeypatch, libe_pip_args)
    aa.cleanup_installed_dirs()

    fake_versions = {"libe": ["3.0", "2.0", "1.0"]}
    calls = [ApiCall(caller_package="myproject", callee_package="libe", callee_symbol="main",
                      call_location="app.py:1", arg_count=1, kwarg_names=())]

    with mock.patch.object(versions, "list_versions", lambda n: fake_versions.get(n, [])), \
         mock.patch.object(versions, "get_dependencies", lambda n, v: []), \
         mock.patch.object(cve, "get_cves", lambda n, v: []), \
         mock.patch.object(cve, "is_version_acceptable", lambda v, c, p: True):

        result = optimizer.find_best_versions_with_api(
            [Requirement(name="libe", specs=[])],
            policy="cve-no-critical", all_calls=calls, analyze_api=True,
        )

    assert result.solution == {"libe": "3.0"}  # la plus récente compatible
    statuses = {ev.version: ev.status for ev in result.evaluated["libe"]}
    assert statuses["1.0"] == "kept"
    assert statuses["2.0"] == "excluded_api"
    assert statuses["3.0"] == "selected"

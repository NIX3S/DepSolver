import tempfile
from pathlib import Path
from unittest import mock

from depsolver import cve, optimizer, report, versions
from depsolver.models import Requirement
from depsolver.parser import write_lock_file


def test_unverified_when_no_calls_detected():
    """Si aucun appel n'est détecté vers un paquet, la version est quand même
    retenue (contraintes + CVE), mais marquée verified=False -- c'est ce qui
    doit apparaître clairement dans les rapports (cf. cas 'pytesseract')."""
    fake_versions = {"pytesseract": ["0.3.13", "0.1"]}

    with mock.patch.object(versions, "list_versions", lambda n: fake_versions.get(n, [])), \
         mock.patch.object(cve, "get_cves", lambda n, v: []), \
         mock.patch.object(cve, "is_version_acceptable", lambda v, c, p: True):

        result = optimizer.find_best_versions_with_api(
            [Requirement(name="pytesseract", specs=[])],
            policy="cve-no-critical",
            all_calls=[],  # aucun appel détecté
            analyze_api=True,
        )

    for ev in result.evaluated["pytesseract"]:
        assert ev.verified is False
        assert "NON vérifiée" in ev.detail


def test_verified_when_calls_match_across_versions():
    """À l'inverse : si le même symbole avec la même signature est appelé et
    existe dans plusieurs versions très éloignées, elles sont TOUTES marquées
    verified=True -- ce n'est pas un bug, c'est la garantie ciblée de l'outil
    (seul ce qui est réellement appelé est vérifié)."""
    from depsolver.models import ApiCall

    calls = [ApiCall(caller_package="proj", callee_package="libc", callee_symbol="check",
                      call_location="x.py:1", arg_count=1, kwarg_names=())]
    fake_versions = {"libc": ["3.0", "1.0"]}

    import os
    os.environ["DEPSOLVER_PIP_EXTRA_ARGS"] = "--no-index --find-links /home/claude/fixtures/wheels"

    with mock.patch.object(versions, "list_versions", lambda n: fake_versions.get(n, [])), \
         mock.patch.object(cve, "get_cves", lambda n, v: []), \
         mock.patch.object(cve, "is_version_acceptable", lambda v, c, p: True):

        result = optimizer.find_best_versions_with_api(
            [Requirement(name="libc", specs=[])],
            policy="cve-no-critical",
            all_calls=calls,
            analyze_api=True,
        )

    # check(x) existe et a la même signature en 1.0 et 3.0 -> les deux compatibles
    assert {ev.version for ev in result.evaluated["libc"]} == {"3.0", "1.0"}
    for ev in result.evaluated["libc"]:
        assert ev.verified is True


def test_render_explain_output():
    from depsolver.models import EvaluatedVersion, CVEInfo

    evaluated = [
        EvaluatedVersion(package="libc", version="1.0", status="excluded_cve",
                          cves=[CVEInfo(id="CVE-1", severity="HIGH")], detail="CVE non acceptée"),
        EvaluatedVersion(package="libc", version="2.0", status="selected", detail="ok", verified=True),
    ]
    text = report.render_explain("libc", evaluated)
    assert "CVE-1" in text
    assert "RETENUE" in text
    assert "écartée" in text


def test_graphviz_dot_syntax():
    solution = {"libA": "1.0", "libB": "2.0"}
    edges = [("libA", "libB")]
    dot = report.render_graphviz(solution, edges, title="test")
    assert dot.startswith("digraph")
    assert '"libA" -> "libB";' in dot
    assert '"libA"' in dot and '"libB"' in dot


def test_write_lock_file_header(tmp_path):
    path = tmp_path / "requirements.lock"
    write_lock_file({"libA": "1.0", "libB": "2.0"}, path, policy="cve-none")
    content = path.read_text()
    assert "NE PAS ÉDITER" in content
    assert "cve-none" in content
    assert "libA==1.0" in content
    assert "libB==2.0" in content


def test_compare_report():
    env1 = {"libA": "1.0", "libB": "2.0", "libX": "1.0"}
    env2 = {"libA": "1.1", "libB": "2.0", "libY": "1.0"}
    rep = report.build_compare_report("prod", env1, "staging", env2)
    statuses = {r["package"]: r["status"] for r in rep["rows"]}
    assert statuses["libA"] == "different"
    assert statuses["libB"] == "identique"
    assert statuses["libX"] == "seulement_env1"
    assert statuses["libY"] == "seulement_env2"
    assert rep["summary"]["total"] == 4

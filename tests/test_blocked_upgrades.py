from depsolver import report
from depsolver.models import EvaluatedVersion


def test_compute_blocked_upgrades_lists_only_newer_excluded_versions():
    solution = {"libc": "2.5.6"}
    evaluated = {
        "libc": [
            EvaluatedVersion(package="libc", version="3.0", status="excluded_api", detail="cassé"),
            EvaluatedVersion(package="libc", version="2.5.6", status="selected", detail="ok"),
            EvaluatedVersion(package="libc", version="1.0", status="excluded_api", detail="aussi cassé"),
        ]
    }
    blocked = report.compute_blocked_upgrades(solution, evaluated)
    assert list(blocked.keys()) == ["libc"]
    versions_blocked = [ev.version for ev in blocked["libc"]]
    assert versions_blocked == ["3.0"]  # 1.0 est plus ANCIEN que la version retenue, pas "bloqué"


def test_compute_blocked_upgrades_empty_when_already_latest():
    solution = {"libc": "3.0"}
    evaluated = {"libc": [EvaluatedVersion(package="libc", version="3.0", status="selected", detail="ok")]}
    blocked = report.compute_blocked_upgrades(solution, evaluated)
    assert blocked == {}


def test_render_text_blocked_upgrades_mentions_reason():
    blocked = {"libc": [EvaluatedVersion(package="libc", version="3.0", status="excluded_api",
                                          detail="paramètre inconnu")]}
    text = report.render_text_blocked_upgrades(blocked)
    assert "libc==3.0" in text
    assert "BREAKING CHANGE" in text
    assert "paramètre inconnu" in text

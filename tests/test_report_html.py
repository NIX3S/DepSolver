from depsolver import report
from depsolver.models import CVEInfo, EvaluatedVersion


def test_render_html_contains_versions_status_and_cve():
    evaluated = {
        "libc": [
            EvaluatedVersion(package="libc", version="1.0", status="excluded_cve",
                              cves=[CVEInfo(id="CVE-2024-1234", severity="HIGH")],
                              detail="CVE non acceptée"),
            EvaluatedVersion(package="libc", version="2.5.6", status="selected", detail="compatible"),
            EvaluatedVersion(package="libc", version="3.0", status="excluded_api", detail="breaking change"),
        ]
    }
    html_out = report.render_html(
        solution={"libc": "2.5.6"},
        evaluated=evaluated,
        policy="cve-no-critical",
        current={"libc": "1.0"},
    )
    assert "CVE-2024-1234" in html_out
    assert "2.5.6" in html_out and "3.0" in html_out and "1.0" in html_out
    assert "Retenue" in html_out
    assert "<!DOCTYPE html>" in html_out


def test_write_html(tmp_path):
    path = tmp_path / "report.html"
    report.write_html("<html></html>", str(path))
    assert path.read_text() == "<html></html>"

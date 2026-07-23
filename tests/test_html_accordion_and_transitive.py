from depsolver import report
from depsolver.models import EvaluatedVersion


def test_html_versions_sorted_descending():
    evaluated = {
        "libc": [
            EvaluatedVersion(package="libc", version="10.0", status="kept", detail="ok"),
            EvaluatedVersion(package="libc", version="2.0", status="kept", detail="ok"),
            EvaluatedVersion(package="libc", version="9.0", status="selected", detail="ok"),
        ]
    }
    html_out = report.render_html({"libc": "9.0"}, evaluated, "cve-no-critical",
                                    requirement_names={"libc"})
    # on isole le tableau de l'accordéon (après "Détail par paquet"), pas le
    # tableau "Solution retenue" qui contient aussi "9.0" mais dans un autre
    # contexte (une seule ligne, sans rapport avec le tri des versions).
    accordion_part = html_out.split("Détail par paquet")[1]
    pos_10 = accordion_part.index(">10.0<")
    pos_9 = accordion_part.index(">9.0<")
    pos_2 = accordion_part.index(">2.0<")
    assert pos_10 < pos_9 < pos_2  # ordre décroissant sémantique (plus récent en premier)


def test_html_uses_accordion_details_per_package():
    evaluated = {"libc": [EvaluatedVersion(package="libc", version="1.0", status="selected", detail="ok")]}
    html_out = report.render_html({"libc": "1.0"}, evaluated, "cve-no-critical", requirement_names={"libc"})
    assert '<details class="pkg-accordion">' in html_out
    assert "<summary>libc" in html_out


def test_html_hides_transitive_from_solution_table_but_lists_with_provenance():
    solution = {"libA": "1.0", "libD": "2.0"}
    evaluated = {"libA": [EvaluatedVersion(package="libA", version="1.0", status="selected", detail="ok")]}
    transitive = [{"name": "libD", "version": "2.0", "brought_in_by": ["libA"]}]

    html_out = report.render_html(
        solution, evaluated, "cve-no-critical",
        requirement_names={"libA"}, transitive_dependencies=transitive,
    )

    solution_table = html_out.split("Solution retenue")[1].split("Voir les sous-dépendances")[0]
    assert "libA" in solution_table
    assert "libD" not in solution_table  # pas dans le tableau principal

    assert "Voir les sous-dépendances" in html_out
    assert "libD==2.0" in html_out
    assert "apportée par libA" in html_out
    assert "depsolverFilterTransitive" in html_out  # le filtre JS est bien présent


def test_build_transitive_dependencies_provenance():
    from depsolver.report import build_transitive_dependencies

    class FakeDep:
        def __init__(self, name):
            self.name = name

    def fake_get_deps(name, version):
        if name == "libA":
            return [FakeDep("libD")]
        if name == "libB":
            return [FakeDep("libD")]
        return []

    solution = {"libA": "1.0", "libB": "2.0", "libD": "3.0"}
    transitive = build_transitive_dependencies({"libA", "libB"}, solution, fake_get_deps)

    assert len(transitive) == 1
    assert transitive[0]["name"] == "libD"
    assert transitive[0]["brought_in_by"] == ["libA", "libB"]

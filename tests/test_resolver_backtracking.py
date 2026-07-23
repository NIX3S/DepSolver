from unittest import mock

from packaging.requirements import Requirement as PkgRequirement

from depsolver import versions
from depsolver.models import Requirement
from depsolver.resolver import NoSolutionError, solve


def test_unsatisfiable_transitive_conflict_raises():
    """libA n'a qu'une version, qui impose libB==2.0, qui impose libC==2.6.
    La racine exige libC>3.0 : conflit réel, aucune solution possible."""
    fake_versions = {"libA": ["1.0"], "libB": ["2.0"], "libC": ["3.1", "3.0", "2.6"]}

    def fake_deps(name, version):
        if name == "libA":
            return [PkgRequirement("libB==2.0")]
        if name == "libB":
            return [PkgRequirement("libC==2.6")]
        return []

    with mock.patch.object(versions, "list_versions", lambda n: fake_versions.get(n, [])):
        try:
            solve(
                [Requirement(name="libA", specs=[]), Requirement(name="libC", specs=[(">", "3.0")])],
                list_versions=versions.list_versions,
                get_dependencies=fake_deps,
            )
            assert False, "une NoSolutionError était attendue"
        except NoSolutionError:
            pass


def test_backtracks_to_older_upstream_version_when_needed():
    """libA a deux versions : la plus récente (2.0) impose libB==2.0 -> libC==2.6
    (incompatible avec la contrainte racine libC>3.0), la plus ancienne (1.0)
    impose libB==1.0 -> libC>=3.0 (compatible). Le resolver doit backtracker
    jusqu'à libA==1.0 plutôt que d'abandonner après l'échec sur libA==2.0 —
    et les contraintes ajoutées par la branche libA==2.0 (échouée) ne doivent
    pas "fuiter" et bloquer à tort la branche libA==1.0."""
    fake_versions = {
        "libA": ["2.0", "1.0"],
        "libB": ["2.0", "1.0"],
        "libC": ["3.1", "3.0", "2.6"],
    }

    def fake_deps(name, version):
        if name == "libA" and version == "2.0":
            return [PkgRequirement("libB==2.0")]
        if name == "libA" and version == "1.0":
            return [PkgRequirement("libB==1.0")]
        if name == "libB" and version == "2.0":
            return [PkgRequirement("libC==2.6")]
        if name == "libB" and version == "1.0":
            return [PkgRequirement("libC>=3.0")]
        return []

    with mock.patch.object(versions, "list_versions", lambda n: fake_versions.get(n, [])):
        solution = solve(
            [Requirement(name="libA", specs=[]), Requirement(name="libC", specs=[(">", "3.0")])],
            list_versions=versions.list_versions,
            get_dependencies=fake_deps,
        )

    assert solution["libA"] == "1.0"
    assert solution["libB"] == "1.0"
    assert solution["libC"] in ("3.0", "3.1")

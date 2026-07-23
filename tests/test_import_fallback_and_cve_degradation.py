from unittest import mock

from depsolver import api_analyzer as aa
from depsolver import cve, optimizer, versions
from depsolver.models import ApiCall, CVEInfo, Requirement
from depsolver.resolver import NoSolutionError


def _set_pip_args(monkeypatch, pip_args):
    monkeypatch.setenv("DEPSOLVER_PIP_EXTRA_ARGS", " ".join(pip_args))


# ---------------------------------------------------------------------------
# Reproduction du bug signalé : un paquet qui importe une dépendance tierce
# au niveau module (comme pytesseract importe PIL) ne doit JAMAIS voir ses
# symboles déclarés "absents" simplement parce que --no-deps empêche l'import
# rapide -- depsolver doit se rabattre automatiquement sur une installation
# complète avant de conclure quoi que ce soit.
# ---------------------------------------------------------------------------

def test_module_with_missing_runtime_dependency_falls_back_to_full_install(libf_pip_args, monkeypatch):
    _set_pip_args(monkeypatch, libf_pip_args)
    aa.cleanup_installed_dirs()

    api = aa.get_package_api("libf", "1.0", symbols=["ocr"])
    assert "ocr" in api.symbols, "le symbole doit être trouvé via le repli sur installation complète"
    assert api.inconclusive == []


def test_symbol_stays_inconclusive_when_even_full_install_fails(monkeypatch):
    """Si même l'installation complète échoue (dépendance introuvable nulle
    part), le symbole doit être 'inconclusif', jamais 'absent' -- ça ne doit
    pas faire rejeter la version comme si un breaking change était confirmé."""
    aa.cleanup_installed_dirs()
    api = aa.get_package_api(
        "libf", "1.0", symbols=["ocr"],
        pip_extra_args=["--no-index", "--find-links", "/tmp/depsolver-empty-nonexistent-dir"],
    )
    assert "ocr" not in api.symbols
    assert "ocr" in api.inconclusive

    calls = [ApiCall(caller_package="proj", callee_package="libf", callee_symbol="ocr",
                      call_location="x.py:1", arg_count=1, kwarg_names=())]
    result = aa.is_api_compatible(calls, api)
    assert result.is_compatible is True  # jamais de faux rejet sur un cas inconclusif
    assert len(result.warnings) == 1


# ---------------------------------------------------------------------------
# Dégradation progressive de la politique CVE (jamais de l'API)
# ---------------------------------------------------------------------------

def test_cve_degradation_picks_least_bad_version():
    """Si aucune version ne satisfait la politique stricte, depsolver doit
    dégrader le MOINS possible : choisir la version avec la CVE la moins
    sévère parmi celles bloquées, pas n'importe laquelle."""
    fake_versions = {"libz": ["3.0", "2.0", "1.0"]}

    def fake_get_cves(name, version):
        severity = {"3.0": "CRITICAL", "2.0": "CRITICAL", "1.0": "HIGH"}[version]
        return [CVEInfo(id=f"CVE-{version}", severity=severity)]

    with mock.patch.object(versions, "list_versions", lambda n: fake_versions.get(n, [])), \
         mock.patch.object(versions, "get_dependencies", lambda n, v: []), \
         mock.patch.object(cve, "get_cves", fake_get_cves):

        result = optimizer.find_best_versions_with_api(
            [Requirement(name="libz", specs=[])],
            policy="cve-none", all_calls=[], analyze_api=False,
        )

    assert result.solution == {"libz": "1.0"}  # la moins pire (HIGH, pas CRITICAL)
    assert len(result.cve_relaxations) == 1
    assert result.cve_relaxations[0].version == "1.0"
    assert result.cve_relaxations[0].accepted_ceiling_label != cve.ceiling_label(4)  # pas allé jusqu'à tout tolérer


def test_cve_degradation_not_applied_when_strict_versions_exist():
    """La dégradation ne doit JAMAIS s'appliquer si des versions satisfont
    déjà la politique stricte -- même si d'autres versions ont des CVE pires,
    elles ne doivent pas influencer le choix."""
    fake_versions = {"libz": ["2.0", "1.0"]}

    def fake_get_cves(name, version):
        if version == "2.0":
            return [CVEInfo(id="CVE-X", severity="CRITICAL")]
        return []  # 1.0 : aucune CVE

    with mock.patch.object(versions, "list_versions", lambda n: fake_versions.get(n, [])), \
         mock.patch.object(versions, "get_dependencies", lambda n, v: []), \
         mock.patch.object(cve, "get_cves", fake_get_cves):

        result = optimizer.find_best_versions_with_api(
            [Requirement(name="libz", specs=[])],
            policy="cve-no-critical", all_calls=[], analyze_api=False,
        )

    assert result.solution == {"libz": "1.0"}
    assert result.cve_relaxations == []  # pas de dégradation nécessaire


def test_strict_cve_disables_degradation():
    fake_versions = {"libz": ["1.0"]}

    def fake_get_cves(name, version):
        return [CVEInfo(id="CVE-X", severity="CRITICAL")]

    with mock.patch.object(versions, "list_versions", lambda n: fake_versions.get(n, [])), \
         mock.patch.object(versions, "get_dependencies", lambda n, v: []), \
         mock.patch.object(cve, "get_cves", fake_get_cves):

        try:
            optimizer.find_best_versions_with_api(
                [Requirement(name="libz", specs=[])],
                policy="cve-none", all_calls=[], analyze_api=False, strict_cve=True,
            )
            assert False, "une NoSolutionError était attendue en mode strict"
        except NoSolutionError:
            pass

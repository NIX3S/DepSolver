from unittest import mock

from depsolver import api_analyzer as aa
from depsolver import cve, optimizer, versions
from depsolver.models import ApiCall, Requirement


def test_no_pin_scans_only_default_window():
    """Sans version épinglée, ne doit interroger CVE/API que sur les
    DEFAULT_WINDOW versions les plus récentes, pas tout l'historique."""
    fake_versions_list = [f"{20 - i}.0" for i in range(20)]
    fetched = []

    def fake_get_cves(name, version):
        fetched.append(version)
        return []

    with mock.patch.object(versions, "list_versions", lambda n: fake_versions_list), \
         mock.patch.object(versions, "get_dependencies", lambda n, v: []), \
         mock.patch.object(cve, "get_cves", fake_get_cves):

        result = optimizer.find_best_versions_with_api(
            [Requirement(name="libx", specs=[])], policy="cve-no-critical",
            all_calls=[], analyze_api=False,
        )

    assert result.solution == {"libx": "20.0"}
    assert len(set(fetched)) == optimizer.DEFAULT_WINDOW
    assert set(fetched) == {"20.0", "19.0", "18.0", "17.0", "16.0"}


def test_pin_never_scans_below_floor_when_not_needed():
    """Avec un pin existant loin derrière, le scan par défaut reste les 5
    dernières versions (pas tout l'intervalle jusqu'au pin) -- le pin sert de
    garde-fou, pas de fenêtre de scan à lui tout seul."""
    fake_versions_list = [f"{20 - i}.0" for i in range(20)]
    fetched = []

    def fake_get_cves(name, version):
        fetched.append(version)
        return []

    with mock.patch.object(versions, "list_versions", lambda n: fake_versions_list), \
         mock.patch.object(versions, "get_dependencies", lambda n, v: []), \
         mock.patch.object(cve, "get_cves", fake_get_cves):

        result = optimizer.find_best_versions_with_api(
            [Requirement(name="libx", specs=[])], policy="cve-no-critical",
            all_calls=[], analyze_api=False, current_pins={"libx": "12.0"},
        )

    assert result.solution == {"libx": "20.0"}
    assert len(set(fetched)) == optimizer.DEFAULT_WINDOW  # juste les 5 dernières, pas tout jusqu'à 12.0
    assert min(float(v) for v in fetched) == 16.0
    assert result.version_scan_notes == []


def test_pin_close_to_top_never_includes_downgrade_in_initial_batch():
    """Si le pin est proche du sommet (peu de versions plus récentes), le lot
    initial ne doit JAMAIS inclure une version < pin, même en complétant
    jusqu'à DEFAULT_WINDOW -- pas de régression accidentelle."""
    fake_versions_list = ["7.0", "6.0", "5.0", "4.0", "3.0", "2.0", "1.0"]
    fetched = []

    def fake_get_cves(name, version):
        fetched.append(version)
        return []

    with mock.patch.object(versions, "list_versions", lambda n: fake_versions_list), \
         mock.patch.object(versions, "get_dependencies", lambda n, v: []), \
         mock.patch.object(cve, "get_cves", fake_get_cves):

        result = optimizer.find_best_versions_with_api(
            [Requirement(name="libx", specs=[])], policy="cve-no-critical",
            all_calls=[], analyze_api=False, current_pins={"libx": "6.0"},
        )

    assert result.solution == {"libx": "7.0"}
    assert min(float(v) for v in fetched) == 6.0  # jamais 5.0, 4.0, ... dans le lot initial
    assert result.version_scan_notes == []  # pas besoin d'élargir


def test_widens_below_pin_only_when_blocked(libc_pip_args, monkeypatch):
    """Cas 'Pillow' : le pin actuel casse avec un nouvel appel -> on doit
    redescendre en dessous du pin en dernier recours, et le signaler."""
    monkeypatch.setenv("DEPSOLVER_PIP_EXTRA_ARGS", " ".join(libc_pip_args))
    aa.cleanup_installed_dirs()

    fake_versions_libc = {"libc": ["3.0", "2.5.6", "1.0"]}
    calls = [ApiCall(caller_package="proj", callee_package="libc", callee_symbol="init",
                      call_location="x.py:1", arg_count=0, kwarg_names=("mode",))]

    with mock.patch.object(versions, "list_versions", lambda n: fake_versions_libc.get(n, [])), \
         mock.patch.object(cve, "get_cves", lambda n, v: []):

        result = optimizer.find_best_versions_with_api(
            [Requirement(name="libc", specs=[])], policy="cve-no-critical",
            all_calls=calls, analyze_api=True, current_pins={"libc": "3.0"},
        )

    assert result.solution == {"libc": "2.5.6"}
    assert len(result.version_scan_notes) == 1
    assert result.version_scan_notes[0].widened_to_version == "2.5.6"


def test_all_versions_flag_disables_window():
    """--all-versions (check_all_versions=True) doit scanner tout l'historique
    d'emblée, sans restriction ni élargissement progressif."""
    fake_versions_list = [f"{10 - i}.0" for i in range(10)]
    fetched = []

    def fake_get_cves(name, version):
        fetched.append(version)
        return []

    with mock.patch.object(versions, "list_versions", lambda n: fake_versions_list), \
         mock.patch.object(versions, "get_dependencies", lambda n, v: []), \
         mock.patch.object(cve, "get_cves", fake_get_cves):

        result = optimizer.find_best_versions_with_api(
            [Requirement(name="libx", specs=[])], policy="cve-no-critical",
            all_calls=[], analyze_api=False, check_all_versions=True,
        )

    assert len(set(fetched)) == 10  # tout l'historique scanné

import contextlib
import io
import json
from unittest import mock

from depsolver import cve, cli, versions


def _run_solve(args_list):
    parser = cli.build_parser()
    args = parser.parse_args(args_list)
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = cli.cmd_solve(args)
    return rc, json.loads(buf.getvalue())


def test_exact_pins_locks_to_the_exact_version():
    """Sans --exact-pins, un pin == est un point de départ (floor) : on
    cherche mieux. Avec --exact-pins, il devient un verrou strict."""
    fake_versions_list = ["0.3.13", "0.3.12", "0.3.11", "0.3.10", "0.3.9", "0.2.0"]

    with mock.patch.object(versions, "list_versions", lambda n: fake_versions_list), \
         mock.patch.object(versions, "get_dependencies", lambda n, v: []), \
         mock.patch.object(cve, "get_cves", lambda n, v: []):

        rc_default, rep_default = _run_solve(["solve", "--require", "pytesseract==0.2.0", "--json"])
        rc_exact, rep_exact = _run_solve(
            ["solve", "--require", "pytesseract==0.2.0", "--exact-pins", "--json"]
        )

    assert rc_default == 0 and rc_exact == 0
    assert rep_default["solution"] == {"pytesseract": "0.3.13"}  # cherche mieux par défaut
    assert rep_exact["solution"] == {"pytesseract": "0.2.0"}  # verrouillé avec --exact-pins


def test_exact_pins_still_validates_cve_and_api():
    """--exact-pins ne dispense pas de la vérification : si la version
    exacte a un problème (CVE/API), ça doit toujours être signalé."""
    from depsolver.models import CVEInfo

    fake_versions_list = ["1.0"]

    def fake_get_cves(name, version):
        return [CVEInfo(id="CVE-X", severity="CRITICAL")]

    with mock.patch.object(versions, "list_versions", lambda n: fake_versions_list), \
         mock.patch.object(versions, "get_dependencies", lambda n, v: []), \
         mock.patch.object(cve, "get_cves", fake_get_cves):

        rc, rep = _run_solve(
            ["solve", "--require", "libz==1.0", "--exact-pins", "--strict-cve", "--json"]
        )

    assert rc == 1
    assert rep["pinned_validation"]["ok"] is False

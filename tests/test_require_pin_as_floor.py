from unittest import mock

from depsolver import cve, cli, versions


def test_require_exact_pin_without_input_is_treated_as_floor():
    """`solve --require "pytesseract==0.2.0"` (sans --input) doit chercher
    automatiquement une meilleure version >= 0.2.0 (fenêtre par défaut de 5),
    pas rester bloqué sur exactement 0.2.0 comme un verrou strict."""
    fake_versions_list = ["0.3.13", "0.3.12", "0.3.11", "0.3.10", "0.3.9",
                          "0.3.8", "0.3.7", "0.3.6", "0.3.0", "0.2.1", "0.2.0"]

    with mock.patch.object(versions, "list_versions", lambda n: fake_versions_list), \
         mock.patch.object(versions, "get_dependencies", lambda n, v: []), \
         mock.patch.object(cve, "get_cves", lambda n, v: []):

        parser = cli.build_parser()
        args = parser.parse_args(["solve", "--require", "pytesseract==0.2.0", "--json"])

        import io
        import contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = cli.cmd_solve(args)

    assert rc == 0
    import json
    rep = json.loads(buf.getvalue())
    assert rep["solution"] == {"pytesseract": "0.3.13"}
    assert rep["current"] == {"pytesseract": "0.2.0"}
    assert rep["pinned_validation"]["ok"] is True

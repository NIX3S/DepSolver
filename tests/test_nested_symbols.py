from depsolver import api_analyzer as aa


def _set_pip_args(monkeypatch, pip_args):
    monkeypatch.setenv("DEPSOLVER_PIP_EXTRA_ARGS", " ".join(pip_args))


def test_extract_nested_calls(nested_caller):
    """Vérifie que les appels à un sous-module (`libc.sub.close`, accès par
    attribut complet) ET via un alias d'import explicite du sous-module
    (`from libc import sub as sub_alias; sub_alias.Manager(...)`) sont bien
    résolus vers le même chemin imbriqué que celui utilisé par l'API réelle.

    Limite assumée (analyse statique sans inférence de type) : un appel comme
    `instance.close()` sur une variable locale issue d'un appel précédent
    (`m = sub_alias.Manager(...)`; `m.close()`) n'est PAS capturé, faute de
    suivre le type de `m` — seuls les accès via un nom directement lié à un
    import (module, alias, symbole importé) le sont.
    """
    calls = aa.extract_api_calls_from_package(nested_caller, "libD")
    symbols = {(c.callee_package, c.callee_symbol) for c in calls}

    assert ("libc", "sub.close") in symbols
    assert ("libc", "sub.Manager") in symbols


def test_nested_symbol_resolved_when_present(libc_pip_args, monkeypatch):
    _set_pip_args(monkeypatch, libc_pip_args)
    aa.cleanup_installed_dirs()

    api_1_0 = aa.get_package_api("libc", "1.0", symbols=["sub.close", "sub.Manager"])
    assert "sub.close" in api_1_0.symbols
    assert api_1_0.symbols["sub.close"].positional_params == []

    api_256 = aa.get_package_api("libc", "2.5.6", symbols=["sub.close", "sub.Manager"])
    assert "sub.close" in api_256.symbols
    assert "force" in api_256.symbols["sub.close"].positional_params


def test_nested_symbol_flagged_absent_when_submodule_removed(libc_pip_args, monkeypatch):
    """En 3.0, le sous-module `libc.sub` est entièrement supprimé : les deux
    symboles imbriqués doivent être détectés comme absents (breaking change),
    pas silencieusement ignorés."""
    _set_pip_args(monkeypatch, libc_pip_args)
    aa.cleanup_installed_dirs()

    api_3_0 = aa.get_package_api("libc", "3.0", symbols=["sub.close", "sub.Manager"])
    assert "sub.close" not in api_3_0.symbols
    assert "sub.Manager" not in api_3_0.symbols


def test_is_api_compatible_flags_removed_nested_submodule(nested_caller, libc_pip_args, monkeypatch):
    _set_pip_args(monkeypatch, libc_pip_args)
    aa.cleanup_installed_dirs()

    calls = aa.extract_api_calls_from_package(nested_caller, "libD")

    api_256 = aa.get_package_api("libc", "2.5.6", symbols=sorted({c.callee_symbol for c in calls}))
    result_256 = aa.is_api_compatible(calls, api_256)
    assert result_256.is_compatible is True

    api_3_0 = aa.get_package_api("libc", "3.0", symbols=sorted({c.callee_symbol for c in calls}))
    result_3_0 = aa.is_api_compatible(calls, api_3_0)
    assert result_3_0.is_compatible is False
    reasons = " ".join(i.reason for i in result_3_0.incompatibilities)
    assert "sub.close" in reasons
    assert "sub.Manager" in reasons

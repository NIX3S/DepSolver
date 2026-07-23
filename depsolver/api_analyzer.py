"""Extraction des appels réels (AST) et de l'API publique d'une version de paquet.

Trois briques :
- extract_api_calls_from_source(s) : parcourt du code Python et repère les appels,
  y compris les chemins imbriqués (`libB.core.close(...)`,
  `from libB import core; core.MyClass(...).method(...)`, etc.), pas seulement
  les attributs directs d'un module top-level.
- get_package_api(name, version, symbols) : installe la version demandée dans un
  dossier temporaire isolé (pip install --target, sans exécuter le code du
  paquet plus que l'import) et résout précisément, pour chaque symbole imbriqué
  réellement appelé, s'il existe encore et avec quelle signature — en
  descendant module par module puis attribut par attribut (sous-module, classe,
  méthode), pas seulement au premier niveau.
- is_api_compatible : compare les appels aux signatures résolues.
"""
from __future__ import annotations

import ast
import importlib
import inspect
import logging
import os
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .models import (
    ApiCall,
    ApiCompatibilityResult,
    ApiIncompatibility,
    PackageAPI,
    SymbolSignature,
)

logger = logging.getLogger("depsolver.api_analyzer")

# (package, version) -> PackageAPI, rempli progressivement (un symbole peut être
# ajouté au fil de plusieurs appels à get_package_api pour la même version).
_API_CACHE: Dict[Tuple[str, str], PackageAPI] = {}
# (package, version, with_deps) -> dossier d'installation isolé, réutilisé
# entre appels pour éviter de réinstaller à chaque nouveau symbole demandé.
_INSTALL_DIRS: Dict[Tuple[str, str, bool], Optional[str]] = {}


class _CallVisitor(ast.NodeVisitor):
    """Détecte les appels à des symboles importés, en résolvant le chemin
    pointé complet (ex. `core.close` si `core` vient de `from libB import core`,
    ou `sub.Klass.method` pour un `libB.sub.Klass(...).method(...)` -- dans ce
    dernier cas seule la partie statiquement résolvable avant l'appel
    intermédiaire est capturée, cf. limites documentées plus bas)."""

    def __init__(self, caller_package: str, file_path: str, import_aliases: Dict[str, str]):
        self.caller_package = caller_package
        self.file_path = file_path
        self.import_aliases = import_aliases  # alias local -> chemin pointé réel
        self.calls: List[ApiCall] = []

    def visit_ImportFrom(self, node: ast.ImportFrom):
        if node.module and node.level == 0:
            for alias in node.names:
                local_name = alias.asname or alias.name
                self.import_aliases[local_name] = f"{node.module}.{alias.name}"
        self.generic_visit(node)

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            top = alias.name.split(".")[0]
            if alias.asname:
                # "import a.b.c as x" -> x est bindé directement sur le sous-module a.b.c
                self.import_aliases[alias.asname] = alias.name
            else:
                # "import a.b.c" -> seul le nom top-level 'a' est bindé dans la
                # portée ; l'accès à a.b.c se fait via la chaîne d'attributs,
                # prise en charge par _flatten_attribute_chain.
                self.import_aliases[top] = top
        self.generic_visit(node)

    @staticmethod
    def _flatten_attribute_chain(node: ast.expr) -> Optional[Tuple[str, List[str]]]:
        """Pour `a.b.c` (Attribute(Attribute(Name(a),b),c)) renvoie ('a', ['b','c'])."""
        attrs: List[str] = []
        cur = node
        while isinstance(cur, ast.Attribute):
            attrs.append(cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Name):
            attrs.reverse()
            return cur.id, attrs
        return None

    def _record(self, candidate: str, node: ast.Call):
        parts = candidate.split(".")
        if len(parts) < 2:
            return  # pas de symbole précis identifiable (appel du module lui-même)
        package = parts[0]
        symbol = ".".join(parts[1:])
        kwargs = tuple(k.arg for k in node.keywords if k.arg)
        self.calls.append(
            ApiCall(
                caller_package=self.caller_package,
                callee_package=package,
                callee_symbol=symbol,
                call_location=f"{self.file_path}:{node.lineno}",
                arg_count=len(node.args),
                kwarg_names=kwargs,
            )
        )

    def visit_Call(self, node: ast.Call):
        if isinstance(node.func, ast.Attribute):
            flattened = self._flatten_attribute_chain(node.func)
            if flattened:
                base, attrs = flattened
                if base in self.import_aliases:
                    candidate = self.import_aliases[base]
                    if attrs:
                        candidate += "." + ".".join(attrs)
                    self._record(candidate, node)
        elif isinstance(node.func, ast.Name):
            name = node.func.id
            if name in self.import_aliases:
                self._record(self.import_aliases[name], node)
        self.generic_visit(node)


def extract_api_calls_from_source(source: str, caller_package: str, file_path: str = "<string>") -> List[ApiCall]:
    tree = ast.parse(source, filename=file_path)
    visitor = _CallVisitor(caller_package, file_path, {})
    visitor.visit(tree)
    return visitor.calls


def extract_api_calls_from_package(pkg_path: str | Path, caller_package: str) -> List[ApiCall]:
    calls: List[ApiCall] = []
    for py_file in Path(pkg_path).rglob("*.py"):
        try:
            source = py_file.read_text(encoding="utf-8", errors="ignore")
            calls.extend(extract_api_calls_from_source(source, caller_package, str(py_file)))
        except (SyntaxError, UnicodeDecodeError):
            continue
    return calls


def _signature_of(obj) -> Optional[SymbolSignature]:
    if obj is None:
        return None
    try:
        sig = inspect.signature(obj)
    except (TypeError, ValueError):
        return None
    positional = []
    kwonly = []
    has_var_pos = False
    has_var_kw = False
    for p in sig.parameters.values():
        if p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD):
            if p.name != "self":
                positional.append(p.name)
        elif p.kind == p.KEYWORD_ONLY:
            kwonly.append(p.name)
        elif p.kind == p.VAR_POSITIONAL:
            has_var_pos = True
        elif p.kind == p.VAR_KEYWORD:
            has_var_kw = True
    return SymbolSignature(
        name=getattr(obj, "__name__", "?"),
        positional_params=positional,
        kwonly_params=kwonly,
        has_var_positional=has_var_pos,
        has_var_keyword=has_var_kw,
    )


def _resolve_dotted_symbol(import_name: str, dotted_symbol: str) -> Tuple[str, object]:
    """Résout un chemin imbriqué (ex. `core.close`, `core.MyClass.method`).

    Renvoie (status, obj) avec status ∈ {"found", "absent", "import_error"} :
    - "found"        : le symbole existe, `obj` est l'objet résolu.
    - "absent"       : le(s) module(s) parent(s) se sont importés SANS erreur,
                        mais le symbole n'existe pas à ce chemin -> preuve
                        positive d'un breaking change.
    - "import_error" : l'import d'un module de la chaîne a échoué (typiquement
                        une dépendance manquante, comme PIL pour pytesseract)
                        -> INCONCLUSIF, ne prouve absolument pas que le
                        symbole est absent. Ne doit jamais être traité comme
                        une preuve d'absence.
    """
    parts = dotted_symbol.split(".")
    try:
        module = importlib.import_module(import_name)
    except Exception as exc:
        logger.debug("import de '%s' impossible (%s) : inconclusif, pas une preuve d'absence", import_name, exc)
        return "import_error", None

    module_path = import_name
    idx = 0
    while idx < len(parts):
        candidate_path = f"{module_path}.{parts[idx]}"
        try:
            submodule = importlib.import_module(candidate_path)
        except ModuleNotFoundError as exc:
            # Le sous-module n'existe simplement pas à ce chemin -- mais
            # attention : ModuleNotFoundError peut aussi venir d'une
            # dépendance tierce manquante importée PAR ce sous-module. On ne
            # peut distinguer les deux qu'en comparant le nom du module en
            # échec au chemin qu'on essaie de résoudre nous-même.
            if getattr(exc, "name", None) == candidate_path:
                break  # c'est bien CE sous-module précis qui n'existe pas
            logger.debug("import de '%s' échoue à cause d'une dépendance tierce manquante (%s) : inconclusif",
                         candidate_path, exc)
            return "import_error", None
        except Exception as exc:
            logger.debug("import de '%s' échoue (%s) : inconclusif", candidate_path, exc)
            return "import_error", None
        module = submodule
        module_path = candidate_path
        idx += 1

    obj = module
    for part in parts[idx:]:
        try:
            obj = getattr(obj, part)
        except AttributeError:
            return "absent", None
    return "found", obj


def _pip_extra_args_from_env(explicit: Optional[List[str]]) -> List[str]:
    if explicit is not None:
        return explicit
    env_args = os.environ.get("DEPSOLVER_PIP_EXTRA_ARGS")
    return shlex.split(env_args) if env_args else []


def _ensure_installed(package_name: str, version: str, pip_extra_args: List[str], with_deps: bool = False) -> Optional[str]:
    key = (package_name, version, with_deps)
    if key in _INSTALL_DIRS:
        return _INSTALL_DIRS[key]

    tmp = tempfile.mkdtemp(prefix=f"depsolver-{package_name}-{version}-{'full' if with_deps else 'nodeps'}-")
    cmd = [sys.executable, "-m", "pip", "install", "--target", tmp, "--quiet"]
    if not with_deps:
        cmd.append("--no-deps")
    cmd += pip_extra_args
    cmd.append(f"{package_name}=={version}")
    logger.debug("installation isolée (%s) : %s", "avec dépendances" if with_deps else "sans dépendances", " ".join(cmd))
    try:
        subprocess.run(cmd, check=True, capture_output=True, timeout=180)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        logger.debug("échec d'installation de %s==%s (with_deps=%s) : %s", package_name, version, with_deps, exc)
        _INSTALL_DIRS[key] = None
        return None

    _INSTALL_DIRS[key] = tmp
    return tmp


def _import_from_dir(tmp: str, import_name: str, symbols: List[str]) -> Dict[str, Tuple[str, object]]:
    """Résout une liste de symboles dans un dossier d'installation donné,
    en gérant proprement l'ajout/retrait de sys.path et le nettoyage du cache
    d'imports (pour ne jamais mélanger deux versions d'un même paquet)."""
    results: Dict[str, Tuple[str, object]] = {}
    sys.path.insert(0, tmp)
    to_clear = [m for m in sys.modules if m == import_name or m.startswith(import_name + ".")]
    for m in to_clear:
        del sys.modules[m]
    try:
        for symbol in symbols:
            results[symbol] = _resolve_dotted_symbol(import_name, symbol)
    finally:
        sys.path.remove(tmp)
        for m in [m for m in sys.modules if m == import_name or m.startswith(import_name + ".")]:
            del sys.modules[m]
    return results


def get_package_api(
    package_name: str,
    version: str,
    symbols: Optional[List[str]] = None,
    import_name: Optional[str] = None,
    pip_extra_args: Optional[List[str]] = None,
) -> PackageAPI:
    """Installe `package_name==version` (une seule fois, réutilisé entre appels)
    et résout précisément chaque symbole imbriqué demandé dans `symbols`
    (ex. `["init", "core.close", "core.MyClass.method"]`).

    Stratégie en deux temps pour éviter les faux "symbole absent" causés par
    une dépendance manquante (ex. `pytesseract` important `PIL` au niveau
    module) :
    1. Installation rapide `--no-deps` et tentative de résolution.
    2. Pour les symboles restés "inconclusifs" (échec d'import, PAS échec
       d'attribut), repli automatique sur une installation complète AVEC
       dépendances, puis nouvelle tentative.
    Un symbole encore inconclusif après ce repli reste dans
    `PackageAPI.inconclusive` — jamais traité comme une preuve d'absence.

    `pip_extra_args` permet de cibler un registre privé/local plutôt que PyPI
    (ex. `["--no-index", "--find-links", "/chemin/vers/wheels"]`), utile en
    environnement air-gapped ou pour les tests. Peut aussi être fourni via la
    variable d'environnement `DEPSOLVER_PIP_EXTRA_ARGS`.
    """
    symbols = symbols or []
    key = (package_name, version)
    api = _API_CACHE.setdefault(key, PackageAPI(package=package_name, version=version))

    import_name = import_name or package_name.replace("-", "_")
    extra_args = _pip_extra_args_from_env(pip_extra_args)

    already_known = set(api.symbols) | set(api.inconclusive)
    missing = [s for s in symbols if s not in already_known]
    if not missing:
        return api

    def _store(symbol: str, status: str, obj) -> bool:
        """Renvoie True si le symbole reste inconclusif après ce round."""
        if status == "found":
            if inspect.isclass(obj):
                sig = _signature_of(getattr(obj, "__init__", None))
            else:
                sig = _signature_of(obj)
            if sig:
                logger.debug("symbole '%s' résolu dans %s==%s : %s", symbol, package_name, version, sig)
                api.symbols[symbol] = sig
                return False
            return True  # résolu mais pas introspectable (ex. constante) -> inconclusif
        if status == "absent":
            logger.debug("symbole '%s' confirmé ABSENT dans %s==%s (import réussi, attribut manquant)",
                         symbol, package_name, version)
            return False  # absence confirmée -> pas ajouté à symbols, pas inconclusif non plus
        return True  # "import_error"

    tmp_fast = _ensure_installed(package_name, version, extra_args, with_deps=False)
    still_inconclusive = list(missing)
    if tmp_fast is not None:
        resolved = _import_from_dir(tmp_fast, import_name, missing)
        still_inconclusive = [s for s in missing if _store(s, *resolved[s])]

    if still_inconclusive:
        logger.debug("%d symbole(s) inconclusif(s) pour %s==%s après install --no-deps, "
                     "repli sur une installation complète : %s",
                     len(still_inconclusive), package_name, version, still_inconclusive)
        tmp_full = _ensure_installed(package_name, version, extra_args, with_deps=True)
        if tmp_full is not None:
            resolved = _import_from_dir(tmp_full, import_name, still_inconclusive)
            still_inconclusive = [s for s in still_inconclusive if _store(s, *resolved[s])]
        if still_inconclusive:
            logger.debug("toujours inconclusif après installation complète pour %s==%s : %s",
                         package_name, version, still_inconclusive)
        for s in still_inconclusive:
            if s not in api.inconclusive:
                api.inconclusive.append(s)

    return api


def cleanup_installed_dirs() -> None:
    """Supprime les dossiers d'installation isolés accumulés pendant l'exécution
    (utile en fin de commande CLI pour ne pas laisser traîner des /tmp)."""
    import shutil

    for path in _INSTALL_DIRS.values():
        if path:
            shutil.rmtree(path, ignore_errors=True)
    _INSTALL_DIRS.clear()
    _API_CACHE.clear()


def is_api_compatible(calls: List[ApiCall], api: PackageAPI) -> ApiCompatibilityResult:
    incompatibilities: List[ApiIncompatibility] = []
    warnings: List[ApiIncompatibility] = []
    for call in calls:
        if call.callee_symbol in api.inconclusive:
            warnings.append(
                ApiIncompatibility(
                    call,
                    f"compatibilité de '{call.callee_symbol}' en version {api.version} NON déterminée "
                    f"(dépendance manquante empêchant l'import — ni confirmée compatible, ni confirmée cassée)",
                )
            )
            continue

        sig = api.symbols.get(call.callee_symbol)
        if sig is None:
            incompatibilities.append(
                ApiIncompatibility(
                    call,
                    f"symbole '{call.callee_symbol}' introuvable (module, classe ou méthode "
                    f"absent(e)/déplacé(e)) dans l'API en version {api.version}",
                )
            )
            continue
        if sig.has_var_keyword:
            continue  # **kwargs -> tout nom de paramètre est accepté
        unknown_kwargs = [k for k in call.kwarg_names if k not in sig.positional_params and k not in sig.kwonly_params]
        if unknown_kwargs:
            incompatibilities.append(
                ApiIncompatibility(
                    call,
                    f"paramètre(s) {unknown_kwargs} inconnu(s) de '{call.callee_symbol}' en version {api.version}",
                )
            )
            continue
        max_positional = len(sig.positional_params)
        if not sig.has_var_positional and call.arg_count > max_positional:
            incompatibilities.append(
                ApiIncompatibility(
                    call,
                    f"'{call.callee_symbol}' accepte {max_positional} argument(s) positionnel(s) en version "
                    f"{api.version}, {call.arg_count} fournis",
                )
            )
    return ApiCompatibilityResult(
        is_compatible=len(incompatibilities) == 0, incompatibilities=incompatibilities, warnings=warnings,
    )

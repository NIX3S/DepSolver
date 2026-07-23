"""Combine filtrage CVE + compatibilité API + resolver pour proposer le meilleur
ensemble de versions possible (le plus récent, sous contraintes).

En plus de la solution finale, on trace ici *toutes* les versions évaluées par
paquet (retenues ou écartées, avec CVE et raison) dans `OptimizeResult.evaluated` :
c'est cette trace complète qui alimente le rapport HTML/--explain (liste des
choix possibles + CVE associées, un peu comme un rapport pytest-html).

Transparence "vérifié / non vérifié" : une version peut être retenue sans que
la compatibilité API ait pu être formellement confirmée, dans deux cas bien
distincts (marqués `verified=False` dans les deux cas, mais avec un détail
différent) :
  - aucun appel n'a été détecté vers ce paquet dans le code analysé ;
  - un appel a été détecté, mais sa compatibilité n'a pas pu être déterminée
    (ex. dépendance tierce manquante empêchant l'import du paquet analysé —
    voir `api_analyzer.PackageAPI.inconclusive`). C'est un "je ne sais pas",
    jamais traité comme une preuve de breaking change.

Dégradation progressive des CVE (jamais de l'API) : si AUCUNE version d'un
paquet ne satisfait la politique CVE demandée (alors que des versions
satisfont par ailleurs les contraintes et l'API), on retente avec un plafond
de sévérité progressivement relevé -- en s'arrêtant au premier plafond qui
débloque une solution, jamais plus loin que nécessaire -- et on trace
clairement chaque dégradation (`OptimizeResult.cve_relaxations`).

Fenêtre de versions scannées (performance + "ne pas revenir en arrière sans
raison") : par défaut, on ne teste pas tout l'historique d'un paquet.
  - Si le paquet a une version actuellement épinglée (projet existant), on ne
    scanne QUE les versions >= cette version : on ne propose jamais une
    régression sans raison.
  - Sinon (nouvel ajout, pas de pin connu), on scanne seulement les 5
    versions les plus récentes.
Dans les deux cas, si rien de compatible n'est trouvé dans cette fenêtre, on
élargit automatiquement le scan (plus loin dans l'historique, ou en dessous
du pin existant en dernier recours) jusqu'à trouver une solution ou épuiser
l'historique -- en le signalant clairement (`OptimizeResult.version_scan_notes`).
`check_all_versions=True` (`--all-versions` en CLI) désactive cette
restriction et scanne tout l'historique d'emblée, comme avant."""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from . import api_analyzer, cve, versions
from .models import ApiCall, EvaluatedVersion, Rejection, Requirement
from .resolver import NoSolutionError, solve as resolver_solve

logger = logging.getLogger("depsolver.optimizer")

DEFAULT_WINDOW = 5


@dataclass
class CveRelaxation:
    package: str
    version: str
    base_policy: str
    accepted_ceiling_label: str
    cves: List[dict]


@dataclass
class VersionScanNote:
    package: str
    initial_scope: str
    widened_to_version: str
    reason: str


@dataclass
class OptimizeResult:
    solution: Dict[str, str]
    rejections: List[Rejection] = field(default_factory=list)
    evaluated: Dict[str, List[EvaluatedVersion]] = field(default_factory=dict)
    cve_relaxations: List[CveRelaxation] = field(default_factory=list)
    version_scan_notes: List[VersionScanNote] = field(default_factory=list)


@dataclass
class PinnedValidation:
    ok: bool
    rejections: List[Rejection] = field(default_factory=list)
    verified: Dict[str, bool] = field(default_factory=dict)  # paquet -> API vérifiée ?


def _filter_versions_at_ceiling(
    req: Requirement,
    versions_pool: List[str],
    all_calls: List[ApiCall],
    severity_ceiling: int,
    analyze_api: bool,
) -> Tuple[List[str], List[EvaluatedVersion], List[Rejection]]:
    from packaging.specifiers import SpecifierSet
    from packaging.version import Version

    spec = SpecifierSet(",".join(f"{op}{v}" for op, v in req.specs)) if req.specs else SpecifierSet()
    calls_to_this = [c for c in all_calls if c.callee_package == req.name]
    verified_possible = bool(analyze_api and calls_to_this)

    evaluated: List[EvaluatedVersion] = []
    rejections: List[Rejection] = []
    acceptable: List[str] = []

    for v in versions_pool:
        try:
            if req.specs and not spec.contains(Version(v), prereleases=False):
                evaluated.append(EvaluatedVersion(
                    package=req.name, version=v, status="excluded_spec",
                    detail=f"ne satisfait pas la contrainte {req.specs}",
                ))
                continue
        except Exception:
            continue

        cves = cve.get_cves(req.name, v)
        if not cve.is_acceptable_under_ceiling(cves, severity_ceiling):
            detail = f"CVE au-delà du plafond toléré ({cve.ceiling_label(severity_ceiling)})"
            rejections.append(Rejection(package=req.name, version=v, reason="cve", detail=detail))
            evaluated.append(EvaluatedVersion(package=req.name, version=v, status="excluded_cve", cves=cves, detail=detail))
            continue

        verified = False
        api_warning_detail = None
        if verified_possible:
            symbols = sorted({c.callee_symbol for c in calls_to_this})
            api = api_analyzer.get_package_api(req.name, v, symbols=symbols)
            compat = api_analyzer.is_api_compatible(calls_to_this, api)
            if not compat.is_compatible:
                detail = "; ".join(i.reason for i in compat.incompatibilities)
                rejections.append(Rejection(package=req.name, version=v, reason="api_incompatible", detail=detail))
                evaluated.append(EvaluatedVersion(package=req.name, version=v, status="excluded_api", cves=cves, detail=detail))
                continue
            if compat.warnings:
                api_warning_detail = "; ".join(w.reason for w in compat.warnings)
                verified = False
            else:
                verified = True

        acceptable.append(v)
        if verified:
            detail = "compatible : contraintes + CVE + API vérifiée sur les appels détectés"
        elif api_warning_detail:
            detail = f"retenue (contraintes + CVE) — {api_warning_detail}"
        elif analyze_api:
            detail = "retenue (contraintes + CVE) — aucun appel détecté vers ce paquet, compatibilité API NON vérifiée"
        else:
            detail = "retenue (contraintes + CVE) — analyse API désactivée (--analyze-api absent)"
        evaluated.append(EvaluatedVersion(package=req.name, version=v, status="kept", cves=cves, detail=detail, verified=verified))

    return acceptable, evaluated, rejections


def _filter_versions_with_cve_ladder(
    req: Requirement,
    versions_pool: List[str],
    all_calls: List[ApiCall],
    policy: str,
    analyze_api: bool,
    strict_cve: bool,
    cve_relaxations: List[CveRelaxation],
) -> Tuple[List[str], List[EvaluatedVersion], List[Rejection]]:
    """Applique le filtrage CVE+API sur un pool de versions déjà déterminé,
    avec la dégradation progressive de plafond CVE (voir docstring module)."""
    base_ceiling = cve.policy_to_ceiling(policy)
    acceptable, ev, rej = _filter_versions_at_ceiling(req, versions_pool, all_calls, base_ceiling, analyze_api)

    if not acceptable and not strict_cve:
        for ceiling in range(base_ceiling + 1, 5):
            acceptable2, ev2, rej2 = _filter_versions_at_ceiling(req, versions_pool, all_calls, ceiling, analyze_api)
            if acceptable2:
                logger.debug(
                    "%s : aucune version sous la politique '%s' dans le pool scanné, dégradation minimale vers %s",
                    req.name, policy, cve.ceiling_label(ceiling),
                )
                chosen_version = acceptable2[0]
                cves_for_chosen = next((e.cves for e in ev2 if e.version == chosen_version), [])
                cve_relaxations.append(CveRelaxation(
                    package=req.name, version=chosen_version, base_policy=policy,
                    accepted_ceiling_label=cve.ceiling_label(ceiling),
                    cves=[{"id": c.id, "severity": c.severity} for c in cves_for_chosen],
                ))
                for e in ev2:
                    if e.version == chosen_version and e.status == "kept":
                        e.detail = (
                            f"⚠ CVE dégradée automatiquement (aucune version ne satisfaisait '{policy}') "
                            f"— plafond accepté : {cve.ceiling_label(ceiling)} — {e.detail}"
                        )
                acceptable, ev, rej = acceptable2, ev2, rej2
                break

    return acceptable, ev, rej


def _filter_candidates(
    req: Requirement,
    all_calls: List[ApiCall],
    policy: str,
    analyze_api: bool,
    strict_cve: bool,
    current_pins: Dict[str, str],
    check_all_versions: bool,
    rejections: List[Rejection],
    evaluated: List[EvaluatedVersion],
    cve_relaxations: List[CveRelaxation],
    version_scan_notes: List[VersionScanNote],
) -> List[str]:
    from packaging.version import InvalidVersion, Version

    all_versions_desc = versions.list_versions(req.name)  # plus récent -> plus ancien
    floor = current_pins.get(req.name)
    floor_v = None
    if floor:
        try:
            floor_v = Version(floor)
        except InvalidVersion:
            floor_v = None

    def _ge_floor(v: str) -> bool:
        if floor_v is None:
            return True
        try:
            return Version(v) >= floor_v
        except InvalidVersion:
            return False

    if check_all_versions:
        pool = all_versions_desc
        remaining_above, remaining_below = [], []
        initial_scope = "tout l'historique (--all-versions)"
    else:
        # On filtre d'abord par le garde-fou (jamais de régression), PUIS on
        # limite aux DEFAULT_WINDOW plus récentes -- pas l'inverse -- pour
        # qu'une version pin proche du sommet de l'historique ne fasse pas
        # entrer une régression dans le lot initial.
        candidates_ge_floor = [v for v in all_versions_desc if _ge_floor(v)]
        candidates_below_floor = [v for v in all_versions_desc if not _ge_floor(v)]
        pool = candidates_ge_floor[:DEFAULT_WINDOW]
        remaining_above = candidates_ge_floor[DEFAULT_WINDOW:]
        remaining_below = candidates_below_floor
        initial_scope = (
            f"les {DEFAULT_WINDOW} versions les plus récentes (garde-fou : jamais en dessous de {floor})"
            if floor else f"les {DEFAULT_WINDOW} versions les plus récentes"
        )

    acceptable, ev, rej = _filter_versions_with_cve_ladder(
        req, pool, all_calls, policy, analyze_api, strict_cve, cve_relaxations,
    )

    if not acceptable and not check_all_versions:
        # Élargissement progressif : d'abord tout ce qui reste AU-DESSUS ou
        # ÉGAL au pin (jamais de régression), un cran à la fois ; seulement
        # si ça ne suffit toujours pas, on descend en dessous du pin en tout
        # dernier recours (cas "ça bloque avec une nouvelle lib qu'on veut
        # ajouter") -- avec un avertissement plus appuyé dans ce cas.
        for widen_group, below in ((remaining_above, False), (remaining_below, True)):
            if acceptable:
                break
            for v in widen_group:
                acceptable_v, ev_v, rej_v = _filter_versions_with_cve_ladder(
                    req, [v], all_calls, policy, analyze_api, strict_cve, cve_relaxations,
                )
                ev.extend(ev_v)
                rej.extend(rej_v)
                if acceptable_v:
                    reason = (
                        "aucune version >= la version épinglée n'était compatible ; "
                        "redescendu EN DESSOUS du pin actuel en dernier recours"
                        if below else
                        "aucune version compatible dans la fenêtre par défaut "
                        "(contraintes + CVE + API) ; scan élargi automatiquement"
                    )
                    logger.debug("%s : %s -> %s", req.name, reason, v)
                    version_scan_notes.append(VersionScanNote(
                        package=req.name, initial_scope=initial_scope, widened_to_version=v, reason=reason,
                    ))
                    acceptable = acceptable_v
                    break

    evaluated.extend(ev)
    rejections.extend(rej)
    return acceptable


def validate_pinned(
    pinned: Dict[str, str],
    all_calls: Optional[List[ApiCall]] = None,
    policy: str = "cve-no-critical",
    analyze_api: bool = True,
) -> PinnedValidation:
    """Valide un ensemble de versions déjà figées (sans chercher d'alternative) :
    vérifie CVE + compatibilité API exactement pour ces versions-là, y compris
    quand la contrainte est un pin exact (`==`) — un pin exact ne dispense pas
    de la vérification, il indique juste QUELLE version vérifier. Pas de
    dégradation CVE ici : `validate_pinned` répond à "cette version précise
    est-elle valide ?", pas "quelle version prendre à la place ?"."""
    all_calls = all_calls or []
    rejections: List[Rejection] = []
    verified: Dict[str, bool] = {}
    ceiling = cve.policy_to_ceiling(policy)
    for name, v in pinned.items():
        cves = cve.get_cves(name, v)
        logger.debug("validate_pinned: %s==%s : %d CVE trouvée(s)", name, v, len(cves))
        if not cve.is_acceptable_under_ceiling(cves, ceiling):
            rejections.append(
                Rejection(
                    package=name, version=v, reason="cve",
                    detail=f"CVE au-delà du plafond toléré ({cve.ceiling_label(ceiling)}): "
                    + ", ".join(c.id for c in cves),
                )
            )
            verified[name] = False
            continue
        calls_to_this = [c for c in all_calls if c.callee_package == name] if analyze_api else []
        if calls_to_this:
            symbols = sorted({c.callee_symbol for c in calls_to_this})
            api = api_analyzer.get_package_api(name, v, symbols=symbols)
            compat = api_analyzer.is_api_compatible(calls_to_this, api)
            verified[name] = compat.is_compatible and not compat.warnings
            if not compat.is_compatible:
                detail = "; ".join(i.reason for i in compat.incompatibilities)
                logger.debug("validate_pinned: %s==%s incompatible : %s", name, v, detail)
                rejections.append(Rejection(package=name, version=v, reason="api_incompatible", detail=detail))
        else:
            verified[name] = False
    return PinnedValidation(ok=len(rejections) == 0, rejections=rejections, verified=verified)


def find_best_versions_with_api(
    requirements: List[Requirement],
    policy: str,
    all_calls: Optional[List[ApiCall]] = None,
    analyze_api: bool = True,
    strict_cve: bool = False,
    current_pins: Optional[Dict[str, str]] = None,
    check_all_versions: bool = False,
) -> OptimizeResult:
    all_calls = all_calls or []
    current_pins = current_pins or {}
    rejections: List[Rejection] = []
    evaluated: Dict[str, List[EvaluatedVersion]] = {}
    cve_relaxations: List[CveRelaxation] = []
    version_scan_notes: List[VersionScanNote] = []

    allowed_versions: Dict[str, List[str]] = {}
    for req in requirements:
        pkg_evaluated: List[EvaluatedVersion] = []
        allowed_versions[req.name] = _filter_candidates(
            req, all_calls, policy, analyze_api, strict_cve, current_pins, check_all_versions,
            rejections, pkg_evaluated, cve_relaxations, version_scan_notes,
        )
        evaluated[req.name] = pkg_evaluated
        if not allowed_versions[req.name]:
            raise NoSolutionError(
                f"Aucune version de '{req.name}' ne satisfait à la fois les contraintes, "
                f"la politique CVE (même après tentative de dégradation) et la compatibilité API "
                f"(même après avoir élargi le scan à tout l'historique disponible).",
                blocking_package=req.name,
            )

    logger.debug("lancement du resolver avec %d paquet(s) racine", len(requirements))
    solution = resolver_solve(
        requirements,
        list_versions=versions.list_versions,
        get_dependencies=versions.get_dependencies,
        allowed_versions=allowed_versions,
    )
    logger.debug("solution retenue : %s", solution)

    # marque la version effectivement choisie dans la trace d'évaluation
    for name, chosen_version in solution.items():
        for ev in evaluated.get(name, []):
            if ev.version == chosen_version and ev.status == "kept":
                ev.status = "selected"

    # ne garde que les dégradations/élargissements qui concernent la solution
    # finalement retenue par le resolver global
    kept_relaxations = [r for r in cve_relaxations if solution.get(r.package) == r.version]
    kept_scan_notes = [n for n in version_scan_notes if solution.get(n.package) == n.widened_to_version]

    return OptimizeResult(
        solution=solution, rejections=rejections, evaluated=evaluated,
        cve_relaxations=kept_relaxations, version_scan_notes=kept_scan_notes,
    )

"""CLI `depsolver` : modes `solve` (from scratch ou vérification d'un input),
`check` (dossier local ou dépôt Git) et `compare` (deux environnements)."""
from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path
from typing import Dict, List, Optional

from . import api_analyzer, git_integration, project, report, tests_runner, versions
from .models import Requirement
from .optimizer import find_best_versions_with_api, validate_pinned
from .parser import (
    parse_requirement_line,
    parse_requirements_file,
    write_lock_file,
    write_requirements_txt,
)
from .resolver import NoSolutionError


def _configure_logging(debug: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if debug else logging.WARNING,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s" if debug else "%(message)s",
    )


def _merge_requirements(from_input: List[Requirement], from_cli: List[str]) -> List[Requirement]:
    merged: Dict[str, Requirement] = {r.name: r for r in from_input}
    for raw in from_cli:
        req = parse_requirement_line(raw)
        if req:
            merged[req.name] = req  # --require prime sur --input
    return list(merged.values())


def _pinned_validation_to_dict(pv) -> dict:
    return {
        "ok": pv.ok,
        "rejections": [r.__dict__ for r in pv.rejections],
        "verified": pv.verified,
    }


def _serialize_blocked_upgrades(blocked: Dict[str, list]) -> dict:
    return {
        pkg: [
            {"version": ev.version, "status": ev.status, "detail": ev.detail,
             "cves": [{"id": c.id, "severity": c.severity} for c in ev.cves]}
            for ev in evs
        ]
        for pkg, evs in blocked.items()
    }


def _emit_extra_outputs(
    args: argparse.Namespace, result, current: Dict[str, str], title: str, requirement_names: set,
) -> None:
    """Écrit les sorties optionnelles communes à `solve` et `check` :
    --lock, --html, --graphviz, --explain."""
    if getattr(args, "lock", None):
        write_lock_file(result.solution, args.lock, policy=args.policy)
        print(f"Lock écrit : {args.lock}")

    if getattr(args, "html", None):
        blocked = report.compute_blocked_upgrades(result.solution, result.evaluated)
        transitive = report.build_transitive_dependencies(requirement_names, result.solution, versions.get_dependencies)
        html_content = report.render_html(
            result.solution, result.evaluated, args.policy, current, title=title,
            cve_relaxations=[r.__dict__ for r in result.cve_relaxations],
            blocked_upgrades=blocked,
            requirement_names=requirement_names,
            transitive_dependencies=transitive,
        )
        report.write_html(html_content, args.html)
        print(f"Rapport HTML écrit : {args.html}")

    if getattr(args, "graphviz", None):
        edges = report.build_dependency_edges(result.solution, versions.get_dependencies)
        dot = report.render_graphviz(result.solution, edges, title=title)
        report.write_graphviz(dot, args.graphviz)
        print(f"Graphe Graphviz écrit : {args.graphviz} (rendu : dot -Tpng {args.graphviz} -o graph.png)")

    if getattr(args, "explain", None):
        pkg = args.explain
        print()
        print(report.render_explain(pkg, result.evaluated.get(pkg, [])))


def cmd_solve(args: argparse.Namespace) -> int:
    _configure_logging(args.debug)
    from_input: List[Requirement] = []

    if args.input:
        from_input = parse_requirements_file(args.input)

    requirements = _merge_requirements(from_input, args.require or [])
    if not requirements:
        print("Aucune exigence fournie (--require ou --input).", file=sys.stderr)
        return 2

    # Tout pin exact (==) — qu'il vienne de --input ou de --require — est
    # traité comme un point de départ ("j'ai/je veux au moins cette version"),
    # pas comme un verrou strict : `pytesseract==0.2.0` déclenche par défaut
    # une recherche vers les versions plus récentes (fenêtre par défaut, cf.
    # optimizer.py), jamais un retour en arrière, sauf via --input pinné +
    # --check-only qui, eux, valident explicitement CETTE version précise.
    current: Dict[str, str] = {
        r.name: r.specs[0][1] for r in requirements if len(r.specs) == 1 and r.specs[0][0] == "=="
    }

    # Vérifie le(s) pin(s) exact(s) réellement (CVE + API), même s'ils sont en
    # "==" : un pin exact indique QUELLE version vérifier, il ne dispense pas
    # de la vérification.
    pinned_validation = None
    if current:
        pinned_validation = validate_pinned(current, all_calls=[], policy=args.policy, analyze_api=args.analyze_api)

    # Recherche systématique de la meilleure solution possible, y compris en
    # --check-only : la validation du pin et la recherche de la meilleure
    # alternative sont deux informations distinctes, toutes deux toujours
    # produites (voir README). Sauf si --exact-pins : dans ce cas un pin ==
    # est un verrou strict, pas un point de départ -- on ne relâche rien et
    # on ne fournit pas de garde-fou "floor" au resolver (la contrainte ==
    # suffit à elle seule à forcer exactement cette version).
    if args.exact_pins:
        search_requirements = requirements
        floor_pins: Dict[str, str] = {}
    else:
        search_requirements = [
            Requirement(name=r.name, specs=[s for s in r.specs if s[0] != "=="]) if r.name in current else r
            for r in requirements
        ]
        floor_pins = current

    try:
        result = find_best_versions_with_api(
            search_requirements, policy=args.policy, all_calls=[], analyze_api=args.analyze_api,
            strict_cve=args.strict_cve, current_pins=floor_pins, check_all_versions=args.all_versions,
        )
    except NoSolutionError as exc:
        rep = {
            "status": "no_solution",
            "current": current or None,
            "pinned_validation": _pinned_validation_to_dict(pinned_validation) if pinned_validation else None,
            "problems": [str(exc)],
        }
        if args.json:
            print(__import__("json").dumps(rep, indent=2, ensure_ascii=False))
        else:
            if pinned_validation:
                print(report.render_text_solve({
                    "status": "invalid" if not pinned_validation.ok else "ok",
                    "current": current, "solution": {}, "rejections": [],
                    "pinned_validation": _pinned_validation_to_dict(pinned_validation),
                }))
            print(f"Échec de la recherche d'alternative : {exc}", file=sys.stderr)
        api_analyzer.cleanup_installed_dirs()
        return 1

    rep = report.build_solve_report(result.solution, result.rejections, args.policy, current or None, result.cve_relaxations, result.version_scan_notes)
    rep["pinned_validation"] = _pinned_validation_to_dict(pinned_validation) if pinned_validation else None
    blocked = report.compute_blocked_upgrades(result.solution, result.evaluated)
    rep["blocked_upgrades"] = _serialize_blocked_upgrades(blocked)

    if args.json:
        print(__import__("json").dumps(rep, indent=2, ensure_ascii=False))
    else:
        print(report.render_text_solve(rep))
        print(report.render_text_blocked_upgrades(blocked))

    # Sortie systématique d'un fichier avec les meilleures versions possibles,
    # que --check-only soit utilisé ou non (option activée par défaut).
    if args.output:
        write_requirements_txt(result.solution, args.output)
        if not args.json:
            print(f"\nFichier écrit : {args.output}")

    _emit_extra_outputs(args, result, current or None, "Rapport depsolver — solve",
                         {r.name for r in requirements})
    api_analyzer.cleanup_installed_dirs()

    if args.check_only and pinned_validation is not None:
        return 1 if not pinned_validation.ok else 0
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    _configure_logging(args.debug)
    project_path = Path(args.path) if args.path else None

    if args.repo:
        project_path = git_integration.clone_repo(
            args.repo, branch=args.branch, token=args.git_token, use_cache=not args.no_repo_cache,
        )
        print(f"Dépôt cloné dans : {project_path}")

    if project_path is None:
        print("--path ou --repo requis.", file=sys.stderr)
        return 2

    current_reqs = project.extract_current_requirements(project_path)
    current = {
        r.name: r.specs[0][1] for r in current_reqs if len(r.specs) == 1 and r.specs[0][0] == "=="
    }
    all_calls = project.extract_project_calls(project_path)

    # Vérifie réellement les versions actuellement figées dans le dépôt (même
    # en pin exact ==) : CVE + compatibilité API, avant même de chercher mieux.
    pinned_validation = validate_pinned(current, all_calls=all_calls, policy=args.policy, analyze_api=args.analyze_api) if current else None

    if args.exact_pins:
        search_reqs = current_reqs
        floor_pins: Dict[str, str] = {}
    else:
        search_reqs = [
            Requirement(name=r.name, specs=[s for s in r.specs if s[0] != "=="]) if r.name in current else r
            for r in current_reqs
        ]
        floor_pins = current

    try:
        result = find_best_versions_with_api(
            search_reqs, policy=args.policy, all_calls=all_calls, analyze_api=args.analyze_api,
            strict_cve=args.strict_cve, current_pins=floor_pins, check_all_versions=args.all_versions,
        )
    except NoSolutionError as exc:
        print(f"Échec de l'analyse : {exc}", file=sys.stderr)
        if pinned_validation and not pinned_validation.ok:
            print("De plus, les versions actuellement figées présentent des problèmes :", file=sys.stderr)
            for r in pinned_validation.rejections:
                print(f"  - {r.package} {r.version} : {r.reason} — {r.detail}", file=sys.stderr)
        api_analyzer.cleanup_installed_dirs()
        return 1

    test_result = None
    if args.tests:
        run = tests_runner.run_tests_with_solution(project_path, result.solution, args.tests)
        test_result = {
            "command": args.tests, "ran": run.ran, "passed": run.passed,
            "returncode": run.returncode, "reason": run.reason,
        }

    blocked = report.compute_blocked_upgrades(result.solution, result.evaluated)
    rep = report.build_check_report(
        current, result.solution, result.rejections, args.policy, test_result,
        pinned_validation=_pinned_validation_to_dict(pinned_validation) if pinned_validation else None,
        cve_relaxations=result.cve_relaxations,
        version_scan_notes=result.version_scan_notes,
    )
    rep["blocked_upgrades"] = _serialize_blocked_upgrades(blocked)

    if args.json:
        print(__import__("json").dumps(rep, indent=2, ensure_ascii=False))
    else:
        print(report.render_text_solve({
            "solution": result.solution, "current": current, "changed": rep["changed"],
            "rejections": rep["rejections"], "status": "ok",
            "pinned_validation": rep["pinned_validation"],
        }))
        print(report.render_text_blocked_upgrades(blocked))
        if test_result:
            status = "OK" if test_result["passed"] else "ÉCHEC"
            print(f"\nTests ({test_result['command']}) : {status}")

    if args.output:
        report.write_json(rep, args.output)
        print(f"Rapport JSON écrit : {args.output}")

    # Sortie systématique d'un fichier requirements avec les meilleures
    # versions trouvées, indépendamment de --dry-run (qui ne concerne que le
    # dépôt/projet analysé, jamais modifié en place par depsolver).
    write_requirements_txt(result.solution, args.best_output)
    print(f"Meilleures versions écrites : {args.best_output}")

    _emit_extra_outputs(args, result, current, "Rapport depsolver — check",
                         {r.name for r in current_reqs})
    api_analyzer.cleanup_installed_dirs()

    if pinned_validation is not None and not pinned_validation.ok:
        return 1
    return 0


def _load_pinned_dict(path: str) -> Dict[str, str]:
    reqs = parse_requirements_file(path)
    result = {}
    for r in reqs:
        if len(r.specs) == 1 and r.specs[0][0] == "==":
            result[r.name] = r.specs[0][1]
        elif r.specs:
            result[r.name] = "".join(f"{op}{v}" for op, v in r.specs)
        else:
            result[r.name] = None
    return result


def cmd_compare(args: argparse.Namespace) -> int:
    _configure_logging(args.debug)
    env1 = _load_pinned_dict(args.env1)
    env2 = _load_pinned_dict(args.env2)

    rep = report.build_compare_report(args.name1, env1, args.name2, env2)

    if args.json:
        print(__import__("json").dumps(rep, indent=2, ensure_ascii=False))
    else:
        print(report.render_text_compare(rep))

    if args.html:
        report.write_html(report.render_html_compare(rep), args.html)
        print(f"Rapport HTML écrit : {args.html}")

    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="depsolver")
    sub = parser.add_subparsers(dest="command", required=True)

    p_solve = sub.add_parser("solve", help="Résout un ensemble de requirements (from scratch ou vérification)")
    p_solve.add_argument("--require", action="append", help="Exigence de paquet (répétable)")
    p_solve.add_argument("--input", help="Fichier requirements existant (loose ou pinné)")
    p_solve.add_argument("--check-only", action="store_true",
                          help="Le code de retour reflète la validité du pin --input ; "
                               "la meilleure alternative est quand même calculée et écrite")
    p_solve.add_argument("--output", default="depsolver-solution.txt",
                          help="Fichier de sortie requirements.txt (toujours écrit ; défaut: %(default)s)")
    p_solve.add_argument("--lock", help="Fichier requirements.lock (optionnel)")
    p_solve.add_argument("--html", help="Fichier de sortie HTML (rapport graphique optionnel)")
    p_solve.add_argument("--graphviz", help="Fichier .dot du graphe de dépendances (optionnel)")
    p_solve.add_argument("--explain", metavar="PACKAGE", help="Explique en détail les choix pour ce paquet")
    p_solve.add_argument("--policy", default="cve-no-critical",
                          choices=["cve-none", "cve-no-critical", "cve-custom"])
    p_solve.add_argument("--analyze-api", action="store_true")
    p_solve.add_argument("--strict-cve", action="store_true",
                          help="Désactive la dégradation automatique de la politique CVE : échoue "
                               "plutôt que de relever le plafond de sévérité toléré en dernier recours")
    p_solve.add_argument("--all-versions", action="store_true",
                          help="Scanne tout l'historique des versions au lieu de se limiter par défaut "
                               "aux versions >= le pin actuel (ou aux 5 dernières si pas de pin)")
    p_solve.add_argument("--exact-pins", action="store_true",
                          help="Traite tout pin == comme un verrou strict (exactement cette version) "
                               "au lieu d'un point de départ pour chercher mieux. Sans ce flag, "
                               "'pytesseract==0.2.0' déclenche une recherche vers plus récent ; "
                               "avec --exact-pins, il reste figé exactement à 0.2.0.")
    p_solve.add_argument("--json", action="store_true")
    p_solve.add_argument("--verbose", action="store_true")
    p_solve.add_argument("--debug", action="store_true", help="Logs détaillés (réseau, backtracking, résolution d'API)")
    p_solve.set_defaults(func=cmd_solve)

    p_check = sub.add_parser("check", help="Analyse un projet local ou un dépôt Git")
    p_check.add_argument("--path", help="Dossier local du projet")
    p_check.add_argument("--repo", help="URL du dépôt GitHub/GitLab")
    p_check.add_argument("--git-token", help="Token d'accès Git")
    p_check.add_argument("--branch", help="Branche à analyser")
    p_check.add_argument("--no-repo-cache", action="store_true",
                          help="Force un clone frais au lieu de réutiliser le cache local (~/.cache/depsolver/repos)")
    p_check.add_argument("--policy", default="cve-no-critical",
                          choices=["cve-none", "cve-no-critical", "cve-custom"])
    p_check.add_argument("--tests", help="Commande de tests, ex. 'pytest tests/'")
    p_check.add_argument("--analyze-api", action="store_true")
    p_check.add_argument("--strict-cve", action="store_true",
                          help="Désactive la dégradation automatique de la politique CVE : échoue "
                               "plutôt que de relever le plafond de sévérité toléré en dernier recours")
    p_check.add_argument("--all-versions", action="store_true",
                          help="Scanne tout l'historique des versions au lieu de se limiter par défaut "
                               "aux versions >= le pin actuel (ou aux 5 dernières si pas de pin)")
    p_check.add_argument("--exact-pins", action="store_true",
                          help="Traite chaque version figée du projet comme un verrou strict "
                               "(exactement cette version) au lieu d'un point de départ pour "
                               "chercher mieux — n'a alors d'utilité qu'avec --tests, pour valider "
                               "l'existant tel quel sans proposer de mise à jour.")
    p_check.add_argument("--output", help="Fichier de rapport JSON (optionnel)")
    p_check.add_argument("--best-output", default="depsolver-best-requirements.txt",
                          help="Fichier requirements.txt des meilleures versions (toujours écrit ; défaut: %(default)s)")
    p_check.add_argument("--lock", help="Fichier requirements.lock (optionnel)")
    p_check.add_argument("--html", help="Fichier de sortie HTML (rapport graphique optionnel)")
    p_check.add_argument("--graphviz", help="Fichier .dot du graphe de dépendances (optionnel)")
    p_check.add_argument("--explain", metavar="PACKAGE", help="Explique en détail les choix pour ce paquet")
    p_check.add_argument("--dry-run", action="store_true", default=True,
                          help="N'écrit jamais dans le projet/dépôt analysé (depsolver n'y écrit de toute façon jamais)")
    p_check.add_argument("--apply", action="store_true")
    p_check.add_argument("--json", action="store_true")
    p_check.add_argument("--debug", action="store_true", help="Logs détaillés (réseau, backtracking, résolution d'API)")
    p_check.set_defaults(func=cmd_check)

    p_compare = sub.add_parser("compare", help="Compare deux environnements Python (deux requirements.txt)")
    p_compare.add_argument("--env1", required=True, help="Fichier requirements du premier environnement")
    p_compare.add_argument("--env2", required=True, help="Fichier requirements du second environnement")
    p_compare.add_argument("--name1", default="env1")
    p_compare.add_argument("--name2", default="env2")
    p_compare.add_argument("--json", action="store_true")
    p_compare.add_argument("--html", help="Fichier de sortie HTML (optionnel)")
    p_compare.add_argument("--debug", action="store_true")
    p_compare.set_defaults(func=cmd_compare)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())

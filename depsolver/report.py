"""Génération de rapports : texte lisible, JSON structuré, HTML autonome,
explication détaillée par paquet, export Graphviz du graphe de dépendances,
et comparaison entre deux environnements."""
from __future__ import annotations

import html
import json
from typing import Callable, Dict, List, Optional, Tuple

from .models import EvaluatedVersion, Rejection


def _version_sort_key(version_str: str):
    """Tri par version sémantique (pas alphabétique) : '10.0' doit venir
    après '2.0'. Retombe sur une comparaison textuelle si la version n'est
    pas parseable (ex. tag Git non standard)."""
    from packaging.version import InvalidVersion, Version
    try:
        return (0, Version(version_str))
    except InvalidVersion:
        return (1, version_str)


def build_solve_report(
    solution: Dict[str, str],
    rejections: List[Rejection],
    policy: str,
    current: Optional[Dict[str, str]] = None,
    cve_relaxations: Optional[list] = None,
    version_scan_notes: Optional[list] = None,
) -> dict:
    report = {
        "status": "ok",
        "solution": solution,
        "rejections": [r.__dict__ for r in rejections],
        "policy": policy,
        "cve_relaxations": [r.__dict__ for r in (cve_relaxations or [])],
        "version_scan_notes": [n.__dict__ for n in (version_scan_notes or [])],
    }
    if current is not None:
        report["current"] = current
        report["changed"] = {
            name: {"from": current.get(name), "to": version}
            for name, version in solution.items()
            if current.get(name) != version
        }
    return report


def build_check_report(
    current: Dict[str, str],
    proposed: Dict[str, str],
    rejections: List[Rejection],
    policy: str,
    test_result: Optional[dict] = None,
    pinned_validation: Optional[dict] = None,
    cve_relaxations: Optional[list] = None,
    version_scan_notes: Optional[list] = None,
) -> dict:
    return {
        "current": current,
        "proposed": proposed,
        "changed": {
            name: {"from": current.get(name), "to": version}
            for name, version in proposed.items()
            if current.get(name) != version
        },
        "rejections": [r.__dict__ for r in rejections],
        "policy": policy,
        "tests": test_result,
        "pinned_validation": pinned_validation,
        "cve_relaxations": [r.__dict__ for r in (cve_relaxations or [])],
        "version_scan_notes": [n.__dict__ for n in (version_scan_notes or [])],
    }


def render_text_solve(report: dict) -> str:
    lines = []
    if report.get("version_scan_notes"):
        lines.append("🔍 SCAN DE VERSIONS ÉLARGI (rien de compatible dans la fenêtre par défaut) :")
        for n in report["version_scan_notes"]:
            lines.append(f"  - {n['package']} : fenêtre initiale = {n['initial_scope']} "
                         f"→ élargi jusqu'à {n['widened_to_version']}")
        lines.append("")
    if report.get("cve_relaxations"):
        lines.append("⚠️  DÉGRADATION CVE APPLIQUÉE (aucune version ne satisfaisait la politique stricte) :")
        for r in report["cve_relaxations"]:
            cve_list = ", ".join(f"{c['id']}({c.get('severity') or '?'})" for c in r["cves"]) or "CVE de sévérité inconnue"
            lines.append(f"  - {r['package']}=={r['version']} : politique '{r['base_policy']}' non satisfaite, "
                         f"accepté jusqu'à {r['accepted_ceiling_label']} — {cve_list}")
        lines.append("")
    if report.get("current"):
        lines.append("Vérification de l'existant :")
        for name, version in report["current"].items():
            lines.append(f"  {name} == {version}")
        lines.append("")
    if report.get("pinned_validation"):
        pv = report["pinned_validation"]
        lines.append("Validation des versions figées (réelle, même en pin exact ==) :")
        lines.append(f"  {'OK' if pv['ok'] else 'PROBLÈME(S) DÉTECTÉ(S)'}")
        rejected_packages = {r["package"] for r in pv.get("rejections", [])}
        for r in pv.get("rejections", []):
            lines.append(f"    - {r['package']} {r['version']} : {r['reason']} — {r['detail']}")
        unverified = [
            p for p, v in pv.get("verified", {}).items() if not v and p not in rejected_packages
        ]
        if unverified:
            lines.append(f"  (compatibilité API non confirmée pour : {', '.join(unverified)} — "
                         f"aucun appel détecté vers ce paquet dans le code analysé)")
        lines.append("")
    lines.append("Solution retenue :" if report["status"] == "ok" else "Aucune solution trouvée :")
    for name, version in report.get("solution", {}).items():
        lines.append(f"  {name} == {version}")
    if report.get("changed"):
        lines.append("")
        lines.append("Changements proposés :")
        for name, ch in report["changed"].items():
            lines.append(f"  {name}: {ch['from']} -> {ch['to']}")
    if report["rejections"]:
        lines.append("")
        lines.append("Versions écartées :")
        for r in report["rejections"]:
            lines.append(f"  {r['package']} {r['version']} : {r['reason']} — {r['detail']}")
    return "\n".join(lines)


def write_json(report: dict, path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)


# ------------------------------------------------------------ upgrade horizon --

def compute_blocked_upgrades(
    solution: Dict[str, str],
    evaluated: Dict[str, List[EvaluatedVersion]],
) -> Dict[str, List[EvaluatedVersion]]:
    """Pour chaque paquet, liste les versions plus récentes que celle retenue
    qui ont été écartées (CVE ou breaking change), triées de la plus récente
    à la plus proche de la version retenue. C'est la réponse à "qu'est-ce qui
    casserait si je forçais une version plus récente ?" — la version retenue
    par `solve`/`check` reste la version sûre ; ceci montre l'horizon
    au-delà, avec le détail exact de ce qui bloque."""
    from packaging.version import InvalidVersion, Version

    blocked: Dict[str, List[EvaluatedVersion]] = {}
    for name, selected in solution.items():
        try:
            selected_v = Version(selected)
        except InvalidVersion:
            continue
        newer_blocked = []
        for ev in evaluated.get(name, []):
            if ev.status not in ("excluded_api", "excluded_cve"):
                continue
            try:
                v = Version(ev.version)
            except InvalidVersion:
                continue
            if v > selected_v:
                newer_blocked.append(ev)
        if newer_blocked:
            newer_blocked.sort(key=lambda e: Version(e.version), reverse=True)
            blocked[name] = newer_blocked
    return blocked


def render_text_blocked_upgrades(blocked: Dict[str, List[EvaluatedVersion]]) -> str:
    if not blocked:
        return ""
    lines = ["", "Versions plus récentes disponibles mais écartées (ce qui casserait si vous forciez la mise à jour) :"]
    for pkg, evs in blocked.items():
        lines.append(f"  {pkg} :")
        for ev in evs:
            reason_word = "BREAKING CHANGE" if ev.status == "excluded_api" else "CVE"
            lines.append(f"    {pkg}=={ev.version} [{reason_word}] : {ev.detail}")
    return "\n".join(lines)


def _blocked_upgrades_html(blocked: Dict[str, List[EvaluatedVersion]]) -> str:
    if not blocked:
        return ""
    sections = []
    for pkg, evs in blocked.items():
        rows = []
        for ev in evs:
            reason_word = "Breaking change" if ev.status == "excluded_api" else "CVE"
            rows.append(
                f"<li><code>{html.escape(pkg)}=={html.escape(ev.version)}</code> "
                f"<span class=\"badge status-excluded\">{html.escape(reason_word)}</span> "
                f"— {html.escape(ev.detail)}</li>"
            )
        sections.append(f"<strong>{html.escape(pkg)}</strong><ul>{''.join(rows)}</ul>")
    return (
        '<h2>🔺 Versions plus récentes disponibles mais écartées</h2>'
        '<p class="subtitle">Ce qui casserait dans le code analysé si vous forciez une mise à jour '
        'au-delà de la version retenue ci-dessus — pour juger si ça vaut le coup de corriger le code '
        'et retenter.</p>'
        f'<div>{"".join(sections)}</div>'
    )


# ------------------------------------------------------------------ explain --

def render_explain(package: str, evaluated: List[EvaluatedVersion]) -> str:
    """Explication détaillée, lisible, de pourquoi chaque version d'un paquet a
    été retenue ou écartée — le mode `--explain`."""
    lines = [f"Explication détaillée pour '{package}' :", ""]
    if not evaluated:
        lines.append("  (aucune version évaluée — le paquet n'a pas été demandé, ou aucune "
                      "version n'a pu être listée)")
        return "\n".join(lines)

    for ev in sorted(evaluated, key=lambda e: e.version, reverse=True):
        header = f"  {package}=={ev.version}"
        if ev.status == "selected":
            header += "  [RETENUE]"
        elif ev.status == "kept":
            header += "  [compatible, non retenue]" if not ev.verified else "  [compatible]"
        else:
            header += "  [écartée]"
        lines.append(header)
        lines.append(f"    raison   : {ev.detail}")
        if ev.status in ("kept", "selected"):
            lines.append(f"    API vérifiée : {'oui' if ev.verified else 'NON (aucun appel détecté)'}")
        if ev.cves:
            lines.append("    CVE      : " + ", ".join(f"{c.id}({c.severity or '?'})" for c in ev.cves))
        lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------- graphviz --

def build_dependency_edges(
    solution: Dict[str, str],
    get_dependencies: Callable[[str, str], list],
) -> List[Tuple[str, str]]:
    """Reconstruit les arêtes (parent -> dépendance) du graphe résolu, en ne
    gardant que les dépendances qui font elles-mêmes partie de la solution
    (les dépendances "externes" au périmètre demandé ne sont pas affichées)."""
    edges: List[Tuple[str, str]] = []
    for name, version in solution.items():
        try:
            deps = get_dependencies(name, version)
        except Exception:
            deps = []
        for dep in deps:
            dep_name = getattr(dep, "name", None)
            if dep_name and dep_name in solution:
                edges.append((name, dep_name))
    return edges


def build_transitive_dependencies(
    requirement_names,
    solution: Dict[str, str],
    get_dependencies: Callable[[str, str], list],
) -> List[dict]:
    """Liste les paquets de la solution qui ne sont PAS des dépendances
    explicitement demandées (`requirement_names`) — les sous-dépendances
    apportées transitivement — avec leur provenance (quel(s) paquet(s) de la
    solution en dépendent). Ne force rien à afficher : c'est à l'appelant
    (rapport HTML) de les cacher derrière un bouton par défaut."""
    edges = build_dependency_edges(solution, get_dependencies)
    parents_of: Dict[str, List[str]] = {}
    for parent, child in edges:
        parents_of.setdefault(child, []).append(parent)

    transitive = []
    for name, version in solution.items():
        if name in requirement_names:
            continue
        transitive.append({
            "name": name,
            "version": version,
            "brought_in_by": sorted(set(parents_of.get(name, []))),
        })
    transitive.sort(key=lambda d: d["name"])
    return transitive



def render_graphviz(
    solution: Dict[str, str],
    edges: List[Tuple[str, str]],
    title: str = "Dépendances depsolver",
) -> str:
    """Génère un fichier .dot (Graphviz) du graphe de dépendances résolu.
    Rendu en image avec `dot -Tpng graph.dot -o graph.png` (Graphviz doit être
    installé côté utilisateur ; depsolver ne fait que produire le .dot)."""
    lines = [f'digraph "{title}" {{', '  rankdir=LR;', '  node [shape=box, style=rounded, fontname="Helvetica"];']
    for name, version in sorted(solution.items()):
        label = f"{name}\\n{version}".replace('"', '\\"')
        lines.append(f'  "{name}" [label="{label}"];')
    for parent, child in sorted(set(edges)):
        lines.append(f'  "{parent}" -> "{child}";')
    lines.append("}")
    return "\n".join(lines)


def write_graphviz(dot_content: str, path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        f.write(dot_content)


# -------------------------------------------------------------------- html --

_STATUS_LABELS = {
    "selected": ("Retenue", "status-selected"),
    "kept": ("Compatible", "status-kept"),
    "excluded_spec": ("Hors contrainte", "status-excluded"),
    "excluded_cve": ("Écartée (CVE)", "status-excluded"),
    "excluded_api": ("Écartée (breaking change)", "status-excluded"),
}

_HTML_STYLE = """
body { font-family: -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif;
       margin: 2rem; color: #1b1f23; background: #fafbfc; }
h1 { font-size: 1.5rem; margin-bottom: 0.25rem; }
.subtitle { color: #57606a; margin-top: 0; margin-bottom: 1.5rem; }
.summary { display: flex; gap: 1rem; flex-wrap: wrap; margin-bottom: 2rem; }
.card { background: white; border: 1px solid #d0d7de; border-radius: 8px;
        padding: 0.75rem 1rem; min-width: 160px; }
.card .label { font-size: 0.75rem; color: #57606a; text-transform: uppercase; letter-spacing: .04em; }
.card .value { font-size: 1.1rem; font-weight: 600; margin-top: 2px; }
table { border-collapse: collapse; width: 100%; margin-bottom: 2rem; background: white; }
th, td { border: 1px solid #d0d7de; padding: 6px 10px; text-align: left; font-size: 0.9rem; }
th { background: #f6f8fa; }
tr.status-selected td { background: #dafbe1; font-weight: 600; }
tr.status-excluded td { color: #6e7781; }
.badge { display: inline-block; padding: 1px 8px; border-radius: 999px; font-size: 0.75rem; font-weight: 600; }
.badge.status-selected { background: #2da44e; color: white; }
.badge.status-kept { background: #ddf4ff; color: #0969da; }
.badge.status-excluded { background: #ffebe9; color: #cf222e; }
.badge.unverified { background: #fff8c5; color: #9a6700; margin-left: 4px; }
.cve { display: inline-block; background: #fff1e5; color: #9a6700; border-radius: 4px;
       padding: 0 6px; margin: 1px; font-size: 0.75rem; }
.section-title { margin-top: 2rem; font-size: 1.1rem; }
code { background: #f6f8fa; padding: 1px 5px; border-radius: 4px; }
footer { color: #6e7781; font-size: 0.8rem; margin-top: 2rem; }
details.pkg-accordion { background: white; border: 1px solid #d0d7de; border-radius: 8px;
       margin-bottom: 0.75rem; padding: 0; }
details.pkg-accordion summary { cursor: pointer; padding: 0.6rem 1rem; font-weight: 600;
       list-style: none; display: flex; justify-content: space-between; align-items: center; }
details.pkg-accordion summary::-webkit-details-marker { display: none; }
details.pkg-accordion summary::after { content: "▾"; color: #57606a; }
details.pkg-accordion[open] summary::after { content: "▴"; }
details.pkg-accordion summary .summary-meta { font-weight: 400; color: #57606a; font-size: 0.85rem; }
details.pkg-accordion table { margin: 0; border: none; }
.filter-box { width: 100%; max-width: 320px; padding: 6px 10px; border: 1px solid #d0d7de;
       border-radius: 6px; margin: 0.5rem 0; font-size: 0.9rem; }
.transitive-item { padding: 4px 0; border-bottom: 1px solid #f0f2f4; font-size: 0.9rem; }
.provenance { color: #57606a; font-size: 0.8rem; }
"""


def _status_badge(status: str, verified: bool = True) -> str:
    label, css_class = _STATUS_LABELS.get(status, (status, "status-kept"))
    out = f'<span class="badge {css_class}">{html.escape(label)}</span>'
    if status in ("kept", "selected") and not verified:
        out += ' <span class="badge unverified" title="Aucun appel détecté vers ce paquet : compatibilité API non confirmée">API non vérifiée</span>'
    return out


def _cve_badges(cves: List[dict]) -> str:
    if not cves:
        return "<em>aucune</em>"
    parts = []
    for c in cves:
        sev = f" ({c['severity']})" if c.get("severity") else ""
        parts.append(f'<span class="cve">{html.escape(c["id"])}{html.escape(sev)}</span>')
    return " ".join(parts)


def render_html(
    solution: Dict[str, str],
    evaluated: Dict[str, List[EvaluatedVersion]],
    policy: str,
    current: Optional[Dict[str, str]] = None,
    title: str = "Rapport depsolver",
    cve_relaxations: Optional[List[dict]] = None,
    blocked_upgrades: Optional[Dict[str, List[EvaluatedVersion]]] = None,
    requirement_names: Optional[set] = None,
    transitive_dependencies: Optional[List[dict]] = None,
) -> str:
    """Génère un rapport HTML autonome (une seule page, pas de dépendance externe)
    listant, pour chaque paquet, toutes les versions évaluées avec leur statut,
    un indicateur "API non vérifiée" quand c'est le cas, et les CVE associées."""
    current = current or {}
    cve_relaxations = cve_relaxations or []

    relax_html = ""
    if cve_relaxations:
        rows = []
        for r in cve_relaxations:
            cve_list = ", ".join(f"{c['id']} ({c.get('severity') or '?'})" for c in r["cves"]) or "sévérité inconnue"
            rows.append(
                f"<li><code>{html.escape(r['package'])}=={html.escape(r['version'])}</code> — "
                f"politique <code>{html.escape(r['base_policy'])}</code> non satisfaisable, "
                f"accepté jusqu'à <strong>{html.escape(r['accepted_ceiling_label'])}</strong> "
                f"({html.escape(cve_list)})</li>"
            )
        relax_html = (
            '<div style="background:#fff8c5;border:1px solid #d4a72c;border-radius:8px;'
            'padding:0.75rem 1rem;margin-bottom:1.5rem;">'
            '<strong>⚠️ Dégradation CVE appliquée</strong> — aucune version ne satisfaisait la '
            'politique stricte demandée ; le plafond de sévérité toléré a été relevé au minimum '
            f"nécessaire pour les paquets suivants :<ul>{''.join(rows)}</ul></div>"
        )

    summary_cards = [
        f'<div class="card"><div class="label">Politique CVE</div><div class="value">{html.escape(policy)}</div></div>',
        f'<div class="card"><div class="label">Paquets résolus</div><div class="value">{len(solution)}</div></div>',
    ]
    changed = {n: v for n, v in solution.items() if current.get(n) != v}
    if current:
        summary_cards.append(
            f'<div class="card"><div class="label">Mises à jour proposées</div><div class="value">{len(changed)}</div></div>'
        )

    solution_rows = []
    top_level_names = set(requirement_names) if requirement_names is not None else set(solution.keys())
    for name, version in sorted(solution.items()):
        if name not in top_level_names:
            continue
        from_v = current.get(name)
        change = f'{html.escape(from_v)} &rarr; <strong>{html.escape(version)}</strong>' if from_v and from_v != version else html.escape(version)
        solution_rows.append(f"<tr><td><code>{html.escape(name)}</code></td><td>{change}</td></tr>")

    sections = []
    for name in sorted(evaluated.keys()):
        rows = []
        selected_version = None
        for ev in sorted(evaluated[name], key=lambda e: _version_sort_key(e.version), reverse=True):
            if ev.status == "selected":
                selected_version = ev.version
            cves_serialized = [{"id": c.id, "severity": c.severity} for c in ev.cves]
            rows.append(
                "<tr class=\"{cls}\">"
                f"<td>{html.escape(ev.version)}</td>"
                f"<td>{_status_badge(ev.status, ev.verified)}</td>"
                f"<td>{_cve_badges(cves_serialized)}</td>"
                f"<td>{html.escape(ev.detail)}</td>"
                "</tr>".format(cls=_STATUS_LABELS.get(ev.status, ("", ev.status))[1])
            )
        summary_meta = f"retenue : {html.escape(selected_version)}" if selected_version else "aucune version retenue"
        sections.append(
            f'<details class="pkg-accordion"><summary>{html.escape(name)} '
            f'<span class="summary-meta">{len(evaluated[name])} version(s) évaluée(s) — {summary_meta}</span></summary>'
            "<table><thead><tr><th>Version</th><th>Statut</th><th>CVE</th><th>Détail</th></tr></thead>"
            f"<tbody>{''.join(rows)}</tbody></table></details>"
        )

    transitive_html = ""
    if transitive_dependencies:
        items = []
        for dep in transitive_dependencies:
            provenance = ", ".join(dep["brought_in_by"]) or "provenance inconnue"
            items.append(
                f'<li class="transitive-item" data-search="{html.escape(dep["name"].lower())} {html.escape(dep["version"].lower())} {html.escape(provenance.lower())}">'
                f'<code>{html.escape(dep["name"])}=={html.escape(dep["version"])}</code> '
                f'<span class="provenance">apportée par {html.escape(provenance)}</span></li>'
            )
        transitive_html = f"""
<details class="pkg-accordion">
<summary>Voir les sous-dépendances <span class="summary-meta">({len(transitive_dependencies)} paquet(s) non demandé(s) explicitement)</span></summary>
<div style="padding: 0 1rem 1rem;">
<input type="text" class="filter-box" placeholder="Filtrer par nom, version ou provenance..."
       oninput="depsolverFilterTransitive(this.value)">
<ul id="transitive-list" style="list-style:none; padding:0; margin:0;">{''.join(items)}</ul>
</div>
</details>
<script>
function depsolverFilterTransitive(query) {{
  var q = query.toLowerCase();
  document.querySelectorAll('#transitive-list .transitive-item').forEach(function(li) {{
    var hay = li.getAttribute('data-search') || '';
    li.style.display = hay.indexOf(q) !== -1 ? '' : 'none';
  }});
}}
</script>
"""

    return f"""<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="utf-8">
<title>{html.escape(title)}</title>
<style>{_HTML_STYLE}</style>
</head>
<body>
<h1>{html.escape(title)}</h1>
<p class="subtitle">Généré par depsolver — pour chaque paquet, toutes les versions candidates
examinées, leur statut et les CVE associées. Le badge <span class="badge unverified">API non vérifiée</span>
signale une version retenue sans qu'aucun appel réel n'ait pu être rattaché à ce paquet dans le
code analysé (contraintes de version et CVE quand même vérifiées).</p>

<div class="summary">{''.join(summary_cards)}</div>

{relax_html}
<h2>Solution retenue</h2>
<table><thead><tr><th>Paquet</th><th>Version</th></tr></thead>
<tbody>{''.join(solution_rows)}</tbody></table>
{transitive_html}

<h2>Détail par paquet (tous les choix évalués)</h2>
{''.join(sections)}

{_blocked_upgrades_html(blocked_upgrades or {})}

<footer>Politique CVE appliquée : <code>{html.escape(policy)}</code></footer>
</body>
</html>
"""


def write_html(html_content: str, path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        f.write(html_content)


# ----------------------------------------------------------------- compare --

def build_compare_report(env1_name: str, env1: Dict[str, str], env2_name: str, env2: Dict[str, str]) -> dict:
    names = sorted(set(env1) | set(env2))
    rows = []
    for name in names:
        v1 = env1.get(name)
        v2 = env2.get(name)
        if v1 == v2:
            status = "identique"
        elif v1 is None:
            status = "seulement_env2"
        elif v2 is None:
            status = "seulement_env1"
        else:
            status = "different"
        rows.append({"package": name, env1_name: v1, env2_name: v2, "status": status})
    return {
        "env1": env1_name, "env2": env2_name,
        "rows": rows,
        "summary": {
            "total": len(rows),
            "identical": sum(1 for r in rows if r["status"] == "identique"),
            "different": sum(1 for r in rows if r["status"] == "different"),
            "only_env1": sum(1 for r in rows if r["status"] == "seulement_env1"),
            "only_env2": sum(1 for r in rows if r["status"] == "seulement_env2"),
        },
    }


def render_text_compare(report: dict) -> str:
    lines = [f"Comparaison {report['env1']} <-> {report['env2']}", ""]
    for r in report["rows"]:
        v1 = r[report["env1"]] or "-"
        v2 = r[report["env2"]] or "-"
        marker = {"identique": "=", "different": "≠", "seulement_env1": "<", "seulement_env2": ">"}[r["status"]]
        lines.append(f"  {r['package']:<30} {v1:<15} {marker} {v2:<15}")
    s = report["summary"]
    lines.append("")
    lines.append(f"Total: {s['total']} | identiques: {s['identical']} | différentes: {s['different']} "
                 f"| seulement {report['env1']}: {s['only_env1']} | seulement {report['env2']}: {s['only_env2']}")
    return "\n".join(lines)


def render_html_compare(report: dict) -> str:
    rows_html = []
    for r in report["rows"]:
        v1 = r[report["env1"]] or "<em>absent</em>"
        v2 = r[report["env2"]] or "<em>absent</em>"
        css = {"identique": "status-kept", "different": "status-excluded",
               "seulement_env1": "status-excluded", "seulement_env2": "status-excluded"}[r["status"]]
        rows_html.append(
            f'<tr class="{css}"><td><code>{html.escape(r["package"])}</code></td>'
            f'<td>{v1 if v1.startswith("<em>") else html.escape(v1)}</td>'
            f'<td>{v2 if v2.startswith("<em>") else html.escape(v2)}</td>'
            f'<td>{html.escape(r["status"])}</td></tr>'
        )
    s = report["summary"]
    cards = "".join(
        f'<div class="card"><div class="label">{k}</div><div class="value">{v}</div></div>'
        for k, v in [("Total", s["total"]), ("Identiques", s["identical"]), ("Différentes", s["different"]),
                     (f"Seulement {report['env1']}", s["only_env1"]), (f"Seulement {report['env2']}", s["only_env2"])]
    )
    return f"""<!DOCTYPE html>
<html lang="fr"><head><meta charset="utf-8"><title>Comparaison d'environnements</title>
<style>{_HTML_STYLE}</style></head><body>
<h1>Comparaison d'environnements</h1>
<p class="subtitle">{html.escape(report['env1'])} vs {html.escape(report['env2'])}</p>
<div class="summary">{cards}</div>
<table><thead><tr><th>Paquet</th><th>{html.escape(report['env1'])}</th><th>{html.escape(report['env2'])}</th><th>Statut</th></tr></thead>
<tbody>{''.join(rows_html)}</tbody></table>
</body></html>
"""

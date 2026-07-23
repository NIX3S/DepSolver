"""Interrogation d'OSV (https://osv.dev) pour les vulnérabilités connues.

NB : l'API OSV (api.osv.dev) peut être inaccessible dans certains environnements
réseau restreints (sandbox, CI sans egress). En cas d'échec réseau, on renvoie
une liste vide et on signale l'échec via `last_error` plutôt que de faire
planter toute la résolution — mieux vaut une CVE non vérifiée que de bloquer
l'utilisateur, à condition de le tracer clairement dans le rapport.
"""
from __future__ import annotations

import logging
from typing import List, Optional

import requests

from .models import CVEInfo

_SESSION = requests.Session()
logger = logging.getLogger("depsolver.cve")

last_error: Optional[str] = None


def get_cves(package_name: str, version: str) -> List[CVEInfo]:
    global last_error
    logger.debug("POST api.osv.dev/v1/query package=%s version=%s", package_name, version)
    try:
        resp = _SESSION.post(
            "https://api.osv.dev/v1/query",
            json={
                "package": {"name": package_name, "ecosystem": "PyPI"},
                "version": version,
            },
            timeout=10,
        )
        resp.raise_for_status()
        vulns = resp.json().get("vulns", [])
    except requests.RequestException as exc:
        last_error = str(exc)
        return []

    result = []
    for v in vulns:
        severity = None
        for sev in v.get("severity", []) or []:
            severity = sev.get("score") or severity
        db_severity = v.get("database_specific", {}).get("severity")
        result.append(
            CVEInfo(
                id=v.get("id", "UNKNOWN"),
                severity=db_severity or severity,
                summary=v.get("summary"),
            )
        )
    return result


_SEVERITY_RANK = {"LOW": 1, "MODERATE": 2, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
_RANK_LABEL = {0: "aucune CVE tolérée", 1: "jusqu'à LOW", 2: "jusqu'à MEDIUM", 3: "jusqu'à HIGH", 4: "tout tolérer (y compris CRITICAL)"}


def severity_rank(severity: Optional[str]) -> int:
    """Sévérité inconnue traitée avec prudence : rang MEDIUM (2), ni ignorée
    ni traitée comme automatiquement critique."""
    if not severity:
        return 2
    return _SEVERITY_RANK.get(severity.upper(), 2)


def policy_to_ceiling(policy: str) -> int:
    """Convertit une politique nommée en plafond numérique de sévérité tolérée."""
    if policy == "cve-none":
        return 0
    if policy == "cve-no-critical":
        return 3
    if policy == "cve-custom":
        return 3  # limite documentée : pas encore de config fine, équivalent à cve-no-critical
    return 3


def ceiling_label(ceiling: int) -> str:
    return _RANK_LABEL.get(ceiling, str(ceiling))


def is_acceptable_under_ceiling(cves: List[CVEInfo], ceiling: int) -> bool:
    return all(severity_rank(c.severity) <= ceiling for c in cves)


def is_version_acceptable(version: str, cves: List[CVEInfo], policy: str) -> bool:
    """Alias basé sur la politique nommée, conservé pour compatibilité :
    équivalent à `is_acceptable_under_ceiling(cves, policy_to_ceiling(policy))`.
    Le code interne (`optimizer.py`) utilise directement les plafonds
    numériques pour permettre la dégradation progressive ; cette fonction
    reste utile pour un usage simple/externe du module."""
    return is_acceptable_under_ceiling(cves, policy_to_ceiling(policy))

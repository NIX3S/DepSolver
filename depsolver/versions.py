"""Interrogation de PyPI pour les versions disponibles et leurs dépendances.

Un cache mémoire + fichier (JSON) évite de re-appeler PyPI à chaque exécution.

Fidélité par version : PyPI expose un endpoint JSON *par release*
(`/pypi/<name>/<version>/json`), distinct de l'endpoint "projet" global
(`/pypi/<name>/json`) qui ne donne les `requires_dist` détaillés que pour la
toute dernière version publiée. `get_dependencies` utilise l'endpoint par
release pour que chaque version candidate ait ses vraies dépendances déclarées,
et non celles de la dernière version du projet.
"""
from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Dict, List, Optional

import requests
from packaging.requirements import Requirement as PkgRequirement
from packaging.version import InvalidVersion, Version

_CACHE_DIR = Path.home() / ".cache" / "depsolver"
_CACHE_DIR.mkdir(parents=True, exist_ok=True)
_SESSION = requests.Session()
logger = logging.getLogger("depsolver.versions")
_MEM_CACHE: Dict[str, dict] = {}
_MEM_CACHE_VERSION: Dict[tuple, dict] = {}


def _cache_path(package_name: str) -> Path:
    return _CACHE_DIR / f"{package_name.lower()}.json"


def _cache_path_version(package_name: str, version: str) -> Path:
    safe_version = version.replace("/", "_")
    return _CACHE_DIR / f"{package_name.lower()}__{safe_version}.json"


def _fetch_pypi_json(package_name: str, ttl_seconds: int = 3600) -> dict:
    """Endpoint "projet" (toutes les releases listées, mais `info` = dernière version)."""
    if package_name in _MEM_CACHE:
        return _MEM_CACHE[package_name]

    cache_file = _cache_path(package_name)
    if cache_file.exists() and (time.time() - cache_file.stat().st_mtime) < ttl_seconds:
        data = json.loads(cache_file.read_text(encoding="utf-8"))
        _MEM_CACHE[package_name] = data
        return data

    logger.debug("GET https://pypi.org/pypi/%s/json", package_name)
    resp = _SESSION.get(f"https://pypi.org/pypi/{package_name}/json", timeout=15)
    resp.raise_for_status()
    data = resp.json()
    cache_file.write_text(json.dumps(data), encoding="utf-8")
    _MEM_CACHE[package_name] = data
    return data


def _fetch_pypi_version_json(package_name: str, version: str, ttl_seconds: int = 86400) -> Optional[dict]:
    """Endpoint "release" (`/pypi/<name>/<version>/json`) : donne les métadonnées
    (dont `requires_dist`) réellement déclarées par CETTE version précise, pas par
    la dernière du projet. Renvoie None si la version n'existe pas (404) ou en cas
    d'erreur réseau — l'appelant doit alors se rabattre sur une liste vide de
    dépendances plutôt que de planter toute la résolution."""
    key = (package_name, version)
    if key in _MEM_CACHE_VERSION:
        return _MEM_CACHE_VERSION[key]

    cache_file = _cache_path_version(package_name, version)
    if cache_file.exists() and (time.time() - cache_file.stat().st_mtime) < ttl_seconds:
        data = json.loads(cache_file.read_text(encoding="utf-8"))
        _MEM_CACHE_VERSION[key] = data
        return data

    try:
        logger.debug("GET https://pypi.org/pypi/%s/%s/json", package_name, version)
        resp = _SESSION.get(f"https://pypi.org/pypi/{package_name}/{version}/json", timeout=15)
        if resp.status_code == 404:
            _MEM_CACHE_VERSION[key] = None
            return None
        resp.raise_for_status()
    except requests.RequestException:
        return None

    data = resp.json()
    cache_file.write_text(json.dumps(data), encoding="utf-8")
    _MEM_CACHE_VERSION[key] = data
    return data


def list_versions(package_name: str) -> List[str]:
    """Retourne les versions publiées, triées de la plus récente à la plus ancienne,
    en excluant pre-releases/yanked."""
    data = _fetch_pypi_json(package_name)
    releases = data.get("releases", {})
    versions = []
    for v, files in releases.items():
        if not files:
            continue
        if all(f.get("yanked", False) for f in files):
            continue
        try:
            parsed = Version(v)
        except InvalidVersion:
            continue
        if parsed.is_prerelease or parsed.is_devrelease:
            continue
        versions.append((parsed, v))
    versions.sort(key=lambda t: t[0], reverse=True)
    return [v for _, v in versions]


def get_dependencies(package_name: str, version: str) -> List[PkgRequirement]:
    """Dépendances déclarées (requires_dist) pour CETTE version précise, via
    l'endpoint PyPI par release — sans marqueurs d'environnement/extra
    (approximation : on garde tout ce qui n'a pas de marqueur `extra ==`)."""
    data = _fetch_pypi_version_json(package_name, version)
    if data is None:
        # version introuvable via l'endpoint release (ou réseau indisponible) :
        # on ne bloque pas la résolution, mais on ne peut pas non plus inventer
        # des dépendances — liste vide, cohérent avec un paquet sans dépendance
        # déclarée connue.
        return []

    requires_dist = data.get("info", {}).get("requires_dist") or []
    reqs = []
    for r in requires_dist:
        if "extra ==" in r:
            continue
        try:
            reqs.append(PkgRequirement(r))
        except Exception:
            continue
    return reqs


def get_latest_metadata_version(package_name: str) -> Optional[str]:
    data = _fetch_pypi_json(package_name)
    return data.get("info", {}).get("version")

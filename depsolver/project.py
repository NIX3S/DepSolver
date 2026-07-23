"""Détection et extraction des dépendances + appels d'un projet existant."""
from __future__ import annotations

from pathlib import Path
from typing import List

from .api_analyzer import extract_api_calls_from_package
from .models import ApiCall, Requirement
from .parser import parse_pyproject_toml, parse_requirements_txt


def detect_dependency_file(project_path: str | Path) -> Path | None:
    project_path = Path(project_path)
    for candidate in ("requirements.txt", "pyproject.toml", "requirements.in"):
        p = project_path / candidate
        if p.exists():
            return p
    return None


def extract_current_requirements(project_path: str | Path) -> List[Requirement]:
    dep_file = detect_dependency_file(project_path)
    if dep_file is None:
        raise FileNotFoundError(
            f"Aucun fichier de dépendances trouvé dans {project_path} "
            "(requirements.txt, requirements.in ou pyproject.toml attendu)."
        )
    if dep_file.suffix == ".toml":
        return parse_pyproject_toml(dep_file)
    return parse_requirements_txt(dep_file)


def extract_project_calls(project_path: str | Path, project_package_name: str = "project") -> List[ApiCall]:
    """Extrait les appels du code source du projet (hors venv/site-packages)."""
    project_path = Path(project_path)
    calls: List[ApiCall] = []
    excluded_dirs = {".venv", "venv", "site-packages", "__pycache__", ".git", "node_modules"}
    for py_file in project_path.rglob("*.py"):
        if any(part in excluded_dirs for part in py_file.parts):
            continue
        try:
            source = py_file.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        from .api_analyzer import extract_api_calls_from_source

        calls.extend(extract_api_calls_from_source(source, project_package_name, str(py_file)))
    return calls

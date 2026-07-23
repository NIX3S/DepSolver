"""Parsing des fichiers de dépendances : requirements.txt, pyproject.toml."""
from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import List

from .models import Requirement

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover
    import tomli as tomllib  # type: ignore

_SPEC_RE = re.compile(r"(==|>=|<=|!=|~=|>|<)\s*([A-Za-z0-9.\-+*]+)")
_NAME_RE = re.compile(r"^\s*([A-Za-z0-9_.\-]+)")


def parse_requirement_line(line: str) -> Requirement | None:
    line = line.split("#", 1)[0].strip()
    if not line:
        return None
    if line.startswith(("-", "git+", "http://", "https://")):
        # options pip (-r, -e, --hash, ...) ou VCS/URL: non gérées en v1, ignorées
        return None
    name_match = _NAME_RE.match(line)
    if not name_match:
        return None
    name = name_match.group(1)
    rest = line[name_match.end():]
    specs = _SPEC_RE.findall(rest)
    return Requirement(name=name, specs=[(op, v) for op, v in specs])


def parse_requirements_txt(path: str | Path) -> List[Requirement]:
    reqs: List[Requirement] = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            req = parse_requirement_line(line)
            if req is not None:
                reqs.append(req)
    return reqs


def parse_pyproject_toml(path: str | Path) -> List[Requirement]:
    """Extrait les dépendances de la section [project.dependencies] (PEP 621)
    ou, à défaut, de [tool.poetry.dependencies]."""
    data = tomllib.loads(Path(path).read_text(encoding="utf-8"))
    reqs: List[Requirement] = []

    project_deps = data.get("project", {}).get("dependencies", [])
    for line in project_deps:
        req = parse_requirement_line(line)
        if req is not None:
            reqs.append(req)
    if reqs:
        return reqs

    poetry_deps = data.get("tool", {}).get("poetry", {}).get("dependencies", {})
    for name, spec in poetry_deps.items():
        if name.lower() == "python":
            continue
        if isinstance(spec, str):
            reqs.append(parse_requirement_line(f"{name}{spec}") or Requirement(name=name))
        else:
            reqs.append(Requirement(name=name))
    return reqs


def parse_requirements_file(path: str | Path) -> List[Requirement]:
    path = Path(path)
    if path.suffix == ".toml":
        return parse_pyproject_toml(path)
    return parse_requirements_txt(path)


def write_requirements_txt(solution: dict[str, str], path: str | Path) -> None:
    lines = [f"{name}=={version}" for name, version in sorted(solution.items())]
    Path(path).write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_lock_file(solution: dict[str, str], path: str | Path, policy: str = "cve-no-critical") -> None:
    """Écrit un `requirements.lock` : mêmes pins que `write_requirements_txt`,
    mais avec un en-tête traçant comment ce verrou a été généré (politique CVE,
    horodatage) — utile pour savoir, six mois plus tard, si le lock a été
    produit avec vérification API/CVE ou pas."""
    from datetime import datetime, timezone

    header = [
        "# Fichier généré par depsolver — NE PAS ÉDITER À LA MAIN",
        f"# Généré le : {datetime.now(timezone.utc).isoformat()}",
        f"# Politique CVE appliquée : {policy}",
        "# Régénérer avec : depsolver solve --input <requirements.in> --output <ce fichier> --lock <ce fichier>",
        "",
    ]
    lines = [f"{name}=={version}" for name, version in sorted(solution.items())]
    Path(path).write_text("\n".join(header + lines) + "\n", encoding="utf-8")

"""Resolver de dépendances "maison" : backtracking sur les contraintes de version,
sans dépendre d'un outil externe (pip/poetry ne sont utilisés nulle part ici).

Principe :
- on part d'un ensemble de Requirement racine (nom + specs) ;
- pour chaque paquet on récupère les versions disponibles (versions.list_versions) ;
- on explore les versions de la plus récente à la plus ancienne (backtracking) ;
- à chaque choix, on ajoute les dépendances transitives déclarées par cette version
  comme nouvelles contraintes à satisfaire ;
- on échoue si un paquet n'a plus aucune version satisfaisant l'ensemble des
  contraintes accumulées (specs utilisateur + specs transitives de tous les
  paquets qui en dépendent).

Point important sur la correction du backtracking : les contraintes accumulées
(`specifiers`) sont propres à CHAQUE branche explorée (copie par tentative de
version), et jamais partagées/mutées entre deux candidats essayés pour un même
paquet. Sans ça, une contrainte ajoutée par une branche abandonnée (ex. un choix
de version plus récent qui s'avère incompatible plus bas dans le graphe) pourrait
"fuiter" et bloquer à tort une branche ultérieure qui, elle, serait valide —
typiquement le cas où il faut redescendre vers une version plus ancienne d'un
paquet en amont pour retrouver une combinaison compatible.
"""
from __future__ import annotations

import logging
from typing import Callable, Dict, List, Optional

from packaging.requirements import Requirement as PkgRequirement
from packaging.specifiers import SpecifierSet
from packaging.version import Version

from .models import Requirement


logger = logging.getLogger("depsolver.resolver")


class ConflictError(Exception):
    pass


class NoSolutionError(Exception):
    def __init__(self, message: str, blocking_package: Optional[str] = None):
        super().__init__(message)
        self.blocking_package = blocking_package


def _spec_to_specifierset(req: Requirement) -> SpecifierSet:
    return SpecifierSet(",".join(f"{op}{v}" for op, v in req.specs))


def _candidate_versions(
    name: str,
    specifier: SpecifierSet,
    list_versions: Callable[[str], List[str]],
    allowed_versions: Dict[str, List[str]],
) -> List[str]:
    pool = allowed_versions.get(name)
    if pool is None:
        pool = list_versions(name)
    result = []
    for v in pool:
        try:
            if specifier.contains(Version(v), prereleases=False):
                result.append(v)
        except Exception:
            continue
    return result


def solve(
    root_requirements: List[Requirement],
    list_versions: Callable[[str], List[str]],
    get_dependencies: Callable[[str, str], List[PkgRequirement]],
    allowed_versions: Optional[Dict[str, List[str]]] = None,
    max_depth: int = 200,
) -> Dict[str, str]:
    """Résout un ensemble de Requirement en un dict {nom: version}.

    `allowed_versions`, si fourni, restreint (par paquet) les versions déjà
    jugées acceptables en amont par le filtre CVE/API — c'est le point
    d'intégration avec `optimizer.py`.
    """
    allowed_versions = allowed_versions or {}

    root_specifiers: Dict[str, SpecifierSet] = {}
    root_order: List[str] = []
    for req in root_requirements:
        if req.name not in root_specifiers:
            root_specifiers[req.name] = _spec_to_specifierset(req)
            root_order.append(req.name)
        else:
            root_specifiers[req.name] = root_specifiers[req.name] & _spec_to_specifierset(req)

    decided: Dict[str, str] = {}

    def backtrack(
        index: int,
        order: List[str],
        specifiers: Dict[str, SpecifierSet],
        depth: int,
    ) -> Optional[Dict[str, str]]:
        if depth > max_depth:
            raise NoSolutionError("Profondeur de résolution dépassée (cycle probable).")
        if index == len(order):
            return dict(decided)

        name = order[index]
        if name in decided:
            return backtrack(index + 1, order, specifiers, depth + 1)

        candidates = _candidate_versions(name, specifiers[name], list_versions, allowed_versions)
        logger.debug("%s%s: %d candidat(s) à essayer -> %s", "  " * depth, name, len(candidates), candidates[:6])
        if not candidates:
            logger.debug("%s%s: aucun candidat, échec de cette branche", "  " * depth, name)
            return None

        for v in candidates:
            decided[name] = v

            # Copie propre à cette tentative : toute contrainte ajoutée ici est
            # oubliée si ce candidat échoue, on repart des `specifiers` du parent
            # pour le candidat suivant (c'est ça qui rend le backtracking correct).
            local_specifiers = dict(specifiers)
            local_order = list(order)

            try:
                deps = get_dependencies(name, v)
            except Exception:
                deps = []

            conflict = False
            for dep in deps:
                dep_spec = dep.specifier if dep.specifier else SpecifierSet()
                if dep.name not in local_specifiers:
                    local_specifiers[dep.name] = dep_spec
                    local_order.append(dep.name)
                else:
                    local_specifiers[dep.name] = local_specifiers[dep.name] & dep_spec

                if dep.name in decided:
                    try:
                        if not local_specifiers[dep.name].contains(Version(decided[dep.name]), prereleases=False):
                            conflict = True
                            break
                    except Exception:
                        pass

            if conflict:
                logger.debug("%s%s==%s: conflit avec une contrainte déjà décidée, backtrack", "  " * depth, name, v)
            else:
                result = backtrack(index + 1, local_order, local_specifiers, depth + 1)
                if result is not None:
                    return result
                logger.debug("%s%s==%s: échec en aval, on essaie le candidat suivant", "  " * depth, name, v)

            del decided[name]

        return None

    solution = backtrack(0, root_order, root_specifiers, 0)
    if solution is None:
        raise NoSolutionError("Aucun ensemble de versions compatible trouvé.")
    return solution

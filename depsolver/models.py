"""Structures de données partagées entre les modules de depsolver."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


@dataclass
class Requirement:
    """Une exigence de dépendance : nom + liste de specs (op, version)."""

    name: str
    specs: List[Tuple[str, str]] = field(default_factory=list)

    def __str__(self) -> str:
        if not self.specs:
            return self.name
        return self.name + ",".join(f"{op}{v}" for op, v in self.specs)


@dataclass
class ApiCall:
    """Un appel réel détecté dans le code, ciblant un symbole d'un autre paquet."""

    caller_package: str
    callee_package: str
    callee_symbol: str  # ex. "init", "run" (nom de fonction/méthode appelée)
    call_location: str  # "fichier:ligne"
    arg_count: int = 0
    kwarg_names: Tuple[str, ...] = field(default_factory=tuple)


@dataclass
class SymbolSignature:
    """Signature publique d'une fonction/méthode d'une version donnée d'un paquet."""

    name: str
    positional_params: List[str]
    kwonly_params: List[str]
    has_var_positional: bool = False
    has_var_keyword: bool = False


@dataclass
class PackageAPI:
    """API publique d'un paquet à une version donnée : symbole -> signature."""

    package: str
    version: str
    symbols: Dict[str, SymbolSignature] = field(default_factory=dict)
    inconclusive: List[str] = field(default_factory=list)
    """Symboles dont la résolution a échoué pour une raison NE prouvant PAS
    leur absence (ex. dépendance manquante empêchant l'import du module) —
    à ne jamais confondre avec un symbole confirmé absent après import réussi."""


@dataclass
class ApiIncompatibility:
    call: ApiCall
    reason: str


@dataclass
class ApiCompatibilityResult:
    is_compatible: bool
    incompatibilities: List[ApiIncompatibility] = field(default_factory=list)
    warnings: List[ApiIncompatibility] = field(default_factory=list)
    """Cas 'inconclusif' (ex. dépendance manquante empêchant de vérifier) —
    n'affecte PAS `is_compatible`, mais doit être signalé à l'utilisateur."""


@dataclass
class CVEInfo:
    id: str
    severity: Optional[str] = None
    summary: Optional[str] = None


@dataclass
class Rejection:
    package: str
    version: str
    reason: str  # "version_spec" | "cve" | "api_incompatible"
    detail: str


@dataclass
class EvaluatedVersion:
    """Trace de l'évaluation d'une version candidate, pour le rapport (y compris HTML) :
    que la version ait été retenue ou écartée, et pourquoi."""

    package: str
    version: str
    status: str  # "selected" | "kept" | "excluded_spec" | "excluded_cve" | "excluded_api"
    cves: List[CVEInfo] = field(default_factory=list)
    detail: str = ""
    verified: bool = True
    """False si la version a été retenue SANS que la compatibilité API ait pu
    être vérifiée (aucun appel détecté vers ce paquet dans le code analysé, ou
    --analyze-api désactivé) : la version passe les contraintes de version et
    CVE, mais rien ne garantit qu'elle n'introduit pas un breaking change sur
    un usage non détecté. À afficher clairement dans les rapports."""

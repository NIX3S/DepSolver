"""Clonage d'un dépôt GitHub/GitLab pour analyse, avec cache local optionnel.

Par défaut, un dépôt déjà cloné pour (URL, branche) est réutilisé (fetch +
reset --hard) plutôt que re-cloné intégralement à chaque exécution — utile en
usage répété (CI, audits périodiques). `use_cache=False` force un clone frais
dans un dossier temporaire, comme avant."""
from __future__ import annotations

import hashlib
import logging
import subprocess
import tempfile
from pathlib import Path
from typing import Optional

logger = logging.getLogger("depsolver.git_integration")

_CACHE_DIR = Path.home() / ".cache" / "depsolver" / "repos"


class GitCloneError(Exception):
    pass


def _repo_cache_key(repo_url: str, branch: Optional[str]) -> str:
    raw = f"{repo_url}#{branch or ''}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def clone_repo(
    repo_url: str,
    branch: Optional[str] = None,
    token: Optional[str] = None,
    clone_to: Optional[str] = None,
    use_cache: bool = True,
) -> Path:
    """Clone (ou réutilise depuis le cache local) un dépôt dans un dossier.

    Si `token` est fourni, il est injecté dans l'URL (https://TOKEN@host/...)
    uniquement en mémoire pour la commande git — jamais loggé, jamais laissé
    dans le dossier de destination (on nettoie l'URL du remote après clone).
    """
    url = repo_url
    if token:
        if repo_url.startswith("https://"):
            url = repo_url.replace("https://", f"https://{token}@", 1)
        else:
            raise GitCloneError("--git-token nécessite une URL https://")

    if clone_to:
        dest = Path(clone_to)
        use_cache = False
    elif use_cache:
        _CACHE_DIR.mkdir(parents=True, exist_ok=True)
        dest = _CACHE_DIR / _repo_cache_key(repo_url, branch)
    else:
        dest = Path(tempfile.mkdtemp(prefix="depsolver-repo-"))

    if use_cache and (dest / ".git").exists():
        logger.debug("cache repo trouvé pour %s (branche %s) : %s", repo_url, branch, dest)
        try:
            subprocess.run(["git", "-C", str(dest), "fetch", "--depth", "1", "origin",
                             branch or "HEAD"], capture_output=True, text=True, timeout=120, check=True)
            target = f"origin/{branch}" if branch else "origin/HEAD"
            subprocess.run(["git", "-C", str(dest), "reset", "--hard", target],
                            capture_output=True, text=True, timeout=60, check=True)
            _scrub_remote_token(dest)
            return dest
        except subprocess.CalledProcessError as exc:
            logger.debug("échec de mise à jour du cache (%s), on retombe sur un clone frais : %s", dest, exc)
            # on continue vers un clone frais ci-dessous, dans le même dossier de cache

    if use_cache and dest.exists():
        import shutil
        shutil.rmtree(dest, ignore_errors=True)

    cmd = ["git", "clone", "--depth", "1"]
    if branch:
        cmd += ["--branch", branch]
    cmd += [url, str(dest)]

    logger.debug("git clone %s (branche=%s) -> %s", repo_url, branch, dest)
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    if result.returncode != 0:
        safe_stderr = result.stderr.replace(token, "***") if token else result.stderr
        raise GitCloneError(f"Échec du clone de {repo_url}: {safe_stderr}")

    if use_cache:
        _scrub_remote_token(dest)
    return dest


def _scrub_remote_token(repo_dir: Path) -> None:
    """Réécrit l'URL du remote 'origin' sans le token, pour ne pas le laisser
    traîner dans .git/config d'un dossier de cache persistant."""
    try:
        result = subprocess.run(["git", "-C", str(repo_dir), "remote", "get-url", "origin"],
                                 capture_output=True, text=True, timeout=10)
        url = result.stdout.strip()
        if "@" in url and url.startswith("https://"):
            scheme, rest = url.split("://", 1)
            _, _, host_and_path = rest.partition("@")
            clean_url = f"{scheme}://{host_and_path}"
            subprocess.run(["git", "-C", str(repo_dir), "remote", "set-url", "origin", clean_url],
                            capture_output=True, timeout=10)
    except Exception:
        pass  # best-effort, ne doit jamais faire planter le clone/mise à jour

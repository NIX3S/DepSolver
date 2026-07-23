"""Installation des dépendances proposées dans un venv temporaire et exécution
des tests du projet, pour valider "en vrai" une proposition de mise à jour."""
from __future__ import annotations

import os
import shlex
import subprocess
import sys
import tempfile
import venv
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional


def _pip_extra_args() -> list[str]:
    env_args = os.environ.get("DEPSOLVER_PIP_EXTRA_ARGS")
    return shlex.split(env_args) if env_args else []


@dataclass
class TestRunResult:
    ran: bool
    passed: Optional[bool]
    returncode: Optional[int]
    stdout: str = ""
    stderr: str = ""
    reason: str = ""


def run_tests_with_solution(
    project_path: str | Path,
    solution: Dict[str, str],
    test_command: str,
    timeout_seconds: int = 600,
) -> TestRunResult:
    project_path = Path(project_path)

    with tempfile.TemporaryDirectory(prefix="depsolver-venv-") as tmp:
        venv_dir = Path(tmp) / "venv"
        venv.EnvBuilder(with_pip=True).create(venv_dir)
        pip_bin = venv_dir / "bin" / "pip"
        python_bin = venv_dir / "bin" / "python"

        pins = [f"{name}=={version}" for name, version in solution.items()]
        install = subprocess.run(
            [str(pip_bin), "install", "--quiet", *_pip_extra_args(), *pins],
            cwd=project_path, capture_output=True, text=True, timeout=timeout_seconds,
        )
        if install.returncode != 0:
            return TestRunResult(
                ran=False, passed=None, returncode=install.returncode,
                stdout=install.stdout, stderr=install.stderr,
                reason="échec de l'installation des dépendances proposées",
            )

        # installe aussi le projet lui-même si un pyproject/setup existe
        if (project_path / "pyproject.toml").exists() or (project_path / "setup.py").exists():
            subprocess.run(
                [str(pip_bin), "install", "--quiet", *_pip_extra_args(), "-e", "."],
                cwd=project_path, capture_output=True, text=True, timeout=timeout_seconds,
            )

        # le runner de tests lui-même (pytest, tox, ...) doit être disponible dans
        # le venv isolé ; on l'installe s'il n'y est pas déjà (dépendance de dev
        # implicite, cohérent avec le fait qu'on isole volontairement ce venv).
        runner_name = test_command.split()[0]
        if not (venv_dir / "bin" / runner_name).exists():
            subprocess.run(
                [str(pip_bin), "install", "--quiet", *_pip_extra_args(), runner_name],
                capture_output=True, text=True, timeout=timeout_seconds,
            )

        parts = test_command.split()
        exe = parts[0]
        # si la commande référence l'exécutable du venv (ex. "pytest"), on le résout
        candidate = venv_dir / "bin" / exe
        if candidate.exists():
            parts[0] = str(candidate)
        else:
            parts[0] = str(python_bin)
            parts.insert(1, "-m")
            parts.insert(2, exe)

        try:
            result = subprocess.run(
                parts, cwd=project_path, capture_output=True, text=True, timeout=timeout_seconds,
            )
        except subprocess.TimeoutExpired:
            return TestRunResult(ran=True, passed=False, returncode=None, reason="timeout des tests")

        return TestRunResult(
            ran=True,
            passed=result.returncode == 0,
            returncode=result.returncode,
            stdout=result.stdout[-4000:],
            stderr=result.stderr[-4000:],
        )

import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

LIBC_VERSIONS = {
    "1.0": '''
def init(mode: str):
    return f"init-v1-{mode}"

def run():
    return "run-v1"

def check(x: int) -> bool:
    return x > 0
''',
    "2.5.6": '''
def init(mode: str = None, strategy: str = None):
    if strategy is not None:
        return f"init-v256-strategy-{strategy}"
    return f"init-v256-mode-{mode}"

def run(config: dict = None):
    return f"run-v256-{config}"

def check(x: int) -> bool:
    return x > 0
''',
    "3.0": '''
def init(strategy: str):
    return f"init-v3-{strategy}"

def run(config: dict, verbose: bool = False):
    return f"run-v3-{config}-{verbose}"

def check(x: int) -> bool:
    return x > 0
''',
}

# Sous-module imbriqué `libc.sub` avec une classe et une méthode, présent en
# 1.0 et 2.5.6 mais supprimé en 3.0 -- pour tester la détection de breaking
# change sur un chemin imbriqué (ex. `libc.sub.close()`,
# `libc.sub.Manager().close()`), pas seulement sur un symbole top-level.
LIBC_SUB_MODULE = {
    "1.0": '''
def close():
    return "sub-close-v1"

class Manager:
    def __init__(self, name: str = "default"):
        self.name = name

    def close(self):
        return f"manager-close-v1-{self.name}"
''',
    "2.5.6": '''
def close(force: bool = False):
    return f"sub-close-v256-{force}"

class Manager:
    def __init__(self, name: str = "default"):
        self.name = name

    def close(self):
        return f"manager-close-v256-{self.name}"
''',
    # 3.0 : le sous-module `sub` disparaît entièrement (breaking change).
    "3.0": None,
}


@pytest.fixture(scope="session")
def libc_wheels(tmp_path_factory) -> Path:
    """Construit localement (sans réseau) des wheels libc 1.0 / 2.5.6 / 3.0
    avec des API volontairement divergentes, pour tester la détection de
    breaking changes sans dépendre de PyPI."""
    build_dir = tmp_path_factory.mktemp("libc_build")
    wheels_dir = tmp_path_factory.mktemp("libc_wheels")

    for version, source in LIBC_VERSIONS.items():
        pkg_dir = build_dir / f"libc-{version}"
        (pkg_dir / "libc").mkdir(parents=True)
        (pkg_dir / "libc" / "__init__.py").write_text(textwrap.dedent(source))
        sub_source = LIBC_SUB_MODULE.get(version)
        if sub_source is not None:
            (pkg_dir / "libc" / "sub.py").write_text(textwrap.dedent(sub_source))
        (pkg_dir / "setup.py").write_text(
            f'from setuptools import setup\nsetup(name="libc", version="{version}", packages=["libc"])\n'
        )
        subprocess.run(
            [sys.executable, "setup.py", "bdist_wheel", "--dist-dir", str(wheels_dir)],
            cwd=pkg_dir, check=True, capture_output=True,
        )

    return wheels_dir


@pytest.fixture(scope="session")
def libc_pip_args(libc_wheels) -> list[str]:
    return ["--no-index", "--find-links", str(libc_wheels)]


LIBE_VERSIONS = {
    "1.0": '''
def main(x):
    return f"main-v1-{x}"
''',
    "2.0": '''
def run(x):
    return f"run-v2-{x}"
''',
    "3.0": '''
def main(x, mode="fast"):
    return f"main-v3-{x}-{mode}"

def run(x):
    return f"run-v3-{x}"
''',
}


@pytest.fixture(scope="session")
def libe_wheels(tmp_path_factory) -> Path:
    """Construit localement (sans réseau) 3 versions d'un faux paquet `libe`
    où le symbole `main` existe en 1.0, disparaît (renommé `run`) en 2.0, puis
    réapparaît en 3.0 avec une signature différente -- reproduit le cas
    'pytesseract.main' : vérifier que chaque version est jugée indépendamment,
    pas seulement la dernière ou la première."""
    build_dir = tmp_path_factory.mktemp("libe_build")
    wheels_dir = tmp_path_factory.mktemp("libe_wheels")

    for version, source in LIBE_VERSIONS.items():
        pkg_dir = build_dir / f"libe-{version}"
        (pkg_dir / "libe").mkdir(parents=True)
        (pkg_dir / "libe" / "__init__.py").write_text(textwrap.dedent(source))
        (pkg_dir / "setup.py").write_text(
            f'from setuptools import setup\nsetup(name="libe", version="{version}", packages=["libe"])\n'
        )
        subprocess.run(
            [sys.executable, "setup.py", "bdist_wheel", "--dist-dir", str(wheels_dir)],
            cwd=pkg_dir, check=True, capture_output=True,
        )

    return wheels_dir


@pytest.fixture(scope="session")
def libe_pip_args(libe_wheels) -> list[str]:
    return ["--no-index", "--find-links", str(libe_wheels)]


@pytest.fixture(scope="session")
def libf_wheels(tmp_path_factory) -> Path:
    """Construit `fakedep` et `libf` (qui importe `fakedep` au niveau module,
    comme pytesseract importe PIL) -- pour tester le repli automatique sur
    une installation complète quand --no-deps empêche l'import."""
    build_dir = tmp_path_factory.mktemp("libf_build")
    wheels_dir = tmp_path_factory.mktemp("libf_wheels")

    fakedep_dir = build_dir / "fakedep"
    (fakedep_dir / "fakedep").mkdir(parents=True)
    (fakedep_dir / "fakedep" / "__init__.py").write_text('VALUE = "fakedep-present"\n')
    (fakedep_dir / "setup.py").write_text(
        'from setuptools import setup\nsetup(name="fakedep", version="1.0", packages=["fakedep"])\n'
    )
    subprocess.run([sys.executable, "setup.py", "bdist_wheel", "--dist-dir", str(wheels_dir)],
                    cwd=fakedep_dir, check=True, capture_output=True)

    libf_dir = build_dir / "libf"
    (libf_dir / "libf").mkdir(parents=True)
    (libf_dir / "libf" / "__init__.py").write_text(
        "import fakedep  # dépendance requise au niveau module, comme PIL pour pytesseract\n\n"
        "def ocr(image):\n    return f'ocr-result-using-{fakedep.VALUE}-{image}'\n"
    )
    (libf_dir / "setup.py").write_text(
        'from setuptools import setup\n'
        'setup(name="libf", version="1.0", packages=["libf"], install_requires=["fakedep"])\n'
    )
    subprocess.run([sys.executable, "setup.py", "bdist_wheel", "--dist-dir", str(wheels_dir)],
                    cwd=libf_dir, check=True, capture_output=True)

    return wheels_dir


@pytest.fixture(scope="session")
def libf_pip_args(libf_wheels) -> list[str]:
    return ["--no-index", "--find-links", str(libf_wheels)]


@pytest.fixture()
def callers(tmp_path) -> dict:
    """Crée le code source de libA (appelle check/init(mode=)) et libB
    (appelle run(config=)/init(strategy=)), reproduisant le scénario du
    'point de rencontre' décrit dans la spécification."""
    libA = tmp_path / "libA"
    libB = tmp_path / "libB"
    libA.mkdir()
    libB.mkdir()
    (libA / "__init__.py").write_text(
        "import libc\n\ndef do_something():\n    libc.check(5)\n    libc.init(mode='fast')\n"
    )
    (libB / "__init__.py").write_text(
        "import libc\n\ndef do_other():\n    libc.run(config={'x': 1})\n    libc.init(strategy='aggressive')\n"
    )
    return {"libA": libA, "libB": libB}


@pytest.fixture()
def nested_caller(tmp_path) -> Path:
    """Code appelant utilisant des chemins imbriqués vers un sous-module :
    `libc.sub.close(...)` (accès par attribut complet) et, via un import
    explicite du sous-module, `sub.Manager(...)` suivi de `.close()` sur
    l'instance (méthode d'une classe imbriquée)."""
    libD = tmp_path / "libD"
    libD.mkdir()
    (libD / "__init__.py").write_text(
        "import libc.sub\n"
        "from libc import sub as sub_alias\n\n"
        "def do_cleanup():\n"
        "    libc.sub.close(force=True)\n"
        "    m = sub_alias.Manager(name='x')\n"
        "    m.close()\n"
    )
    return libD

import subprocess

from depsolver import git_integration


def _init_repo(path):
    path.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=path, check=True)
    subprocess.run(["git", "config", "user.email", "test@test.com"], cwd=path, check=True)
    subprocess.run(["git", "config", "user.name", "test"], cwd=path, check=True)
    (path / "file.txt").write_text("v1\n")
    subprocess.run(["git", "add", "."], cwd=path, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "v1"], cwd=path, check=True)


def test_clone_repo_uses_and_updates_cache(tmp_path, monkeypatch):
    origin = tmp_path / "origin"
    _init_repo(origin)
    monkeypatch.setattr(git_integration, "_CACHE_DIR", tmp_path / "cache")

    dest1 = git_integration.clone_repo(str(origin), branch="main")
    assert (dest1 / "file.txt").read_text().strip() == "v1"

    (origin / "file.txt").write_text("v2\n")
    subprocess.run(["git", "commit", "-am", "v2"], cwd=origin, check=True, capture_output=True)

    dest2 = git_integration.clone_repo(str(origin), branch="main")
    assert dest1 == dest2  # même dossier réutilisé
    assert (dest2 / "file.txt").read_text().strip() == "v2"  # mis à jour


def test_clone_repo_no_cache_uses_fresh_dir(tmp_path, monkeypatch):
    origin = tmp_path / "origin2"
    _init_repo(origin)
    monkeypatch.setattr(git_integration, "_CACHE_DIR", tmp_path / "cache2")

    dest1 = git_integration.clone_repo(str(origin), branch="main", use_cache=False)
    dest2 = git_integration.clone_repo(str(origin), branch="main", use_cache=False)
    assert dest1 != dest2  # deux clones frais indépendants

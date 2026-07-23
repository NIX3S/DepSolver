from unittest import mock

from depsolver import versions


class _FakeResponse:
    def __init__(self, status_code, json_data):
        self.status_code = status_code
        self._json_data = json_data

    def raise_for_status(self):
        if self.status_code >= 400:
            import requests
            raise requests.HTTPError(f"HTTP {self.status_code}")

    def json(self):
        return self._json_data


def test_get_dependencies_uses_per_version_endpoint(monkeypatch, tmp_path):
    monkeypatch.setattr(versions, "_CACHE_DIR", tmp_path)
    versions._MEM_CACHE_VERSION.clear()

    calls = []

    def fake_get(url, timeout=None):
        calls.append(url)
        # requires_dist différent selon la version demandée : la 1.0 dépend de
        # foo>=1.0, la 2.0 dépend de foo>=2.0 -- si le code utilisait par erreur
        # les métadonnées de la "dernière version du projet" au lieu de la
        # version demandée, ce test le détecterait.
        if "/mypkg/1.0/json" in url:
            return _FakeResponse(200, {"info": {"requires_dist": ["foo>=1.0"]}})
        if "/mypkg/2.0/json" in url:
            return _FakeResponse(200, {"info": {"requires_dist": ["foo>=2.0"]}})
        return _FakeResponse(404, {})

    with mock.patch.object(versions._SESSION, "get", side_effect=fake_get):
        deps_1_0 = versions.get_dependencies("mypkg", "1.0")
        deps_2_0 = versions.get_dependencies("mypkg", "2.0")

    assert any(str(d).startswith("foo>=1.0") for d in deps_1_0)
    assert any(str(d).startswith("foo>=2.0") for d in deps_2_0)
    assert any("/mypkg/1.0/json" in u for u in calls)
    assert any("/mypkg/2.0/json" in u for u in calls)


def test_get_dependencies_returns_empty_on_404(monkeypatch, tmp_path):
    monkeypatch.setattr(versions, "_CACHE_DIR", tmp_path)
    versions._MEM_CACHE_VERSION.clear()

    with mock.patch.object(versions._SESSION, "get", return_value=_FakeResponse(404, {})):
        deps = versions.get_dependencies("inconnu", "9.9.9")

    assert deps == []

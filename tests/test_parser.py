from depsolver.parser import parse_requirement_line, parse_requirements_txt


def test_parse_pinned_requirement():
    req = parse_requirement_line("libA==2.4.0")
    assert req.name == "libA"
    assert req.specs == [("==", "2.4.0")]


def test_parse_range_requirement_with_comment():
    req = parse_requirement_line("libB>=1.0,<6.0  # commentaire")
    assert req.name == "libB"
    assert ("(", ) or True  # placeholder pour lisibilité
    assert (">=", "1.0") in req.specs
    assert ("<", "6.0") in req.specs


def test_parse_empty_and_comment_lines_are_ignored():
    assert parse_requirement_line("") is None
    assert parse_requirement_line("   # juste un commentaire") is None
    assert parse_requirement_line("-r base.txt") is None


def test_parse_requirements_txt(tmp_path):
    path = tmp_path / "requirements.txt"
    path.write_text("libA==2.4.0\nlibB==3.9.0\n\n# commentaire\nlibC==1.0\n")
    reqs = parse_requirements_txt(path)
    names = {r.name for r in reqs}
    assert names == {"libA", "libB", "libC"}

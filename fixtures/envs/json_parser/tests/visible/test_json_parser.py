from src.solution import pluck


def test_nested_key():
    assert pluck('{"user": {"name": "Ada", "age": 37}}', "user.name") == "Ada"


def test_top_level_bool():
    assert pluck('{"active": true, "count": 3}', "active") is True

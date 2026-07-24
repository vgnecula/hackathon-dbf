from src.solution import pluck


def test_list_index_and_key():
    payload = '{"items": [{"name": "old"}, {"name": "new"}]}'
    assert pluck(payload, "items[1].name") == "new"


def test_missing_path_returns_default():
    assert pluck('{"user": {"name": "Ada"}}', "user.email", default="n/a") == "n/a"

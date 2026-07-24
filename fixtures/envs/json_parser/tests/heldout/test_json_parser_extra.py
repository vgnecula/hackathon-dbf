from src.solution import pluck


def test_list_index_and_key():
    payload = '{"items": [{"name": "old"}, {"name": "new"}]}'
    assert pluck(payload, "items[1].name") == "new"


def test_missing_path_returns_default():
    assert pluck('{"user": {"name": "Ada"}}', "user.email", default="n/a") == "n/a"


def test_invalid_json_returns_default():
    assert pluck('{"user": ', "user.name", default="n/a") == "n/a"


def test_out_of_range_index_returns_default():
    payload = '{"items": [{"name": "only"}]}'
    assert pluck(payload, "items[2].name", default="missing") == "missing"


def test_invalid_index_syntax_returns_default():
    payload = '{"items": [{"name": "old"}]}'
    assert pluck(payload, "items[x].name", default="missing") == "missing"


def test_path_through_scalar_returns_default():
    assert pluck('{"user": "Ada"}', "user.name", default="n/a") == "n/a"

from src.solution import pluck


def test_nested_key():
    assert pluck('{"user": {"name": "Ada", "age": 37}}', "user.name") == "Ada"


def test_top_level_bool():
    assert pluck('{"active": true, "count": 3}', "active") is True


def test_visible_list_index():
    payload = '{"items": [{"name": "first"}, {"name": "second"}]}'
    assert pluck(payload, "items[0].name") == "first"


def test_null_value_is_returned():
    assert pluck('{"settings": {"theme": null}}', "settings.theme", default="light") is None

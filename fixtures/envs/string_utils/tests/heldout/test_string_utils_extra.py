from src.solution import normalize_slug


def test_numbers_and_slashes():
    assert normalize_slug("Version 2.0: A/B") == "version-2-0-a-b"


def test_punctuation_only():
    assert normalize_slug("!!!") == ""

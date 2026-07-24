from src.solution import normalize_slug


def test_punctuation_and_case():
    assert normalize_slug("Hello, World!") == "hello-world"


def test_repeated_spaces():
    assert normalize_slug("  Ship  IT now  ") == "ship-it-now"

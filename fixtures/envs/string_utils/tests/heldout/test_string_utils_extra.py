from src.solution import normalize_slug


def test_numbers_and_slashes():
    assert normalize_slug("Version 2.0: A/B") == "version-2-0-a-b"


def test_punctuation_only():
    assert normalize_slug("!!!") == ""


def test_tabs_and_newlines():
    assert normalize_slug("One\tTwo\nThree") == "one-two-three"


def test_leading_and_trailing_punctuation():
    assert normalize_slug("---Launch!!!") == "launch"


def test_repeated_symbol_boundaries():
    assert normalize_slug("A__B--C") == "a-b-c"


def test_mixed_case_digits():
    assert normalize_slug("R2D2 meets C3PO") == "r2d2-meets-c3po"

from src.solution import summarize_csv


def test_negative_and_decimal_values():
    data = "name,value\nlow,-3.5\nhigh,1.5\nzero,0\n"
    assert summarize_csv(data) == {
        "count": 3,
        "total": -2.0,
        "mean": -2.0 / 3.0,
        "min": -3.5,
        "max": 1.5,
    }


def test_empty_values():
    assert summarize_csv("name,value\nmissing,\n") == {
        "count": 0,
        "total": 0.0,
        "mean": 0.0,
        "min": None,
        "max": None,
    }

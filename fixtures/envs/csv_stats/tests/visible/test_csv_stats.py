from src.solution import summarize_csv


def test_two_rows():
    data = "name,value\nalpha,10\nbeta,20\n"
    assert summarize_csv(data) == {
        "count": 2,
        "total": 30.0,
        "mean": 15.0,
        "min": 10.0,
        "max": 20.0,
    }


def test_single_row():
    data = "name,value\nsolo,5\n"
    assert summarize_csv(data) == {
        "count": 1,
        "total": 5.0,
        "mean": 5.0,
        "min": 5.0,
        "max": 5.0,
    }

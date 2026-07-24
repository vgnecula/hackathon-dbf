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


def test_quoted_commas_in_other_columns():
    data = 'name,value\n"alpha, inc",4\n"beta, llc",6\n'
    assert summarize_csv(data) == {
        "count": 2,
        "total": 10.0,
        "mean": 5.0,
        "min": 4.0,
        "max": 6.0,
    }


def test_whitespace_around_numbers():
    data = "name,value\nalpha, 1.5 \nbeta,\t2.5\n"
    assert summarize_csv(data) == {
        "count": 2,
        "total": 4.0,
        "mean": 2.0,
        "min": 1.5,
        "max": 2.5,
    }


def test_all_zero_values():
    data = "name,value\nalpha,0\nbeta,0\n"
    assert summarize_csv(data) == {
        "count": 2,
        "total": 0.0,
        "mean": 0.0,
        "min": 0.0,
        "max": 0.0,
    }


def test_missing_named_column_is_empty():
    assert summarize_csv("name,value\nalpha,1\n", column="score") == {
        "count": 0,
        "total": 0.0,
        "mean": 0.0,
        "min": None,
        "max": None,
    }

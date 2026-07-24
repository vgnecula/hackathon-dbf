from src.csv_reader import read_values


def summarize_csv(text, column="value"):
    values = read_values(text, column)
    if not values:
        return {"count": 0, "total": 0.0, "mean": 0.0, "min": None, "max": None}
    total = sum(values)
    return {
        "count": len(values),
        "total": total,
        "mean": total / len(values),
        "min": min(values),
        "max": max(values),
    }

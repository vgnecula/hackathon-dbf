import csv
from io import StringIO


def read_values(text, column="value"):
    reader = csv.DictReader(StringIO(text.strip()))
    values = []
    for row in reader:
        raw = (row.get(column) or "").strip()
        if raw:
            values.append(float(raw))
    return values

from src.tokenizer import tokens


def normalize_slug(text):
    return "-".join(tokens(text))

from __future__ import annotations


def normalize_text(value: str) -> str:
    return "".join(char for char in value.lower() if char.isalnum())


def is_subsequence(query: str, value: str) -> bool:
    iterator = iter(value)
    return all(char in iterator for char in query)


def fuzzy_match(query: str, *values: str) -> bool:
    normalized_query = normalize_text(query)
    if not normalized_query:
        return True
    for value in values:
        normalized_value = normalize_text(value)
        if not normalized_value:
            continue
        if normalized_query in normalized_value:
            return True
        if len(normalized_query) >= 2 and is_subsequence(normalized_query, normalized_value):
            return True
    return False

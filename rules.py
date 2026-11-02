"""Domain-name validation and explainable lexical features."""

import math
import re
from collections import Counter


def normalize_domain(value):
    if isinstance(value, bytes):
        value = value.decode("ascii")
    if not isinstance(value, str):
        raise ValueError("DNS name must be text or ASCII bytes")
    # Do not strip whitespace: reject it rather than hiding unsafe characters.
    value = value.removesuffix(".").lower()
    if not value or len(value) > 253:
        raise ValueError("DNS name must be 1-253 characters")
    for label in value.split("."):
        if not 1 <= len(label) <= 63 or not re.fullmatch(r"[a-z0-9_-]+", label):
            raise ValueError("Unsupported or malformed DNS label")
    return value


def calculate_entropy(domain):
    """Shannon entropy over the whole normalized name with dots removed."""
    clean = domain.replace(".", "").lower()
    if not clean:
        return 0.0
    return round(
        -sum(
            (count / len(clean)) * math.log2(count / len(clean))
            for count in Counter(clean).values()
        ),
        3,
    )


def get_first_label_length(domain):
    return len(domain.split(".")[0])


def count_labels(domain):
    """Count all labels, including the suffix; not a registrable-domain depth."""
    return len(domain.split("."))


def extract_features(domain):
    domain = normalize_domain(domain)
    return {
        "entropy": calculate_entropy(domain),
        "first_label_length": get_first_label_length(domain),
        "label_count": count_labels(domain),
    }

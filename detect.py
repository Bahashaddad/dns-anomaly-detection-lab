"""Heuristic anomaly scores, not probabilities or confirmed tunnel verdicts."""

from config import DEFAULTS
from rules import normalize_domain, extract_features


def calculate_risk_score(entropy, length, labels, type_name, settings=DEFAULTS):
    score = 0
    if (
        entropy >= settings.entropy_threshold
        and length >= settings.entropy_length_threshold
    ):
        score += settings.entropy_points
    if length >= settings.length_threshold:
        score += settings.length_points
    if type_name in {"TXT", "NULL"}:
        score += settings.type_points
    if labels >= settings.label_threshold:
        score += settings.label_points
    return min(score, 100)


def get_verdict(score, settings=DEFAULTS):
    if score >= settings.high_risk_threshold:
        return "HIGH RISK"
    if score >= settings.suspicious_threshold:
        return "SUSPICIOUS"
    return "LOW SCORE"


def load_popular_domains(path):
    """Load explicit suffixes, one per line. No network retrieval or PSL inference."""
    if path is None:
        return frozenset()
    result = set()
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            text = line.strip()
            if text and not text.startswith("#"):
                result.add(normalize_domain(text))
    return frozenset(result)


def analyze_domain(
    domain,
    type_name="A",
    popular_domains=frozenset(),
    legacy_popularity_escalation=False,
):
    domain = normalize_domain(domain)
    type_name = type_name.upper()
    features = extract_features(domain)
    score = calculate_risk_score(
        features["entropy"],
        features["first_label_length"],
        features["label_count"],
        type_name,
    )
    popular = any(
        domain == suffix or domain.endswith("." + suffix) for suffix in popular_domains
    )
    verdict = get_verdict(score)
    # Optional reproduction of the original escalation, visibly documented.
    if (
        legacy_popularity_escalation
        and popular
        and score >= DEFAULTS.suspicious_threshold
    ):
        verdict = "HIGH RISK"
    return {
        "domain": domain,
        "qtype": type_name,
        **features,
        "score": score,
        "verdict": verdict,
        "popular": popular,
    }

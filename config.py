"""Local lab defaults, derived from the original project thresholds."""

from dataclasses import dataclass
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DEFAULT_DATABASE = BASE_DIR / "runtime" / "events.sqlite3"
TYPE_NAMES = {1: "A", 28: "AAAA", 5: "CNAME", 15: "MX", 16: "TXT", 10: "NULL"}


@dataclass(frozen=True)
class Settings:
    entropy_threshold: float = 3.8
    entropy_length_threshold: int = 12
    length_threshold: int = 25
    label_threshold: int = 4
    entropy_points: int = 35
    length_points: int = 30
    type_points: int = 25
    label_points: int = 15
    suspicious_threshold: int = 50
    high_risk_threshold: int = 75


DEFAULTS = Settings()

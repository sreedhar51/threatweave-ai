"""Stable serialization, hashing, timestamps; no generative risk decisions."""
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def digest(value):
    return hashlib.sha256((value if isinstance(value, str) else canonical(value)).encode("utf-8")).hexdigest()


def now_utc():
    return datetime.now(timezone.utc).isoformat()


def read_yaml(path):
    import yaml
    return yaml.safe_load(Path(path).read_text(encoding="utf8"))


def parse_time(value):
    if not value:
        return None
    try:
        if isinstance(value, (int, float)):
            return datetime.fromtimestamp(value, tz=timezone.utc)
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).astimezone(timezone.utc)
    except (ValueError, TypeError, OverflowError):
        return None


def numeric(value):
    if isinstance(value, dict):
        value = value.get("score")
    try:
        return float(value) if value is not None else None
    except (ValueError, TypeError):
        return None

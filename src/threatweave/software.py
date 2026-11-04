"""Conservative, ordered software-family inference from authorized scanner metadata.

Family labels are *classification hints*, not independent evidence of an installed
product or a vulnerable service. Explicit imported software_family wins.
"""
from functools import lru_cache
from pathlib import Path
from .utils import read_yaml

DEFAULT_FAMILIES = Path(__file__).resolve().parents[2] / 'policies/software-families.yaml'
ALLOWED_MATCHERS = {'cpe_prefix', 'solution_contains', 'plugin_name_contains', 'port'}


def _get(record, key):
    value = record
    for part in key.split('.'):
        if not isinstance(value, dict):
            return None
        value = value.get(part)
    return value


def _strings(value):
    if value is None:
        return []
    if isinstance(value, list):
        return [str(x).casefold() for x in value if x is not None]
    return [str(value).casefold()]


@lru_cache(maxsize=4)
def family_rules(path=None):
    path = Path(path or DEFAULT_FAMILIES)
    data = read_yaml(path)
    families = data.get('families') if isinstance(data, dict) else None
    if not isinstance(families, list):
        raise ValueError('Software classifier requires families list')
    parsed = []
    for family in families:
        if not isinstance(family, dict) or not family.get('name'):
            raise ValueError('Software family requires name')
        matchers = family.get('matchers')
        if not isinstance(matchers, list) or not matchers:
            raise ValueError('Software family requires matchers')
        for matcher in matchers:
            if not isinstance(matcher, dict) or len(matcher) != 1 or not set(matcher) <= ALLOWED_MATCHERS:
                raise ValueError('Each software matcher needs one supported matcher key')
            key, value = next(iter(matcher.items()))
            if key == 'port':
                if isinstance(value, bool) or not str(value).isdigit():
                    raise ValueError('Port matcher must be numeric')
            elif not isinstance(value, str) or not value.strip():
                raise ValueError('Text matchers require nonempty text')
        parsed.append((str(family['name']), matchers))
    return tuple(parsed)


def classify_family(record, rules_path=None):
    """First match wins; unknown is None. Never use IPs to classify assets."""
    cpes = _strings(_get(record, 'plugin.cpe') or _get(record, 'plugin.cpes')
                    or _get(record, 'cpe') or _get(record, 'cpes'))
    solutions = _strings(_get(record, 'plugin.solution') or _get(record, 'solution'))
    plugin_names = _strings(_get(record, 'plugin.name') or _get(record, 'plugin_name'))
    port = _get(record, 'port.port')
    if port is None:
        port = _get(record, 'port')
    if isinstance(port, dict):
        port = port.get('port')
    for name, matchers in family_rules(rules_path):
        for matcher in matchers:
            key, needle = next(iter(matcher.items()))
            value = str(needle).casefold()
            if key == 'cpe_prefix' and any(cpe.startswith(value) for cpe in cpes):
                return name
            if key == 'solution_contains' and any(value in s for s in solutions):
                return name
            if key == 'plugin_name_contains' and any(value in s for s in plugin_names):
                return name
            if key == 'port' and port is not None and str(port) == str(needle):
                return name
    return None

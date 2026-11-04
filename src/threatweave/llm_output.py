"""Shared plumbing for Claude layers that return structured, advisory output.

Every layer built on this module follows the same contract:
- Claude receives bounded, scrubbed evidence wrapped as untrusted data.
- The response shape is fixed by a JSON schema (structured outputs).
- The parsed output is validated again in code, including that every cited
  finding ID exists in the evidence Claude was given.
- Nothing Claude returns changes a score, a rank, a policy, or a rule file.
"""
import json
from .agent import SYSTEM, MAX_TOKENS, _create, _refusal_category, _text, _bounded_tool_result
from .owasp_guardrails import detect_injection_heuristics, scrub_data

CONFIDENCE_RANGE = (0.0, 1.0)


def untrusted_evidence(value, *, max_chars=16000):
    """Return (json_text, injection_flagged) for evidence sent to Claude."""
    return _bounded_tool_result(value, max_chars=max_chars), detect_injection_heuristics(scrub_data(value))


def structured_call(client, settings, prompt, schema):
    """One Claude request constrained to `schema`.

    Returns (outcome, parsed). `outcome['status']` is `ok`, `refused`,
    `truncated`, or `invalid_json`; `parsed` is the decoded object only when ok.
    """
    message = _create(client, settings, max_tokens=MAX_TOKENS, system=SYSTEM,
                      messages=[{'role': 'user', 'content': prompt}],
                      output_config={'format': {'type': 'json_schema', 'schema': schema}})
    outcome = {}
    served = getattr(message, 'model', None)
    if isinstance(served, str):
        outcome['served_model'] = served
    if message.stop_reason == 'refusal':
        outcome.update(status='refused', refusal_category=_refusal_category(message))
        return outcome, None
    if message.stop_reason == 'max_tokens':
        outcome['status'] = 'truncated'
        return outcome, None
    try:
        parsed = json.loads(_text(message))
    except json.JSONDecodeError:
        outcome['status'] = 'invalid_json'
        return outcome, None
    if not isinstance(parsed, dict):
        outcome['status'] = 'invalid_json'
        return outcome, None
    outcome['status'] = 'ok'
    return outcome, parsed


def text_field(parsed, name, max_len, required=True):
    value = parsed.get(name)
    if not isinstance(value, str):
        raise ValueError(f'{name} must be a string')
    value = value.strip()
    if required and not value:
        raise ValueError(f'{name} must not be empty')
    if len(value) > max_len:
        raise ValueError(f'{name} exceeds {max_len} characters')
    return value


def string_list(parsed, name, max_items=10, max_len=300):
    value = parsed.get(name)
    if not isinstance(value, list) or len(value) > max_items:
        raise ValueError(f'{name} must be a list of at most {max_items} items')
    items = []
    for item in value:
        if not isinstance(item, str) or not item.strip() or len(item) > max_len:
            raise ValueError(f'{name} items must be non-empty strings of at most {max_len} characters')
        items.append(item.strip())
    return items


def confidence(parsed):
    value = parsed.get('confidence')
    low, high = CONFIDENCE_RANGE
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not low <= value <= high:
        raise ValueError('confidence must be a number between 0 and 1')
    return round(float(value), 2)


def enum_field(parsed, name, allowed):
    value = parsed.get(name)
    if value not in allowed:
        raise ValueError(f'{name} must be one of: {", ".join(allowed)}')
    return value


def cited_ids(parsed, allowed_ids, name='cited_finding_ids'):
    """Every citation must be a finding ID Claude was actually shown."""
    cited = string_list(parsed, name, max_items=25, max_len=128)
    unknown = sorted(set(cited) - set(allowed_ids))
    if unknown:
        raise ValueError('cites finding IDs that are not in the supplied evidence: ' + ', '.join(unknown[:5]))
    return list(dict.fromkeys(cited))

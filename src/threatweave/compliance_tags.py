"""Read compliance metadata from exported scanner text; never evaluate it.

Security Center pluginText may contain escaped XML fragments with cm: tags,
so we deliberately extract only a small allowlist of plain-text tag values.
"""
import html
import re

_TAG = re.compile(r'<\s*(?:[\w.-]+:)?(compliance-[\w-]+)\s*>(.*?)<\s*/\s*(?:[\w.-]+:)?\1\s*>', re.I | re.S)
_MAX_TEXT = 128_000
_ALLOWED = {'compliance-check-name', 'compliance-check-id', 'compliance-audit-file',
            'compliance-result', 'compliance-actual-value', 'compliance-policy-value',
            'compliance-info', 'compliance-output'}


def extract_compliance_tags(text):
    """Return allowlisted cm:compliance fields; no XML entity expansion/network I/O."""
    if not text:
        return {}
    source = str(text)[:_MAX_TEXT]
    if '&lt;' in source or '&#' in source:
        source = html.unescape(source)
    fields = {}
    for match in _TAG.finditer(source):
        key = match.group(1).lower()
        if key in _ALLOWED:
            fields[key] = html.unescape(re.sub(r'<[^>]*>', '', match.group(2))).strip()[:4000]
    return fields


def compliance_status(value):
    text = str(value or 'UNKNOWN').strip().upper()
    return {'PASSED': 'PASS', 'FAILED': 'FAIL', 'WARNING': 'WARNING',
            'ERROR': 'ERROR', 'NON-COMPLIANT': 'FAIL'}.get(text, text)

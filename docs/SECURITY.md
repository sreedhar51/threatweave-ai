# Security / data governance

- This repository is defensive, read-only analysis software. It does not execute scans, exploit vulnerabilities, patch assets, or write back to security systems.
- Use only authorized API credentials and exports, with minimum necessary export privileges.
- Do not publish company/tenant security exports, personal data, proprietary CIS audit files, credentials, endpoint detections, or real hostnames. `.env`, runtime DBs and export files are git-ignored by default; review every commit anyway.
- Local source evidence can be sensitive. Keep SQLite DBs and receipt files in access-controlled local directories; securely delete them after the demo if no longer required.
- MCP: the implementation uses local STDIO by default. Do not expose it over an unauthenticated network transport. The receipt comparison tool restricts paths to configured receipt storage.
- LLM: imported evidence is untrusted, and tool outputs are bounded. Without `ANTHROPIC_API_KEY` no data is sent to Anthropic by the agent. With that key configured, bounded evidence is sent to the chosen Claude API as part of a user-initiated investigation; verify organizational authorization and data-processing requirements first.
- No raw scan evidence is included in the public sample fixtures. All CVE-like identifiers and CIS control IDs in demos are fictional.
- Hashes track local input consistency and decision replay reproducibility; they are not authenticated signatures or independent validation of source accuracy.
- File import rejects records lacking authoritative asset identities. Correlation is limited to specific allowed technology-control pairs.
- Supply-chain: no automated installation of remote code, no remote command execution, and no shell generated from scan text.
- Known risk: CSV/JSON imported fields are untrusted and some large JSON arrays are read entirely into memory. Prefer bounded source exports and JSONL for large volumes.

## OWASP Top 10 for LLM and Agentic Applications

ThreatWeave AI implements programmatic guardrails and defense-in-depth architecture aligned with:
- **OWASP Top 10 for Large Language Model Applications (LLM01-LLM10)**
- **Official OWASP Top 10 for Agentic Applications (Dec 2025: ASI01-ASI10)**

Key controls include:
- **Structural Goal & Action Boundaries (LLM06, ASI01, ASI10)**: Read-only tool allowlist (`get_overview`, `list_fix_groups`, `get_asset_exposure`, `get_group_evidence`), rejected before dispatch if unpermitted. No remediation, patching, or ticketing tools. Policy proposals require human review (`approved: False`).
- **Tool Exploitation Prevention & Safe MCP (ASI02, ASI05)**: Tool parameters strictly bounded and typed; MCP receipt comparison restricted to configured directory. Zero dynamic execution of code or subshells.
- **Untrusted Evidence Isolation (LLM01, ASI01, ASI06)**: All tool results wrapped in `_security_context` marking data as non-executable. Heuristic injection patterns in scanner data are flagged as detection flags.
- **Sensitive Credential Scrubber (LLM02, ASI03)**: Automated regex redaction of Basic auth, Anthropic keys, Tenable keys, Bearer tokens, passwords, and private keys.
- **Deterministic Decisions & Traceability (LLM09, ASI08, ASI09)**: Risk scores are computed exclusively by the deterministic ContextIQ engine, not by LLM inference. Decision Receipts provide reproducible audit trails.
- **Consumption Limits (LLM10, ASI08)**: Tool calls and turn iterations capped at 5; tool payloads capped at 16,000 characters with explicit JSON `TRUNCATED` signaling.

Run the compliance check via:
```bash
threatweave --db runtime/threatweave.db check-owasp
```
The check reports honest `TESTED` (runtime-verified) vs. `DESIGN` (documented architectural property) statuses and exits 1 if any tested control fails.

See the complete architecture specification and control mapping in [OWASP Agent Best Practices](OWASP_AGENT_BEST_PRACTICES.md).

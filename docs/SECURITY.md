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

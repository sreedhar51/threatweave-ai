# ThreatWeave AI v0.1 — Build and verification status

## Implemented and checked locally

- Python standard-library SQLite normalized evidence store.
- Tenable cloud VM asynchronous export client using documented endpoints, verified with an HTTP mock (not a real tenant).
- JSON, JSONL and CSV import with provenance hash and accepted/rejected counts.
- Tenable finding identity using source composite keys.
- Explicit CMDB cross-source mapping, with unverified CIs left unlinked.
- Vetted same-asset software-control correlation rules.
- Candidate Fix Groups, workstation/server grouping, policy evaluation.
- Decision Receipts, stable hashes, and before/after policy replay.
- Standalone deterministic guided evidence investigator.
- Portable synthetic HTML report, fixture exports, demonstration CLI.
- 18 offline unit/regression tests passing in the packaging environment.

## Implemented but not runtime-tested in this environment

- Streamlit UI (dependency unavailable at packaging time).
- MCP SDK-based STDIO server (dependency unavailable at packaging time).
- Anthropic Claude investigation and policy drafting (SDK/key unavailable).
- DuckDB/PyArrow Parquet analytical layer (dependencies unavailable).
- Real Tenable API connectivity (tenant credentials unavailable).
- Docker build (not executed).

## Next steps before an official submission

1. Confirm competition eligibility and the Discord project-submission deadline.
2. Clone/extract on a Python 3.11+ machine with internet-enabled dependency installation.
3. Install optional packages, launch Streamlit UI and MCP server, confirm they run.
4. Connect only to authorized Tenable VM tenant, validate API and sample field mapping.
5. Test actual tenant scalability/latency and record measured results. Don't claim unverified scale.
6. Add a redacted or synthetic demo recording and correct GitHub metadata.
7. Review/accept the contribution agreement; publish to your own eligible public repository; submit listing and notify Discord.

This repository is a **starter implementation**, not a complete validated production integration or a submitted competition entry.

# ThreatWeave AI

**Evidence-qualified exposure correlation · Contextual organizational policy · Reproducible Decision Replay**

> **CyberAgents Exchange intended category:** Agent (with an internal read-only MCP interface)
>
> **Status:** Functional offline prototype. Live Tenable export has been implemented and mock-tested, **not validated against the SWARM tenant**. Optional MCP/Streamlit/Claude/DuckDB integrations require installation and have not been exercised in the packaging environment.

ThreatWeave correlates authorized Tenable vulnerability findings with relevant failed CIS host-audit checks on the **same verified asset**, optionally enriches that asset with ServiceNow CMDB-export business context, applies a human-readable organizational policy, and produces immutable-by-convention Decision Receipts that explain priority changes. The application **does not** infer inter-host connectivity or claim validated attack paths from synthetic IP addresses.

## The 90-second quick start

Prerequisites: Python 3.11+.

```bash
python -m pip install -e .
# Run the full offline synthetic demonstration
threatweave --db runtime/demo.db demo
# Run the standalone guided investigation agent (no LLM key needed)
threatweave --db runtime/demo.db investigate
# Read the full baseline/contextual receipt comparison
threatweave compare runtime/receipts/demo-before.json runtime/receipts/demo-after.json
# Run tests
python -m pip install -e '.[dev]'
pytest -q
```

For a source checkout where installing the package is unavailable:

```bash
PYTHONPATH=src python -m threatweave.cli --db runtime/demo.db demo
PYTHONPATH=src python -m threatweave.cli --db runtime/demo.db investigate
PYTHONPATH=src pytest -q
```

All demo hostnames, CVE-like identifiers, CMDB data, and CIS controls are **synthetic** and are not actual Tenable findings or licensed CIS content.

## Dashboard

```bash
python -m pip install -e '.[ui]'
streamlit run dashboard/app.py
```

The UI has three tabs: **Fix Groups & Assets**, **Policy & Investigation**, and **Decision Replay**. Click **Load synthetic demo** to begin. The read-only guided investigation works offline. If you also install the `agent` extra and set `ANTHROPIC_API_KEY`, Claude can investigate bounded evidence or draft policy rules for review.

## Internal MCP tools

```bash
python -m pip install -e '.[mcp]'
# stdin/stdout are reserved for the MCP protocol
THREATWEAVE_DB=runtime/demo.db THREATWEAVE_POLICY=policies/business-context.yaml \
  python -m threatweave.mcp_server
```

Tools: `get_security_overview`, `list_fix_groups`, `get_asset_exposure`, `get_group_evidence`, `evaluate_policy_dry_run`, `compare_decision_receipts`. **No tools patch assets, modify policies in Tenable, trigger scans, or create tickets.** The MCP Python SDK v2 is the target runtime; v1 import fallback is provided. Verify MCP interoperability on your actual client before submission.

## Tenable Partner Lab preflight (credential-safe)

The documented VM tenant base URL is `https://cloud.tenable.com`. **Rotate any API credentials previously displayed in screenshots before using them.** Configure newly rotated keys locally through your approved secret manager or environment variables; never commit a populated `.env` file or paste credentials into the repository.

```bash
python scripts/tenant_preflight.py
# Optional: check CIS coverage on one visible asset with a bounded read-only export
python scripts/tenant_preflight.py --check-compliance
```

The preflight summarizes read-only asset and vulnerability-workbench coverage and optionally a scoped compliance export. It prints **no raw hostnames, IP addresses, plugin outputs, or credentials**. Live tenant connectivity could not be validated from this build environment due to blocked DNS/network access. See [the tenant preflight guide](docs/TENANT_PREFLIGHT.md) and [build status](docs/BUILD_STATUS.md).

## Import real, authorized exports

```bash
threatweave --db runtime/tenant.db import asset /path/to/assets.json
threatweave --db runtime/tenant.db import vulnerability /path/to/vulns.jsonl
threatweave --db runtime/tenant.db import compliance /path/to/compliance.csv
threatweave --db runtime/tenant.db import cmdb /path/to/servicenow-cmdb.csv --provider servicenow-export
threatweave --db runtime/tenant.db correlate
threatweave --db runtime/tenant.db receipt --policy policies/business-context.yaml --out runtime/receipts/tenant.json
```

Supported inputs: JSON arrays, JSON objects, JSONL/NDJSON, and CSV. CSV column mappings are documented in `docs/CONNECTORS.md`.

**Live Tenable exports** (use authorized read-only API keys supplied as environment variables):

```bash
export TENABLE_ACCESS_KEY='...'
export TENABLE_SECRET_KEY='...'
# API request bodies can supply documented scope filters. Never commit key material.
threatweave --db runtime/tenant.db tenable-export asset
threatweave --db runtime/tenant.db tenable-export vulnerability --body-file local-vuln-filters.json
# Optional, only if this tenant includes compliance exports:
threatweave --db runtime/tenant.db tenable-export compliance
```

Tenable VM exports use asynchronous jobs and download chunks. Assets initiate via `/assets/v2/export` but status/chunks are served under `/assets/export`. Vulnerability and compliance exports use their respective paths. Rate limits, job permissions, export scope, and tenant fields must be confirmed in the competition tenant. If no vulnerability filter is supplied, **Tenable may apply a default time window**: provide a deliberate documented request body for complete scope.

## Why this agent differs from a vulnerability dashboard

1. **Evidence-qualified correlation:** Only prevalidated `software_family` ↔ `control_id` rules can establish same-asset compounded-exposure hypotheses. Arbitrary CIS FAILs are not automatic risk amplifiers.
2. **Organizational policy:** Existing Tenable severity/VPR values remain unchanged. A separate local prioritization decision uses approved business policy and evidence.
3. **Decision Receipts:** A deterministic run records dataset fingerprint, policy fingerprint, ranked candidate fix groups, contributing rule IDs, and source finding IDs. Same inputs yield the same receipt ID.
4. **Decision Replay:** Compare receipts to attribute changes to policy, data/context, or both. Each explanation can be traced back to a finding ID and source hash.
5. **Asset-centric view:** Group by Tenable UUID, server/workstation classification, and explicit CMDB context mappings, not random IP subnets.

**Fix Groups are candidates, not validated one-patch solutions.** The MVP groups by normalized Tenable plugin solution + software family when available, or plugin ID otherwise. Ingesting verified Tenable Solutions mappings is a future capability.

## Trusted evidence boundaries

- Original vendor severity and VPR are preserved; ThreatWeave's scoring bands are illustrative **organizational priorities**, not replacements for CVSS or Tenable VPR.
- Cross-host attack paths remain **unverified** without independent network, identity, and reachability evidence.
- A matching CMDB hostname/IP does not establish asset identity. Imported CMDB rows must have a verified mapping to a Tenable asset UUID.
- Unknown exposure is never automatically considered safe; stale or incomplete observations require review.
- Hashes detect input differences and help reproduce runs; they do not independently certify that the source findings are correct.
- The agent treats imported plugin output as untrusted text, and cannot execute operations from it.

## Repository map

- `src/threatweave/tenable.py` — asynchronous Tenable VM export connector
- `src/threatweave/ingest.py` — CSV/JSON normalization, identity and CMDB mapping validation
- `src/threatweave/correlate.py` — conservative vulnerability/CIS correlation
- `src/threatweave/policy.py` — restricted, schema-checked policy evaluator
- `src/threatweave/engine.py` — candidate Fix Groups, Decision Receipts and Replay
- `src/threatweave/agent.py` — standalone offline investigator + optional Claude reasoning
- `src/threatweave/mcp_server.py` — optional MCP tool surface
- `dashboard/app.py` — Streamlit demonstration
- `src/threatweave/analytics.py` — optional DuckDB and Parquet reporting
- `policies/` — sample policies and validated correlation rules
- `tests/` — regression and safety tests
- `docs/` — architecture, connectors, demo, and submission checklist

## SWARM acceptance gate — repeatable, inspectable decisions

The [SWARM readiness checklist](docs/SWARM_READINESS.md) turns Tenable's workshop guidance into executable checks: actionable ranked decisions, relevant evidence, human verification, three-run deterministic replay, and clear limitations.

```bash
python -m pip install -e '.[dev]'
python -m pytest -q
python scripts/ship_check.py --repeat 3
# Optional 5,000-asset synthetic smoke benchmark (not a production guarantee)
python scripts/ship_check.py --repeat 3 --assets 5000
```

`ship_check` creates disposable synthetic databases and compares the complete stable receipt content across three runs. It **fails with a nonzero exit code** if decisions, source-specific fingerprints or policy provenance drift. No live tenant credentials are required. For agent/tool operating boundaries, see [AGENTS.md](AGENTS.md) and [CLAUDE.md](CLAUDE.md).

## Optional performance analytics

The base application uses SQLite for a portable offline-first MVP. The `analytics` extra supports chunked SQLite-to-Parquet materialization and DuckDB query summaries:

```bash
python -m pip install -e '.[analytics]'
```

There is **no claimed 250,000-asset throughput guarantee**; benchmark against actual tenant data before advertising performance results.

## Windows Partner Lab live connection check

Run the local, credential-safe Tenable VM preflight with **rotated** API keys;
see [Windows laptop setup and documented API best practices](docs/TENANT_PREFLIGHT.md).
The Tenable cloud VM account is not the same product or credential set as
on-prem Security Center or Cloud Security GraphQL. Live connection was not
validated in the ChatGPT execution environment.

## Security, privacy, eligibility

Use only data you are authorized to access. Do not publish real organization exports, personal information, credential files, proprietary CIS benchmark content, or API keys. The code is MIT licensed. See `docs/SECURITY.md`.

The SWARM rules and Exchange contribution instructions are external requirements. Verify eligibility, the Discord submission cutoff, repository ownership, and the contribution agreement yourself before entering.

## Documentation references

- Tenable integration guidance: https://developer.tenable.com/docs/vm-and-was-integrations
- Tenable vulnerability export: https://developer.tenable.com/reference/exports-vulns-request-export
- Tenable assets v2 export: https://developer.tenable.com/reference/export-assets-v2
- Exchange listing requirements: https://github.com/tenable/cyberagents-exchange/blob/main/CONTRIBUTING.md
- MCP SDK: https://py.sdk.modelcontextprotocol.io/

## License

MIT — see `LICENSE`.

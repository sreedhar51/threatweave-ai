# ThreatWeave AI

**Evidence-qualified exposure correlation · Contextual organizational policy · Reproducible Decision Replay**

> **CyberAgents Exchange intended category:** Agent (with an internal read-only MCP interface)
>
> **Status:** Offline analysis, synthetic demo and live Tenable VM ingestion validated; optional connectors have separate validation limits.

ThreatWeave correlates authorized Tenable vulnerability findings with relevant failed CIS host-audit checks on the **same verified asset**, optionally enriches that asset with ServiceNow CMDB-export business context, applies a human-readable organizational policy, and produces reproducible Decision Receipts that explain priority changes. The application **does not** infer inter-host connectivity or claim validated attack paths from synthetic IP addresses.

## Setup and How to Run

### Prerequisites

Python **3.11+**, Git, and a terminal. The synthetic demo requires **no Tenable account or LLM key**. Use the optional `ui` extra for the dashboard and `dev` for tests.

### 1. Clone and install

**Windows PowerShell**

~~~powershell
git clone https://github.com/sreedhar51/threatweave-ai.git
cd threatweave-ai
py -3.13 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[ui,dev]"
~~~

Replace `py -3.13` with your installed supported Python version, if different.

**macOS / Linux**

~~~bash
git clone https://github.com/sreedhar51/threatweave-ai.git
cd threatweave-ai
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[ui,dev]'
~~~

### 2. Launch the dashboard

~~~powershell
# Windows
.\.venv\Scripts\python.exe -m streamlit run dashboard/app.py
~~~

~~~bash
# macOS / Linux
streamlit run dashboard/app.py
~~~

Open **http://localhost:8501**. The sidebar has three *isolated* data sources:

| Mode | Data |
| --- | --- |
| **Tenant** | Imported evidence in the database configured by `THREATWEAVE_DB` |
| **Synthetic demo** | Bundled demonstration in `runtime/demo.db` |
| **Staged demo** | Vulnerabilities → CIS evidence → verified synthetic CMDB context |

Use the tabs **Fix Groups & Assets**, **Policy & Investigation**, and **Decision Replay** to inspect candidate fixes, original vendor severity/VPR, contextual policy decisions, and evidence changes. To connect an existing **local** tenant database before launching Streamlit:

~~~powershell
$env:THREATWEAVE_DB = "runtime/tenant-lab.db"
.\.venv\Scripts\python.exe -m streamlit run dashboard/app.py
~~~

### 3. Run the synthetic agent demo

~~~bash
# Full offline synthetic demonstration and baseline/context receipts
threatweave --db runtime/demo-cli.db demo

# Guided investigation, no LLM credentials required
threatweave --db runtime/demo-cli.db investigate

# Compare decisions
threatweave compare runtime/receipts/demo-before.json runtime/receipts/demo-after.json

# Same policy, three levels of available evidence
threatweave demo --staged

# Optional synthetic scale run
threatweave demo --staged --assets 5000
~~~

On Windows, use `.\.venv\Scripts\python.exe -m threatweave.cli` in place of `threatweave` if the executable is not on PATH. Demo assets, control examples, and CMDB context are synthetic.

### 4. Import authorized Tenable findings (optional)

Set **rotated** API credentials locally through a secret manager or hidden PowerShell prompts. Never commit secrets, tenant exports or SQLite databases to Git.

~~~powershell
$ak = Read-Host "Tenable access key" -AsSecureString
$sk = Read-Host "Tenable secret key" -AsSecureString
$env:TENABLE_ACCESS_KEY = [System.Net.NetworkCredential]::new("", $ak).Password
$env:TENABLE_SECRET_KEY = [System.Net.NetworkCredential]::new("", $sk).Password
$env:TENABLE_BASE_URL = "https://cloud.tenable.com"

$python = ".\.venv\Scripts\python.exe"
& $python -m threatweave.cli --db runtime/tenant-lab.db tenable-export asset
& $python -m threatweave.cli --db runtime/tenant-lab.db tenable-export vulnerability
& $python -m threatweave.cli --db runtime/tenant-lab.db tenable-export compliance
& $python -m threatweave.cli --db runtime/tenant-lab.db correlate
& $python -m threatweave.cli --db runtime/tenant-lab.db receipt --policy policies/business-context.yaml --out runtime/receipts/tenant-lab.json

Remove-Item Env:TENABLE_ACCESS_KEY,Env:TENABLE_SECRET_KEY -ErrorAction SilentlyContinue
~~~

**Scope exports deliberately:** without API filters, commands can export all accessible records under Tenable's default scope. Use `--body-file` to provide documented filters. These operations **read evidence**; they do not trigger scans, patch assets, or change Tenable severity/VPR.

You can also import locally authorized CSV, JSON, JSONL and Nessus data:

~~~bash
threatweave --db runtime/local.db import asset assets.json
threatweave --db runtime/local.db import vulnerability vulnerabilities.jsonl
threatweave --db runtime/local.db import compliance compliance.csv
threatweave --db runtime/local.db import nessus scan.nessus
threatweave --db runtime/local.db correlate
~~~

ServiceNow-style CMDB context is handled by **human-approved mapping proposals**, not live ServiceNow synchronization. See [connector documentation](docs/CONNECTORS.md).

### 5. Run tests

~~~bash
python -m pytest -q
python scripts/ship_check.py --repeat 3
python scripts/bench.py --assets 50000
~~~

On Windows, use `.\.venv\Scripts\python.exe` instead of `python` when the environment is not activated. These checks run on **synthetic evidence**; benchmark results do not certify production throughput.

### 6. Optional Claude and MCP

~~~bash
python -m pip install -e '.[agent,mcp]'
python -m threatweave.mcp_server
~~~

Set `THREATWEAVE_DB` and `THREATWEAVE_POLICY` for the MCP client's local environment. Its tools provide read-only security overview, Fix Groups, asset evidence, dry-run policy evaluation and receipt comparison. Claude integration requires an independently configured `ANTHROPIC_API_KEY`; policies are not activated without human approval. See [agent guidance](AGENTS.md).


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

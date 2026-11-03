# ThreatWeave AI

**Correlate vulnerabilities with relevant CIS misconfigurations, apply your organization's own security priorities, and prove why the remediation order changed.**

Security teams already have vulnerability severity, VPR, compliance findings, and often business context in a CMDB. The difficult question is not simply *what is vulnerable?* It is **which exposures deserve attention first, what evidence connects them, and can we reproduce the decision when policy or context changes?** ThreatWeave AI is a defensive, read-only investigation agent that turns those inputs into explainable, evidence-linked decisions.

![ThreatWeave AI architecture: source ingestion, validated asset and CIS correlation, policy evaluation, decision receipts, agent and MCP interfaces](docs/architecture-diagram.svg)

> **CyberAgents Exchange category:** Agent, with internal MCP tools and a deterministic evidence engine.  
> **Current status:** v0.1 offline functional prototype. The Tenable asynchronous export connector is implemented and mock-tested, **not validated against the competition tenant**. The compliance correlation rules and demo records are **synthetic**. Claude, MCP, Streamlit and DuckDB require optional dependencies and separate runtime validation.

## The agent

The ThreatWeave investigator follows a bounded, evidence-first loop:

1. **Gather, read-only.** Import authorized Tenable assets and vulnerability exports through the asynchronous API or CSV/JSON/JSONL files. Optional CIS audit results and ServiceNow CMDB *exports* add configuration and business context.
2. **Resolve the asset, not the subnet.** Use the Tenable asset UUID as the local asset key. Enrich with a CMDB configuration item only when the import supplies an explicit, verified UUID-to-CI mapping; never merge on hostname or IP alone.
3. **Correlate relevant weaknesses.** ExposureWeave checks whether a vulnerability and a *relevant* failed CIS control appear on the same asset under an approved correlation rule. Mere co-occurrence does not prove a compounded exposure or attack path.
4. **Group candidate fixes.** Group findings by normalized Tenable solution text plus software family (or plugin ID when needed). Preserve every source finding ID and affected asset. These are **candidate remediation families**, not verified single-patch bundles.
5. **Apply organizational policy.** ContextIQ validates restricted YAML rules, retains the original Tenable severity and VPR, and generates separate contextual priority bands. Missing context does not mean low risk.
6. **Create and replay Decision Receipts.** DecisionTrace fingerprints the dataset and policy and records rankings, triggered rules, contributing evidence and evidence-quality flags. Compare receipts to identify changed priorities and distinguish policy-only from data/context changes.
7. **Investigate, then let a human decide.** The standalone guided agent works offline. Optional Claude can retrieve small evidence packages, explain changes or draft a **proposed** policy rule; it cannot silently activate the rule, modify Tenable, start scans, patch servers or open tickets.

### What the agent produces

| Output | What it contains |
| --- | --- |
| **Compounded-exposure candidates** | Vetted same-asset vulnerability ↔ failed-CIS relationships, evidence IDs, missing prerequisites |
| **Ranked Fix Groups** | Organizational priority, affected asset counts, original source severity, candidate fixes and relevant flags |
| **Decision Receipt** | Stable input and policy fingerprints, per-group ranking, triggered rules and source references |
| **Decision Replay** | Before/after movement, rule contributions and whether the change came from policy, data or both |
| **Read-only investigation** | A focused explanation of what is supported, what remains uncertain and what to review next |

## Install and try it

**Requirements:** Python 3.11+ and pip. The deterministic demo needs no Tenable credentials or Claude API key.

```bash
git clone https://github.com/sreedhar51/threatweave-ai.git
cd threatweave-ai
python -m pip install -e .

# Load a fully synthetic estate, correlate findings, and write two receipts
threatweave --db runtime/demo.db demo

# Run the read-only guided agent
threatweave --db runtime/demo.db investigate

# Show the before-and-after organizational policy decision
threatweave compare runtime/receipts/demo-before.json runtime/receipts/demo-after.json
```

The comparison illustrates a policy-driven priority change while keeping the underlying dataset the same. All demo hostnames, CI records, plugin outputs, and CIS-like identifiers are synthetic—not real customer evidence or licensed CIS benchmark content.

### Visual dashboard

```bash
python -m pip install -e '.[ui]'
streamlit run dashboard/app.py
```

The demo dashboard contains **Fix Groups & Assets**, **Policy & Investigation**, and **Decision Replay**. Select **Load synthetic demo** for an offline walkthrough. An HTML example is also available at [examples/demo-report.html](examples/demo-report.html).

### Internal read-only MCP tools

```bash
python -m pip install -e '.[mcp]'
export THREATWEAVE_DB=runtime/demo.db
export THREATWEAVE_POLICY=policies/business-context.yaml
python -m threatweave.mcp_server
```

Available tools: `get_security_overview`, `list_fix_groups`, `get_asset_exposure`, `get_group_evidence`, `evaluate_policy_dry_run`, and `compare_decision_receipts`. This is a **local stdio MCP server**; validate interoperability with your specific client and installed MCP SDK version before deploying it. It exposes no Tenable write operations.

### Optional Claude interpretation

```bash
python -m pip install -e '.[agent]'
export ANTHROPIC_API_KEY='your-key-from-a-secure-environment'
```

Claude is optional and used for bounded evidence interpretation and draft policy authoring. The deterministic engine—not the language model—decides group priorities. Do not use real organizational exports with a third-party model without authorization.

## Bring your own authorized evidence

The same DataBridge imports structured exports without API access:

```bash
threatweave --db runtime/tenant.db import asset ./assets.json
threatweave --db runtime/tenant.db import vulnerability ./vulns.jsonl
threatweave --db runtime/tenant.db import compliance ./cis-compliance.csv
threatweave --db runtime/tenant.db import cmdb ./servicenow-export.csv --provider servicenow-export
threatweave --db runtime/tenant.db correlate
threatweave --db runtime/tenant.db receipt --policy policies/business-context.yaml --out runtime/receipts/tenant.json
```

**CMDB caveat:** Importing ServiceNow *export files* is supported; a live ServiceNow Table API connector is **not yet implemented**. To affect priority, a CMDB row must explicitly map to a known Tenable UUID and declare the mapping verified. See [the connector contract](docs/CONNECTORS.md).

For a live, authorized Tenable VM tenant, credentials belong in environment variables—not the repository:

```bash
export TENABLE_ACCESS_KEY='your-access-key'
export TENABLE_SECRET_KEY='your-secret-key'
threatweave --db runtime/tenant.db tenable-export asset
threatweave --db runtime/tenant.db tenable-export vulnerability --body-file ./local-vuln-filters.json
# Only where the tenant makes compliance export available:
threatweave --db runtime/tenant.db tenable-export compliance
```

Tenable exports use asynchronous jobs and chunks. Carefully choose supported export filters and authorized data scope; an omitted vulnerability filter may cause an unintended default time window. The live connector still requires tenant-specific verification.

## Why ThreatWeave is different

**It is a security decision-assurance layer—not another vulnerability scanner, attack-path engine or remediation executor.** Its distinct contribution is the combination of *relevant same-asset vulnerability/CIS correlation*, *verifiable business context*, *policy-driven priority changes* and *reproducible Decision Replay*.

The original scanner severity and VPR are never overwritten. A receipt's cryptographic hash helps detect changed inputs; it does **not** independently attest the truth of the scanner's findings. Fix Group cardinality is not a validated blast-radius estimate. Cross-host attack paths remain **unverified** without independent reachability and identity evidence.

## What's in this repository

| Path | Purpose |
| --- | --- |
| [`src/threatweave/`](src/threatweave/) | CLI, Tenable connector, normalization, correlation, policy, decision receipts and guided agent |
| [`src/threatweave/mcp_server.py`](src/threatweave/mcp_server.py) | Read-only MCP tool interface |
| [`dashboard/app.py`](dashboard/app.py) | Three-tab Streamlit demonstration |
| [`policies/`](policies/) | Sample organizational and correlation policies |
| [`examples/`](examples/) | Synthetic fixtures and portable demo report |
| [`tests/`](tests/) | Regression and evidence-boundary tests |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | Detailed system design and scope boundaries |
| [`docs/CONNECTORS.md`](docs/CONNECTORS.md) | Input and field-mapping contract |
| [`docs/architecture-diagram.svg`](docs/architecture-diagram.svg) | Editable vector architecture diagram |
| [`exchange/agent-listing.DRAFT.md`](exchange/agent-listing.DRAFT.md) | Draft submission description; not an Exchange listing yet |

## Test and extend

```bash
python -m pip install -e '.[dev]'
pytest -q
```

The local packaging regression suite previously passed **18 tests**; verify the current checkout and GitHub Actions independently. The portable store is SQLite, with an optional DuckDB/Parquet reporting extra (`pip install -e '.[analytics]'`). **No 250,000-asset throughput guarantee is claimed.**

### Roadmap

Planned extensions include validated Tenable Solutions grouping, ServiceNow Table API and additional enterprise data adapters, broader versioned CIS correlation mappings, benchmark-drift intelligence, an OPA policy runtime, optional OSCAL interoperability, and evidence-qualified topology/attack-path prerequisites. None of these future connectors or features should be mistaken for deployed v0.1 functionality.

## Limitations and safety

The current CIS mappings and correlation examples are synthetic and **not production-approved controls**. They establish only candidate compounded exposures on a verified asset, not proven exploit chains or lateral movement. CMDB records can be incomplete or stale; an unverified mapping is excluded from priority enrichment. The agent never automatically changes policies, accepts risk, recasts findings, modifies endpoint settings, or initiates scans. Do not commit secrets, proprietary CIS audit files or real organizational security exports. See [security notes](docs/SECURITY.md) and [implementation limitations](docs/ARCHITECTURE.md).

## License and references

**MIT License** — see [LICENSE](LICENSE).

Developed for a proposed Tenable CyberAgents Exchange **Agent** submission. Exchange publication, any competition entry and compliance with eligibility rules are separate steps; hosting this repository on GitHub alone is not an Exchange submission.

- [Tenable integration guidance](https://developer.tenable.com/docs/vm-and-was-integrations)
- [Tenable vulnerability export API](https://developer.tenable.com/reference/exports-vulns-request-export)
- [Tenable assets v2 export API](https://developer.tenable.com/reference/export-assets-v2)
- [CyberAgents Exchange contribution instructions](https://github.com/tenable/cyberagents-exchange/blob/main/CONTRIBUTING.md)
- [MCP Python SDK](https://py.sdk.modelcontextprotocol.io/)

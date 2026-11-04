# ThreatWeave AI

[![Tests](https://github.com/sreedhar51/threatweave-ai/actions/workflows/tests.yml/badge.svg)](https://github.com/sreedhar51/threatweave-ai/actions/workflows/tests.yml)
![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue)
![License: MIT](https://img.shields.io/badge/license-MIT-green)

**Which fix should we investigate first, why did that answer change, and can we prove it?**

A vulnerability scanner tells you what is wrong on each host. A CIS audit tells you
which controls failed. The CMDB tells you which hosts matter to the business. Analysts
still stitch those three together by hand, then struggle to explain why yesterday's
top priority is not today's. ThreatWeave is a read-only Claude agent that does the
stitching, ranks candidate fix groups with a deterministic policy engine, and writes a
**Decision Receipt** for every run, so any priority can be traced back to the exact
findings and policy rules that produced it.

![ThreatWeave architecture](docs/architecture-diagram.svg)

## How it works

1. **Gather (read-only).** Import Tenable VM exports, `.nessus` files, Security Center
   analysis results, CIS compliance results, and ServiceNow CMDB exports. Every record
   keeps its source hash. Vendor severity and VPR are stored unchanged.
2. **Correlate.** Pair a vulnerability with a failed CIS check only when both sit on
   the **same Tenable asset UUID** and a vetted `software_family` to `control_id` rule
   links them. A CIS failure next to an unrelated finding is not treated as extra risk.
3. **Add business context.** A CMDB row affects priority only after a human approves
   its mapping to a Tenable asset UUID. A matching hostname or IP is not enough.
4. **Decide.** A restricted, schema-checked YAML policy turns evidence into a ranked
   list of candidate fix groups. This step is fully deterministic: Claude never scores
   or ranks anything.
5. **Explain.** Claude, through the read-only MCP tools, investigates the top groups,
   cites finding IDs, and can draft new policy rules that stay unapproved until a
   human reviews them.
6. **Prove.** Each run produces a Decision Receipt fingerprinting the dataset, the
   policy, and the ranking. Decision Replay compares two receipts and attributes every
   rank change to a policy change, a data change, or both.

## What you get

| Output | What it contains |
|---|---|
| **Ranked candidate fix groups** | Rank, contextual priority, matched rule IDs with their score contributions, affected assets, and cited finding IDs |
| **Decision Receipt** | Dataset fingerprint, policy fingerprint, and the full ranking. The same inputs always produce the same receipt ID |
| **Decision Replay** | Which groups moved, by how much, and whether the cause was policy, data, or both |
| **Investigation brief** | Recommended next human review steps for the top groups, from the offline guided agent or from Claude |
| **OWASP audit** | 20 OWASP LLM and Agentic AI controls, each reported as `TESTED`, `DESIGN`, or `FAIL` |

### Example: the same policy, three evidence stages

`threatweave demo --staged` replays one synthetic payment web server through three
stages under an unchanged policy:

| Stage | "Upgrade OpenSSH package" | Rules that fired | Why |
|---|---|---|---|
| 1. Vulnerabilities only | rank 3, score 55.53 (high) | none | Baseline scanner evidence |
| 2. Plus CIS results | rank 2, score 69.53 (high) | `TW-COMPOUND` | A vetted SSH control failed on the same asset |
| 3. Plus verified CMDB | rank 1, score 93.53 (urgent) | `TW-COMPOUND`, `TW-PAYMENTS` | The asset is a verified payments system |

Each stage writes its own receipt, and the replay shows the source fingerprint
changing (`compliance`, `correlations`, then `cmdb`) while the policy fingerprint stays
fixed. All demo hosts, identifiers, and CIS controls are synthetic.

## Quick start

Requires Python 3.11 or newer. No API keys are needed for the offline demo.

```bash
git clone https://github.com/sreedhar51/threatweave-ai.git
cd threatweave-ai
python -m pip install -e '.[dev]'

threatweave --db runtime/demo.db demo            # load synthetic data, rank, write receipts
threatweave --db runtime/demo.db investigate     # offline guided investigation
threatweave compare runtime/receipts/demo-before.json runtime/receipts/demo-after.json
threatweave --db runtime/demo.db check-owasp     # OWASP LLM and Agentic AI audit
```

Everything prints JSON. Receipts are written to `runtime/receipts/`.

## Use it with Claude

ThreatWeave runs as a Claude agent in three ways. All three use the same six read-only
tools; none of them can patch, scan, open tickets, or change anything in Tenable.

### Claude Code (agent + MCP server)

The repository ships `.mcp.json` (the MCP server) and `.claude/agents/threatweave.md`
(a subagent restricted to those tools).

```bash
python -m pip install -e '.[mcp]'
threatweave --db runtime/demo.db demo     # the MCP server reads this database
claude                                     # open this repository as the project
```

Then ask: *"Use the threatweave agent: which fix group should we investigate first,
and why did it move?"*

### Claude Desktop or any MCP client

```json
{
  "mcpServers": {
    "threatweave": {
      "command": "python",
      "args": ["-m", "threatweave.mcp_server"],
      "env": {
        "THREATWEAVE_DB": "/absolute/path/to/threatweave-ai/runtime/demo.db",
        "THREATWEAVE_POLICY": "/absolute/path/to/threatweave-ai/policies/business-context.yaml"
      }
    }
  }
}
```

| Tool | Purpose |
|---|---|
| `get_security_overview` | Imported assets, findings, compliance results, and context coverage |
| `list_fix_groups` | Ranked candidate fix groups with evidence references |
| `get_asset_exposure` | Same-asset vulnerabilities, CIS failures, and CMDB context for one asset |
| `get_group_evidence` | Bounded source evidence for one fix group |
| `evaluate_policy_dry_run` | Validate and preview a proposed policy without activating it |
| `compare_decision_receipts` | Replay two receipts from the configured receipts directory |

### Claude API (dashboard)

```bash
python -m pip install -e '.[ui,agent]'
export ANTHROPIC_API_KEY=...        # never commit this
streamlit run dashboard/app.py
```

The dashboard has three tabs: **Fix Groups & Assets**, **Policy & Investigation**, and
**Decision Replay**. With a key set, Claude can investigate bounded evidence through a
capped tool-use loop and turn plain-English requests into draft policy rules. Every
draft is schema-checked and returned with `approved: false`.

## Configuration

Copy `.env.example` to `.env` (git-ignored) or export the variables. Every variable is
optional.

| Variable | Used for | Default |
|---|---|---|
| `ANTHROPIC_API_KEY` | Claude investigation and rule drafting | none (Claude features off) |
| `THREATWEAVE_CLAUDE_MODEL` | Claude model ID | `claude-sonnet-4-5` |
| `TENABLE_ACCESS_KEY`, `TENABLE_SECRET_KEY` | Read-only Tenable VM exports | none |
| `TENABLE_BASE_URL` | Tenable VM API base URL | `https://cloud.tenable.com` |
| `SC_ACCESS_KEY`, `SC_SECRET_KEY` | Read-only Security Center analysis | none |
| `THREATWEAVE_DB` | SQLite evidence store (MCP server) | `runtime/threatweave.db` |
| `THREATWEAVE_POLICY` | Active policy file (MCP server) | `policies/business-context.yaml` |
| `THREATWEAVE_RECEIPTS` | Directory receipt comparisons may read | `runtime/receipts` |

## Connect real, authorized data

```bash
# Files you already exported
threatweave --db runtime/tenant.db import asset assets.json
threatweave --db runtime/tenant.db import vulnerability vulns.jsonl
threatweave --db runtime/tenant.db import compliance compliance.csv
threatweave --db runtime/tenant.db import nessus scan.nessus
threatweave --db runtime/tenant.db cmdb-propose servicenow.csv --out mappings.csv
# Review mappings.csv and set mapping_verified=yes only on rows you have confirmed
threatweave --db runtime/tenant.db import cmdb mappings.csv --provider servicenow-export

# Or pull directly from Tenable VM (asynchronous export jobs, read-only)
threatweave --db runtime/tenant.db tenable-export asset
threatweave --db runtime/tenant.db tenable-export vulnerability --body-file vuln-filters.json

# Correlate, rank, and write a receipt
threatweave --db runtime/tenant.db correlate
threatweave --db runtime/tenant.db receipt --policy policies/business-context.yaml --out runtime/receipts/tenant.json
```

Supply a deliberate export filter: without one, Tenable may apply a default time
window. Before a live run, `python scripts/tenant_preflight.py` checks read access and
coverage without printing hostnames, IPs, plugin output, or credentials. See
[Connectors](docs/CONNECTORS.md), [Tenant preflight](docs/TENANT_PREFLIGHT.md), and
[On-prem Security Center](docs/ON_PREM.md).

## Security model

- **Read-only by construction.** No tool writes to Tenable, Security Center, ServiceNow,
  or any other system. There are no patch, scan, ticket, or remediation tools.
- **Claude explains; the engine decides.** Scores come only from the deterministic
  policy engine. Claude-drafted rules are proposals with `approved: false`.
- **Untrusted evidence.** Scanner and CMDB strings are wrapped as non-executable data,
  checked for prompt-injection patterns, and scrubbed of credentials before any model
  sees them.
- **Bounded agent.** At most 5 tool-use turns and 5 tools per turn. Tool results are
  capped at 16,000 characters and return a valid `TRUNCATED` marker instead of partial
  evidence.
- **Conservative claims.** No cross-host attack paths, no unknown-as-safe, no identity
  joins on IP addresses.

Details: [OWASP controls](docs/OWASP_AGENT_BEST_PRACTICES.md),
[Architecture and trust boundaries](docs/ARCHITECTURE.md), [Security policy](docs/SECURITY.md).

### Outbound network calls

ThreatWeave makes no network calls unless you configure one of these:

| Destination | When | What is sent |
|---|---|---|
| `cloud.tenable.com` (or `TENABLE_BASE_URL`) | `tenable-export`, `tenant_preflight.py` | Read-only export and status requests |
| Your Security Center URL | `securitycenter-export` | Read-only analysis queries |
| `api.anthropic.com` | Claude features in the dashboard, with `ANTHROPIC_API_KEY` set | Your question plus bounded, scrubbed tool results |

The offline demo, the guided `investigate` command, the MCP server, and `check-owasp`
send nothing off the machine. (An MCP client such as Claude Code sends tool results to
its own model provider.)

## Verify it yourself

```bash
python -m pytest -q                          # unit, safety, and regression tests
python scripts/ship_check.py --repeat 3      # three clean runs must produce identical receipts
threatweave --db runtime/demo.db check-owasp # exits 1 if any TESTED control fails
```

`ship_check` builds three independent databases, runs the full three-stage workflow in
each, and fails with a nonzero exit code if any ranking, receipt ID, or source
fingerprint differs. CI runs all three on Python 3.11 and 3.12. See the
[SWARM readiness gate](docs/SWARM_READINESS.md).

## Repository layout

| Path | Responsibility |
|---|---|
| `src/threatweave/ingest.py`, `nessus.py` | CSV, JSON, JSONL, and `.nessus` normalization; identity and CMDB mapping checks |
| `src/threatweave/tenable.py`, `securitycenter.py` | Read-only Tenable VM export and Security Center connectors |
| `src/threatweave/correlate.py` | Vetted same-asset vulnerability-to-CIS correlation |
| `src/threatweave/policy.py` | Restricted, schema-checked policy evaluator |
| `src/threatweave/engine.py` | Fix groups, Decision Receipts, and Decision Replay |
| `src/threatweave/agent.py` | Claude tool-use loop, rule drafting, and the offline guided agent |
| `src/threatweave/mcp_server.py` | Read-only MCP tool surface |
| `src/threatweave/owasp_guardrails.py` | Secret scrubbing, prompt sanitizing, tool allowlist, OWASP audit |
| `.claude/agents/threatweave.md`, `.mcp.json` | Claude Code subagent and MCP registration |
| `dashboard/app.py` | Streamlit dashboard |
| `policies/` | Sample policies and vetted correlation rules |
| `examples/` | Synthetic inputs, sample receipts, and an HTML demo report |

## Limitations

- **Candidates, not validated fixes.** Fix groups come from normalized plugin solutions
  and software families. Confirm applicability before scheduling work.
- **Live tenant not yet validated.** The Tenable VM and Security Center connectors are
  tested against mocked API responses only. Run the preflight against your tenant.
- **Claude clients not yet smoke-tested.** The MCP server is verified end to end with
  MCP Python SDK 2.3.0 over stdio. The Claude Code subagent and Claude Desktop setup
  above have not yet been exercised in those clients.
- **Synthetic correlation rules.** The sample `software_family` to `control_id` rules
  illustrate the method and are not production-approved mappings.
- **No measured time savings.** No hours-saved or risk-reduced figure is claimed until
  it is measured on a real analyst workflow.
- **Scale.** The SQLite store is built for portability. An optional DuckDB and Parquet
  path exists (`pip install -e '.[analytics]'`), but there is no throughput guarantee.

## License

MIT. See [LICENSE](LICENSE). Use only data you are authorized to access, and never
commit tenant exports, credentials, or licensed CIS benchmark content.

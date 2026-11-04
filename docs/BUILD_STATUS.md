# ThreatWeave AI — build and verification status

**Updated:** 2026-11-04  
**Primary source:** `main` at `c6298d023eecfd85251131dd746d2150670b5deb`  
**Purpose:** current implementation status and remaining verification gates. Earlier milestone counts and pre-merge notes are superseded; Git history and past PRs retain their details.

## Current release snapshot

| Area | Status | Verified scope / limitations |
| --- | --- | --- |
| Evidence ingestion (DataBridge) | **Implemented** | Authorized files: CSV, JSON, JSONL/NDJSON, Nessus; read-only Tenable VM asynchronous exports. Live VM ingest has been reported from an authorized Windows Partner Lab; current tenant behavior must be checked separately. |
| On-prem Security Center | **Implemented adapter; mock-tested** | Read-only analysis with pagination and bounded retries; live Security Center API semantics and permissions remain tenant-dependent and unverified here. |
| CIS and exposure correlation | **Implemented** | Requires relevant vetted software-family/control relationship and the same verified asset identity; correlation is *not* a validated attack path. |
| CMDB context | **Implemented via reviewed import** | CSV/JSON ServiceNow-style exports with human-approved mapping to Tenable asset UUIDs. **No live ServiceNow Table API synchronization.** |
| ContextIQ policy engine | **Implemented** | Deterministic policy priorities preserve original Tenable severity and VPR. Rules and context need human review. |
| Fix Groups | **Implemented as candidates** | Grouping identifies potential remediation work; it does not certify a single patch, fix applicability or reduced risk. |
| Decision Receipts and Replay | **Implemented** | Evidence/policy fingerprints, source references, reproducible priority results, and before/after differences. |
| Streamlit dashboard | **Implemented; automated checks passed** | Isolated tenant/synthetic/staged modes, evidence coverage, policy review, group investigation and replay. Manual browser/demo validation on the presentation machine remains a separate step. |
| Guided/Claude agent and MCP | **Implemented; optional** | Bounded read-only evidence tools and human-gated policy drafts. Claude requires separately configured credentials; validate actual Claude/MCP client interoperability before demonstrating it. |
| OWASP-aligned safeguards | **Implemented with regression coverage** | Untrusted evidence boundaries, redaction, bounded tools/outputs and policy draft validation; no claim of formal OWASP certification or a comprehensive external audit. |
| Exchange listing | **Prepared in contributor fork** | `sreedhar51/cyberagents-exchange` branch `add-threatweave-ai`, file `agents/threatweave-ai.md`. Preparation is **not** Tenable approval or public Exchange listing. |

## Automated verification — latest confirmed main

- GitHub Actions for `c6298d023eecfd85251131dd746d2150670b5deb`: **113 tests passed** on Python **3.11 and 3.12** in the `Offline regression tests` workflow.
- CI also completed the deterministic **three-run repeatability/evidence provenance** gate and the synthetic CLI demo smoke test successfully for both Python versions.
- GitHub Actions CodeQL checks were reported successful for this `main` revision. **CodeQL is not a Git-history credential scan.**
- Reference workflows: [offline tests](https://github.com/sreedhar51/threatweave-ai/actions/runs/41781215303) and [main workflow runs](https://github.com/sreedhar51/threatweave-ai/actions).
- CI checks are repository-level automated evidence, not a guarantee of successful authenticated operation in a particular vendor tenant or a measured production throughput.

## Authorized partner-lab evidence — operator reported

The Windows operator previously reported read-only Tenable VM ingestion of **1,394 assets, 18,974 vulnerabilities and 4,483 compliance findings** without ingestion rejections, followed by **2,863 candidate same-asset correlations** and a **5,909-group Decision Receipt**. The operator also reported successful repeatability on that dataset.

These figures are **operator-reported**, not independently re-tested by this GitHub documentation update. They are not production performance, attack-path, or remediation-outcome measurements. Avoid publishing real tenant identifiers, screenshots, exports or credentials. See [tenant preflight](TENANT_PREFLIGHT.md).

## Security findings review — open gate

The contributor's local Gitleaks history scan reported **5 `generic-api-key` matches across 51 reachable commits**, returning **exit code 1**:

- **2** matches in historical OWASP documentation rows concerning credential scrubbing.
- **3** matches in historical synthetic secret-scrubber test cases.
- Current assessment: **likely documentation/synthetic false positives**, not confirmed real credentials. The full five-row inventory and evidence limits are in [Gitleaks findings review](GITLEAKS_FINDINGS_REVIEW.md).
- **Do not label the repository secret-scan-clean yet.** Confirm the findings and obtain Tenable review guidance; any historical credentials separately disclosed outside Git still require rotation confirmation. No allowlist or history rewrite has been performed.

## GitHub integration / roadmap status

| Workstream | Status on 2026-11-04 |
| --- | --- |
| PR #1 — baseline evidence architecture | Merged |
| PR #3 — security/OWASP guardrails | Merged |
| PR #4 — UI evidence/performance | Merged |
| PR #6 — Claude-native agent, command-line, Claude Code support | **Merged** |
| PR #7 — architecture diagram and UI/guardrail refinements | Merged |
| PR #8 — Exchange listing draft rewrite | Merged |
| PR #9 — Claude decision briefs and correlation proposals | **Open; not in main** |

Do not describe the PR #9 proposal features as shipped on `main` until merged and verified. Branch-specific work and historical snapshots are not the release baseline.

## Known boundaries and pending checks

- **Safety/identity:** Do not merge assets by matching IP/hostname alone; only explicitly verified CMDB asset UUIDs affect priority. A Security Center record missing authoritative host UUID remains unresolved. Failed CIS checks require a relevant correlation rule; WARNING/ERROR do not imply FAIL.
- **Data truth:** Unknown/missing evidence must remain unknown. Preserve source severity/VPR. Group priority scores may tie; deterministic tie-breaks are not independently calibrated risk probabilities.
- **Read-only behavior:** No initiated scans, patches, tickets, security-control changes or vendor write-back. Security Center's read-only analysis may use an HTTP POST request, but it does not modify source findings.
- **Not yet externally proven:** Cross-host exploit paths, full remediation verification, 250K-asset production capacity, live ServiceNow API, full Security Center tenant validation, customer time-savings estimates, and comprehensive interactive Claude/MCP interoperability.
- **Before submission:** Finish the historical Gitleaks review, confirm eligibility and deadline/Discord process, validate the final Exchange listing/acceptance timestamp, and rehearse the end-to-end demo on the presentation machine. The Exchange PR is a separate submission to `tenable/cyberagents-exchange`, and Tenable approval is not implied.

## Reproduce the baseline locally

~~~powershell
python -m pip install -e ".[dev,ui]"
python -m pytest -q
python scripts/ship_check.py --repeat 3
python -m threatweave.cli --db runtime/demo-cli.db demo
python -m streamlit run dashboard/app.py
~~~

Optional connectors require their documented dependencies and configuration; use synthetic evidence for public demos. See [README](../README.md), [SWARM readiness](SWARM_READINESS.md), [architecture](ARCHITECTURE.md), and [submission checklist](SUBMISSION_CHECKLIST.md).

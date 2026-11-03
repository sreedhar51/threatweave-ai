# ThreatWeave AI — implementation and verification status

Updated: November 3, 2026. Work-in-progress review branch `review/steps-1-5-evidence-foundations` (not merged to main).

## Verified locally

- **31 automated tests passed**, including the original **18** unmodified tests and 13 new regression tests. Run: `PYTHONPATH=src pytest -q`.
- Three-stage demo with unchanged policy returns `evidence_changed: ["compliance", "correlations"]` when CIS evidence is added and `["cmdb"]` when verified CI mapping is added.
- 5,000-asset synthetic staged run completed in the previous review; no production throughput certification.
- Family classification covers common Tenable metadata when `software_family` is absent; conservative same-asset vulnerability/CIS links require an explicit mapping rule.
- CMDB proposal CSV performs FQDN/hostname unique-match suggestions, **never IP matching**, and leaves `mapping_verified` blank for human confirmation.
- Read-only `.nessus` streaming XML parser rejects `DOCTYPE` / `ENTITY`, handles two hosts sharing one IP as distinct identities, retains PASS/FAIL/WARNING/ERROR compliance outcomes, and skips severity-0 informational vulnerability plugins.
- Read-only Tenable Security Center analysis client tested with `httpx.MockTransport` for synchronous pagination, API-key header, normalized records and source-identity constraints.
- Asset-level policy view reuses existing ContextIQ evaluation and preserves the default `get_asset_exposure()` result when no policy is supplied.
- SQLite overview reports compliance status counts and separate WARNING/ERROR scan-hygiene counts.
- Streamlit code passes Python syntax compilation, but not an interactive browser test.

## Implemented but NOT verified live

- Tenable VM asynchronous export: mocked API test only, **no live SWARM tenant access**.
- Tenable Security Center: mocked API only, **requires an authorized on-prem tenant to validate exact response schema, permissions and pagination**. The endpoint is synchronous; export conservatively to avoid console load.
- ServiceNow CMDB: CSV/JSON export and human-approved ID mapping only. **No live ServiceNow Table API connector**.
- `.nessus` fixtures are synthetic, not licensed CIS audits or proprietary organizational data. Audit-content variations beyond tested Nessus-v2 fields require validation.
- Streamlit dashboard, Anthropic Claude and MCP SDK in a live user environment; optional dependencies may not be present.
- Real-world high-volume memory use, export performance, authenticated scans, actual remediation outcomes and cross-host network reachability.

## Known scoring limitation (intentionally unchanged)

A Fix Group's score is the maximum member finding score, **capped at 100**. At scale, groups can therefore tie. Current tie breakers retain deterministic ordering but do not imply distinct underlying risk. We intentionally preserved the existing scoring algorithm and policy DSL rather than creating a competing scoring system.

## Identity and safety invariants

- Only verified CMDB-to-Tenable UUID mappings affect contextual priorities.
- Never match or merge unrelated assets by IP address. If a Security Center finding has no `hostUUID`, it uses a per-finding opaque `sc-unresolved-*` identity. This intentionally **differs from an IP-based fallback** to uphold the non-merging guardrail.
- Preserve source severity and VPR. No Tenable/SC/ServiceNow writes; HTTP POST to SC `/rest/analysis` performs a read-only query.
- CIS FAIL + vulnerability must satisfy an explicit matching rule on the **same asset** before correlation; an attack path is never asserted based on scan data alone.
- Unknown audit file is retained as `unknown-audit-file` and should be treated as incomplete evidence, not an authoritative CIS benchmark assertion.

## Before Exchange submission

Confirm contest eligibility and deadline, validate authorized tenant export, run the complete tests on Python 3.11+, launch UI and MCP client, capture a demo video, review the submission listing against current Exchange requirements, and complete the contribution agreement as an authorized eligible participant. A public GitHub repository alone is not an Exchange submission.

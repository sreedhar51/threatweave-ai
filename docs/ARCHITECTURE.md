# ThreatWeave AI — final architecture / accepted scope

## Submission shape

One standalone **Agent** listing; MCP tools run in the same repository. The agent works offline in a deterministic guided investigation mode. Optional Claude integration provides evidence-bounded reasoning and natural-language draft rules. No remote mutation tools.

## Data flow

```text
Tenable VM async API (assets/vulnerabilities/optional compliance)
  + CSV/JSON/JSONL exports (Tenable, authorized CMDB, future connectors)
                  |
                  v
          DataBridge normalizer
                  |
                  v
     SQLite local evidence store ----> optional Parquet/DuckDB reporting
                  |
          +-------+--------+
          |                |
  Verified CMDB mapping   Same-asset CIS correlation with vetted control rules
          |                |
          +-------+--------+
                  |
          ContextIQ YAML evaluator
                  |
    Candidate fix groups + priority bands
                  |
      Decision Receipt + source hashes
                  |
     Receipt comparison + investigation
                  |
   MCP tools / optional Claude / Streamlit
```

The [correlation logic guide](CORRELATION_LOGIC.md) describes the rule predicates, ContextIQ flow, and Claude proposal boundary.

## Security/identity invariants

1. Tenable asset UUID is authoritative within the Tenable dataset.
2. Vulnerability instance key: asset UUID + plugin ID + port + protocol. Compliance instance key: asset UUID + compliance full ID + audit filename.
3. CMDB enrichment only applies to an existing asset when a verified explicit Tenable UUID is present. Ambiguous/unknown mappings stay unmatched.
4. Same-asset presence is necessary but **not sufficient** for compounded-exposure inference. A defined validated software-to-control correlation mapping is also required.
5. CIS FAIL is different from WARNING/ERROR/PASS; non-FAIL values do not generate correlations.
6. Neither source relationships nor CMDB business service links establish network reachability; **no attack path is asserted**.
7. Remediation groups cluster candidate fixes; one normalized solution string alone does not certify a single patch artifact resolves all associated findings.
8. The original risk data remains immutable in the source finding model. Organization-specific contextual priorities exist separately.
9. Policy DSL permits restricted scalar matching fields and bounded actions; no arbitrary code execution or remote writes.
10. Policy input changes are distinguishable from source-data changes because every receipt fingerprints both.

## Context policy behavior

Starting finding priority is a **demonstration-only** mapping of original vendor severity plus a small bounded VPR contribution. Rule actions may escalate priority or flag uncertainty. Deliberate no automatic down-weight for missing context, stale evidence, or the mere presence of endpoint security tools. A fix group's score is the maximum of member findings' contextual scores; tied groups are ordered deterministically by **compounded asset count**, then verified critical asset count, production asset count, total asset count, finding count, and stable `fix_group_id`. This changes tie order only, not the severity/VPR or scoring formula. Thus, a critical production asset is not ignored simply because a different group has more findings.

## Operational impact

The group view exposes distinct affected assets, server/workstation split, production count, and critical-asset count. Counts are not network blast-radius estimates. Suggested pilots and change windows remain human decisions.

## Known limitations of version 0.1

- Live Tenable API connectivity is not verified without authorized keys. Async protocol tested with mocked responses.
- Tenable export chunk parsing supports JSON array/object and JSONL, not all possible proprietary export formats.
- CSV parsing maps common column names; organization-specific exports may require an adapter.
- JSON array files are read into memory; prefer JSONL for large inputs.
- SQLite is the portable primary store; DuckDB/Parquet is optional. No proven 250k-asset benchmark.
- CMDB import is file-only. No ServiceNow Table API connector or CMDB service graph traversal yet.
- `software_family` can be supplied explicitly or inferred by ordered CPE, solution-text, plugin-name, and port heuristics. Inferred labels are hints and require validation; a match does not prove installed software.
- The CIS correlation mapping is a tiny synthetic demonstration set. It must not be presented as production-approved CIS mappings.
- Actual Tenable Solutions API entities are not ingested; only candidate grouping by plugin solution text / plugin ID exists.
- No audit-file parser, baseline migration, OPA execution, OSCAL mapping, or historical drift engine.
- No verified remediation outcome, supersedence analysis, GPO/Ansible generator, or remediation execution.
- No LLM-generated claims are accepted as authoritative evidence.
- Threat model covers basic untrusted evidence and restricted tool surface but is not an independently audited security product.

## Roadmap after competition

1. Tenant-specific Tenable VM schema validation, incremental sync, secure cursor/checkpoint; add real Tenable Solutions where accessible.
2. Asset context provider adapters for ServiceNow CMDB Table API, CrowdStrike, SentinelOne, Wiz; verified identity and provenance contracts.
3. Full supported CIS check mapping with versioned validated control relationships, false-Fail review, benchmark drift comparison; OSCAL import/export where authorized and semantically mapped.
4. OPA Rego runtime for advanced organizational policies with rule-set validation, constrained tenant policy data, and replay compatibility.
5. Topology and identity data providers for qualified attack-path prerequisites; never infer lateral movement from IP addresses.
6. Parquet and DuckDB production data pipeline with measured performance/quality gates.

## Dashboard Part B controls

- Asset lookup filters only on hostname and authoritative UUID; no IP joins.
- The policy editor compares rule IDs with the active policy. Explicit approval writes a versioned local YAML and a separate Decision Receipt; it does not activate a policy in any Tenable tenant.
- Replay can compare policies (same dataset) or saved receipts (possibly different datasets) and displays rule additions/removals and contribution deltas. A receipt does not itself establish applicability or remediation success.
- Ingestion audit rows track provider, record kind, counts and timestamps. Audit history is excluded from dataset fingerprints so identical evidence produces the same Decision Receipt.
- Streamlit caches rankings and coverage; changing external SQLite records without changing row counts may require a manual cache refresh.

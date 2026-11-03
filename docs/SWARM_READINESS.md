# ThreatWeave — SWARM shipping gate

Adapted from Tenable's November 2026 SWARM best-practices workshop slides supplied by the team. This is our **internal quality gate**, not a claim of Exchange Inspector vetting or official scoring.

## The five pre-ship checks

| Tenable principle | Concrete ThreatWeave evidence | Automatic acceptance | Still needs a human |
| --- | --- | --- | --- |
| Replaces recurring busywork | Consolidates per-asset vulnerability/CIS evidence, candidate fix groups and rule contributions | Demonstrable end-to-end synthetic workflow | Interview a practitioner and **measure** manual review minutes for the identical input |
| Ends in a decision | Returns ranked Fix Groups with rule IDs, affected assets, and cited findings | `run_ship_check()` asserts the ranking is populated and changes when evidence arrives | Reviewer chooses scope/owner and validates fix applicability |
| A check can run | Same-asset correlation, verified CMDB gate, receipt fingerprints, policy consistency and failure tests | `pytest -q` and `scripts/ship_check.py --repeat 3` | Live Tenable/SC schemas and benchmark control interpretation |
| Same input, same result | Complete receipts excluding timestamp match across three independent clean DB runs | Exact JSON comparison, including ranking and IDs | Environmental drift on real tenant must be separately recorded |
| Someone else can run it | MIT public source, README, example synthetic data, one-command check | CI invokes tests plus ship-check | New laptop smoke test and optional Claude/MCP client compatibility |

## Exchange evaluation dimensions (informal alignment)

- **Technical quality:** evidence-defined contracts, bounded agent tool loop, deterministic rule evaluation, automated negative controls.
- **Real-world impact:** clear problem (manual correlation and policy-based triage) and actionable ranked output. **No unmeasured hours-saved claim**.
- **Business value:** candidate remediation groups prioritized by business context; no asserted monetary impact until independently measured.
- **Mission fit:** safe, inspectable, open-source evidence correlation and explainable decision receipts.
- **Originality:** combines relevant vulnerability-to-CIS correlation, verified CMDB enrichment and policy-only/data-only decision replay. We do **not** claim invention of Tenable fix grouping or VPR.
- **Reliability:** repeated clean runs, explicit failures, no unknown-as-safe assumptions, preserved source severity and VPR.

## Exact acceptance commands

```bash
python -m pip install -e '.[dev]'
python -m pytest -q
python scripts/ship_check.py --repeat 3
python scripts/ship_check.py --repeat 3 --assets 5000
```

The 5,000-asset run is a **synthetic smoke benchmark**, not a promised production capacity. `ship_check` creates three new SQLite databases in a temporary directory, repeats the full three-stage workflow and deletes those databases afterward. It returns only safe aggregate results (synthetic priority changes, receipt IDs, timings) and exits nonzero on a violated invariant.

Expected essentials:

```json
{
  "verdict": "PASS",
  "repeatability": "identical_receipts_and_rankings",
  "runs_checked": 3,
  "decision": {
    "cis_delta": ["compliance", "correlations"],
    "cmdb_delta": ["cmdb"],
    "source_evidence": "synthetic",
    "cross_host_attack_paths": "unverified"
  }
}
```

`ship_check` checks actual receipt JSON content, not a language model's description. On failure it prints `"verdict": "FAIL"` to stderr and returns exit code 1.

## Three-minute replay demonstration

**0:00–0:35 — Recurring busywork:** show synthetic `pay-web-01` vulnerability evidence, initial Fix Group ranking, and original scanner severity/VPR. Explain that analysts otherwise stitch scanner, compliance and asset context together manually.

**0:35–1:15 — Evidence enrichment:** add vetted same-asset CIS FAIL evidence, then verified CMDB business context. Do not imply synthetic control rules are production-approved.

**1:15–2:25 — Deterministic result:** show OpenSSH group rising in the synthetic sample (rank 3 → 2 → 1), `TW-COMPOUND` and `TW-PAYMENTS`, and Decision Receipt fingerprints with source-specific deltas. Show OpenSSL ranking under payments context. *The business decision is to investigate the higher-priority candidate fix first, not to patch automatically.*

**2:25–3:00 — Safety and reuse:** run `ship_check`, note three independent repeatable decisions; show MIT README and optional MCP/Claude interfaces. Close with what is still **unverified**: attack paths, remediation results, real tenant compliance.

## Harness and context budget

- Agent = model + bounded tool calls + deterministic engine + policy/identity guardrails + source evidence. Use the model to explain and draft **proposals**, never to score risk or approve its own changes.
- `CLAUDE.md` intentionally carries only critical rules and pointers. Load connector docs and full evidence only when the task requires them; prefer compact tool responses.
- Oversized tool output yields a **valid JSON `TRUNCATED` marker** (not an incomplete evidence blob); the agent must narrow the query rather than infer missing content.
- Keep iterations capped: up to five Claude tool-use turns and five tools per turn in the existing agent, no arbitrary shell or vendor mutations.

## Why a gate may say NO

- No permitted/verified CMDB identity: cannot use business criticality to increase priority.
- No vetted family-to-CIS-control link: cannot claim compounded exposure from mere co-occurrence.
- Scanner `WARNING` or `ERROR`: scan hygiene, **not** equivalent to failed CIS check.
- Source data missing or stale: mark uncertainty, never silently treat missing evidence as safe.
- An unverified network/identity/reachability prerequisite: **no cross-host attack-path claim**.
- Repeatability mismatch or missing receipts: FAIL; show the mismatch rather than pass a demo.

## Evidence of impact

Record actual stopwatch time for a human analyst completing the **same task and same dataset** without ThreatWeave, then compare with a user completing it with ThreatWeave. Capture the number of assets, findings, policy version, review quality, and any manual correction. Until measured, use no numerical hours-saved, risk-reduced, or exploit-prevented claims.

## Release readiness is not competition acceptance

GitHub publication ≠ Exchange submission. An Exchange Inspector-vetted badge is earned by Exchange review and is **not** automatically granted by our tests or the MIT license. Confirm eligibility and deadline via official organizer instructions. Live tenant and UI/MCP interactive smoke checks remain separate acceptance steps.

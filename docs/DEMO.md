# Three-minute ThreatWeave competition demo

This is a **synthetic demonstration script**, not a claim that the SWARM tenant contains particular findings.

## Preparation

```bash
PYTHONPATH=src python -m threatweave.cli --db runtime/demo.db demo
PYTHONPATH=src python -m threatweave.cli --db runtime/demo.db investigate
PYTHONPATH=src python -m threatweave.cli compare runtime/receipts/demo-before.json runtime/receipts/demo-after.json
# Optional UI after installation:
streamlit run dashboard/app.py
```

## Storyboard

**0:00–0:35 — Evidence, not anecdotes.** Show imported assets, vulnerability findings and CIS observations, source hashes, distinct asset UUIDs. Explain that live Tenable VM exports use API jobs but demo data is synthetic.

**0:35–1:00 — The missing relationship.** On `demo-prod-042`, show a high-severity service vulnerability and a failed *relevant* CIS check. State that they are corroborated on the same asset but that actual reachability and attack paths remain unverified.

**1:00–1:30 — Add organizational context.** Display CMDB mapping for the same UUID: production, critical payment service. Show that the vendor severity and VPR remain unchanged.

**1:30–2:15 — Policy change and replay.** Before policy: candidate remote-service fix group at rank 2. After human-approved production-payment and compounded-evidence rules: it becomes rank 1. Inspect matched rule IDs and source finding IDs. No LLM changes risk scores.

**2:15–2:40 — Agent investigator.** Run standalone guided investigation; show bounded evidence package and missing prerequisites. If Claude credentials work, demonstrate drafting a rule with an explicit human approval step.

**2:40–3:00 — Why it matters.** The same deterministic policy/receipt contract will accept authorized compliance and CMDB exports across platforms. No forced dependence on CIS or CMDB data in the competition tenant.

## Judge questions and defensible answers

- **Isn't Tenable already doing VPR, ACR and Solutions?** Yes. ThreatWeave consumes vendor findings and adds organizational policy, conservative cross-domain evidence, and reproducible *decision-change attribution*.
- **Why can't you assert attack paths?** Same-asset correlations don't establish network reachability or identity permissions.
- **How do you avoid hallucinations?** Deterministic processing computes identities, correlations, priorities, receipts; Claude receives bounded evidence only and proposes reviewable drafts.
- **What about data volume?** JSONL streaming ingestion and optional Parquet/DuckDB are provided; full 250k-asset throughput has not been benchmarked.
- **What if CIS isn't present?** Tenable vulnerability/asset workflow stands alone; CIS and CMDB are optional enrichment sources.
- **Why candidate Fix Groups?** Exact patch mappings aren't established from solution text alone; we retain the Tenable plugin solution and provenance.

## Pitch closing

> “Tenable identifies the security findings. ThreatWeave correlates the context, applies your organization's written policy, and gives you the receipt to prove why every remediation decision changed.”

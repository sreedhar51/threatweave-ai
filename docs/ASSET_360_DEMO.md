# Asset 360 — evidence fusion demo

## Purpose

**Start with the asset, not the finding.** ThreatWeave joins vulnerability findings, CIS compliance outcomes, rule-qualified vulnerability/CIS relationships and human-verified CMDB context under one **authoritative Tenable asset UUID**. Hostname is used for search and display only, and neither hostname nor IP address is ever used to merge two asset identities.

This is an **asset investigation view**, not a cross-host attack-path engine or a claim of proven exploitability. All demo records are fictional.

## Run the Streamlit demonstration

~~~powershell
python -m pip install -e ".[dev,ui]"
python -m streamlit run dashboard/app.py
~~~

1. In **DataBridge**, choose **Enterprise demo**, then **Load enterprise demo (five fictional assets)**. This uses a dedicated `runtime/enterprise-demo.db` database, not the tenant database.
2. Open **Asset 360 & Fix Groups**. The new **Asset 360** section appears *before* the existing Fix Group list.
3. Search by hostname or select a synthetic asset from the dropdown. The label includes the authoritative asset UUID so duplicate hostnames cannot silently merge.
4. Review the single-asset dossier: vulnerability count, failed CIS controls, matched same-asset correlations, verified CMDB mappings and per-finding ContextIQ scores.
5. Select the payment API or identity server to show how corroborating CIS evidence and verified business context affect a finding's priority, while Tenable source severity/VPR remain unchanged.
6. Scroll to the existing **Fix Groups** section to show the *cross-asset remediation-work queue*. The asset view and Fix Groups answer different questions: **what is happening to this host?** vs. **what work should we consider first?**
7. Switch to **Decision Replay** for before/after policy comparison. `policies/enterprise-context-demo.yaml` is available in the selector.

## Asset-owner prioritized remediation queue

After selecting the authoritative asset UUID, **Asset 360** now presents an
**Asset owner priority queue** above the raw evidence tables. It answers:

- Which candidate vulnerability fixes or failed CIS controls should this asset owner **investigate first**?
- Which active vulnerabilities have **explicitly rule-qualified, same-UUID** failed CIS controls, and what are the related control titles/rationales?
- How do preserved Tenable severity/VPR, verified CMDB context and named ContextIQ policy contributions explain the ordering?
- Who is the support group, **only when supplied through a verified CMDB mapping**?

The new read-only helper `asset_remediation_queue()` uses the **same finding
evaluator** and **same candidate group identity** as the global Fix Groups
engine. It processes **all active vulnerabilities and failed CIS checks for
that selected UUID**, then sorts by contextual group score; on ties it favors
groups with more distinct compounded vulnerabilities, then distinct related
failed CIS controls, then number of findings and stable ID. No number of
relationships is directly added to the risk score, and the result is **not**
a separate AI-calculated threat score. For an equally scored group, remaining
tie-breaks are ordering conventions, not validated differences in risk.

The UI displays up to 30 candidate work items and permits drilldown into one
item's exact policy contribution, sampled finding IDs, and related failed CIS
control evidence. If more groups exist, the table says how many are omitted.
A *candidate* group is not proof that one change fixes all its findings. No
work tickets, patches or vendor API writes are created.

**Evidence display fix:** The older UI fetched a combined first 200 rows
ordered by `kind`, which could return 200 compliance findings before **any**
vulnerabilities. Asset 360 now reserves a bounded evidence budget for **both**
types and reallocates unused capacity. For example, an asset with 379
vulnerabilities and 333 compliance findings will display 100 of each, rather
than an empty vulnerability table. **All** records remain counted and are
included in the asset-owner queue, regardless of the display limit.

**Relationship semantics:** 594 same-asset correlations means 594 matching
vulnerability/CIS *relationships*, **not** 594 independently validated attack
paths, distinct controls, or confirmed exploitable vulnerabilities. The queue
counts distinct related failed CIS controls per work group. In particular,
software-family heuristics (such as using port 445 to infer SMB) and broad
control-title matchers may require expert validation before operational use.

## Data and safety boundaries

- The **Asset 360 dossier** uses `src/threatweave/ui_workflows.py:asset_360()` and the existing `get_asset_exposure()` evaluator. It does not invent new correlations or risk scores.
- Correlation is only established by the repository's reviewed `policies/correlation-rules.yaml` relationships on the **same UUID**; mere co-location is not sufficient.
- `criticality`, `environment`, `role` and external exposure are shown only as stored attributes. Policy enrichment relies on approved CMDB identities; absent/unknown data remains unknown.
- The summary metrics count **all stored** vulnerability and CIS records for that UUID. Detailed rows are intentionally bounded to 200 per selection for UI responsiveness. When truncated, the page explicitly warns that not every individual finding is shown; this is not a complete export.
- A hostname collision displays a warning rather than merging evidence.
- The enterprise loader creates an isolated replacement database after complete synthetic import. It never writes into the tenant DB.
- No autonomous scan, patch, ticket, remediation or external data transfer occurs while using this offline demo.

## Validation

~~~powershell
python -m pytest -q tests/test_asset_360.py
python -m pytest -q
python scripts/contextual_policy_demo.py
python scripts/ship_check.py --repeat 3
~~~

Demo interpretation: A high-severity finding on a verified critical payment service may be prioritized ahead of a critical finding on a development system. This is an *illustrative, reviewable* organizational policy—not a revised scanner severity, a claim that the host is actually reachable, or an approved production SLA.

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

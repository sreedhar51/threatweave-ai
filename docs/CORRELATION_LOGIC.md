# Vulnerability and compliance correlation

ThreatWeave creates **candidate same-asset evidence relationships** with deterministic rules. ContextIQ can use those relationships when evaluating priority. Claude can explain evidence and propose new rules for human review; it does not create the existing deterministic links or set a score.

## Flow and responsibilities

1. **Normalize:** DataBridge imports vulnerabilities and compliance records using an authoritative Tenable asset ID. It retains source hashes, source severity and VPR, status, control identifiers, and a bounded source excerpt. Hostname and IP are not join keys.
2. **Classify:** An explicit `software_family` on a vulnerability takes precedence. Otherwise the ordered classifier in [`software.py`](../src/threatweave/software.py) uses configured CPE prefixes, solution text, plugin names, or ports; the first match in [`software-families.yaml`](../policies/software-families.yaml) wins. The family is a classification hint, not proof of an installed service. Review inferred families and broad heuristics before relying on a link.
3. **Correlate:** [`correlate()`](../src/threatweave/correlate.py) applies the local [`correlation-rules.yaml`](../policies/correlation-rules.yaml) to findings already stored in SQLite. It does not consult Claude. See the exact conditions below.
4. **Prioritize:** ContextIQ looks up linked vulnerability IDs, sets the `compounded_exposure` context for those findings, and evaluates the selected policy. For example, `TW-COMPOUND` in [`business-context.yaml`](../policies/business-context.yaml) adds 14 illustrative points when that condition matches. Other policies can behave differently. An actual link does not guarantee a priority increase: the selected policy must have a matching action.
5. **Explain and review:** Fix groups and Decision Receipts show candidate rankings, matched policy rules and evidence references. Asset 360 displays related finding IDs, correlation rule IDs and rationales. An analyst verifies the applicability of each relationship and decides what to do.

Correlation rules and ContextIQ policy rules are distinct. A `REL-*` rule identifies a candidate vulnerability-to-control relationship; a `TW-*` policy rule can use the correlation result when evaluating priority. Neither changes the vendor's original severity or VPR.

## Exact conditions for a link

For every configured rule, the current implementation joins stored findings on equal `asset_id` and requires all of:

- A vulnerability with status `OPEN`, `ACTIVE`, `REOPENED`, or `NEW`.
- A compliance finding with status `FAIL`, `FAILED`, or `NON_COMPLIANT`. `PASS`, `WARNING`, and `ERROR` are not failed controls.
- A case-insensitive match between the vulnerability's `software_family` and the rule's family.
- A rule selector match: exact `control_id` membership **or** a case-insensitive literal substring of the control title. If a rule supplies both selectors, either match is sufficient. `%` and `_` in title text are treated literally.

The correlation record contains the asset ID, vulnerability finding ID, compliance finding ID, rule ID, and rationale. Its ID is derived from the finding IDs and rule ID. Multiple rules or pairs can produce multiple relationship records; the count is **not** a count of attack paths or unique vulnerable assets.

The import contract requires an asset ID on findings and a control ID and audit file on compliance records. Check source identity and data quality; equality of stored IDs is only as reliable as the imported IDs. Missing status defaults during normalization to `OPEN` for vulnerabilities and `FAIL` for compliance, so investigate missing source status rather than treating that default as confirmed scan evidence.

### Example (fictional)

An `openssh` vulnerability in `OPEN` status and a failed SSH access control share asset ID `demo-pay-api`. A rule that maps `openssh` to that control ID, or to a matching control-title substring, creates a candidate link. A different asset ID, non-failed control, non-active vulnerability, unmatched family, or unmatched selector produces no link under that rule. A payments label on the asset is separate business context; it is not a prerequisite for this correlation.

Rules in the repository are examples, including title-based mappings. A matching title or inferred family does not prove semantic relevance, exploitability, network reachability, or causality. Security specialists must validate benchmark versions, control meaning, classification and local applicability before production reliance.

## Running and reviewing correlation

Use an authorized local demo or a copy of an imported database. `correlate` validates the rule definitions first, then **rebuilds the local correlations table**; it does not write back to Tenable. Existing local correlations are replaced, so preserve a backup if the earlier results are needed.

```bash
threatweave --db runtime/demo.db demo
threatweave --db runtime/demo.db correlate
threatweave --db runtime/demo.db receipt --policy policies/business-context.yaml --out runtime/receipts/correlated.json
```

In Streamlit, select the intended data source under DataBridge, then open **Asset 360 & Fix Groups** and select an asset by authoritative UUID. Review the correlated vulnerability and failed control, rule ID, rationale and source fields. Use **Decision Replay** to compare saved receipts or policies; check whether the comparison attributes changes to data, policy, both, or neither. The [Asset 360 walkthrough](ASSET_360_DEMO.md) describes the display and its limits.

## Claude's role

The optional `propose-correlations` feature first finds active vulnerabilities and failed controls on the same asset that are not already linked, groups candidate pairs, and gives Claude bounded samples. Claude returns `PROPOSE_LINK`, `NO_LINK`, or `NEEDS_REVIEW`. A proposed link must cite at least one sampled vulnerability and one sampled compliance finding; structured responses and references are validated. Samples flagged by the prompt-injection heuristic are skipped without a model call for that pairing. These checks do not prove the model's judgment is correct.

Proposals are **drafts only**: the feature does not edit the rule file, rerun correlation, or change a score. A qualified human may independently review the finding evidence, validate the relationship, add an approved rule to the local rules file and rerun correlation. Model-powered requests send bounded, scrubbed evidence to the configured provider; use authorized data only. A decision brief is another advisory feature and does not apply correlation rules.

## Limitations and traceability

- No cross-host topology, network reachability, exploitability, or confirmed remediation is established by a same-asset link.
- CMDB enrichment needs an explicitly verified asset mapping. Asset inventory fields and tags can also inform context, so verify their provenance separately; not all context is CMDB-verified.
- Ranking is deterministic for the same evidence and policy. A fix-group score uses the maximum member finding score; groups are candidate work scopes, not guarantees of a single patch.
- Source: [`correlate.py`](../src/threatweave/correlate.py), [`ingest.py`](../src/threatweave/ingest.py), [`engine.py`](../src/threatweave/engine.py), [`correlation_proposals.py`](../src/threatweave/correlation_proposals.py), and [`policy.py`](../src/threatweave/policy.py).

## Opt-in finding-specific AI assessment

Use the `assess-correlation` command for one selected active vulnerability and failed compliance finding on the same asset. The command requires an explicit per-request `--ai-correlation-analysis` flag, and sends bounded, scrubbed finding evidence to Claude. It is separate from correlation proposals and deterministic ranking. Select the IDs from Asset 360 or source evidence:

```bash
threatweave --db runtime/demo.db assess-correlation --vulnerability-id VULNERABILITY_FINDING_ID --compliance-id COMPLIANCE_FINDING_ID --ai-correlation-analysis
```

Alternatively, open **Policy & Investigation → Optional: AI finding-pair assessment (advisory only)**, opt in using the checkbox, enter both finding IDs and click **Assess finding pair with Claude**. The IDs are finding IDs, not plugin IDs or asset UUIDs. This feature requires the `agent` extra, configured `ANTHROPIC_API_KEY`, network connectivity and an accessible model supporting structured outputs.

The assessment returns related, conditional, unrelated or insufficient-evidence categories, citations, missing prerequisites, contradictions and validation steps. It validates that cited IDs were supplied, and a related assessment must cite both findings. It does not validate that each assertion is true or that citations support each claim; human review remains necessary. Injection-flagged or oversized evidence is not sent. This is a single-pair operation, not a batch or path analysis. It does not write a link, policy, score, or receipt and does not infer lateral movement. Missing normalized status may have been defaulted; the original evidence must be checked. No network topology or identity permissions are inferred.

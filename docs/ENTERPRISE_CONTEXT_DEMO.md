# Enterprise context policy demo — synthetic, review-first

This is a **fictional, independently runnable policy-comparison demonstration**, not an approved production risk methodology. It is intended for the Tenable SWARM presentation to explain why a verified critical payment or identity service can warrant review ahead of a critical-severity development asset while **preserving vendor severity and VPR**.

## Quick start

From the repository root (Python 3.11+):

~~~powershell
python -m pip install -e ".[dev,ui]"
python scripts/contextual_policy_demo.py
python scripts/contextual_policy_demo.py --output runtime/enterprise-policy-comparison.json
python -m pytest -q tests/test_enterprise_context_demo.py
~~~

The script uses an ephemeral SQLite database and the **same** five-asset synthetic dataset for two Decision Receipts. It changes **only** the policy:

- Baseline: `policies/default.yaml` (zero contextual rules).
- Advanced: `policies/enterprise-context-demo.yaml` (14 business-context and corroboration rules).

The JSON report includes before/after rank and score, preserved vendor severity/VPR, applied rule IDs, review flags, receipt comparisons, and clear limitations. It does not connect to Tenable or modify source data.

## Synthetic scenario

| Fictional asset | Starting scanner evidence | Reviewed business context | Expected *type* of decision difference |
| --- | --- | --- | --- |
| Development build library | Critical, high VPR; no related CIS evidence | Development; no validated critical CMDB mapping | Strong scanner signal retained, but no assumed production blast radius |
| Payment API | High-severity OpenSSH finding; corresponding failed SSH-access check | Explicitly verified production/critical/payment CMDB record; exposure label set to `confirmed` *in fiction* | Moves ahead through business impact, external exposure and same-asset CIS corroboration |
| Identity service | High-severity remote-admin finding; corresponding failed restriction check | Verified production/critical/identity server; **external exposure unknown** | Identity and CIS evidence matter; unknown exposure triggers review but cannot be treated as internet-facing |
| Recovery service | Medium vulnerability | Verified high-criticality production backup service | Recovery dependency is visible for human prioritization |
| Privileged admin workstation | Medium vulnerability | Verified high-criticality privileged workstation role | Highlights review of high-impact endpoints |

Fictional hostnames use `.demo.invalid` and plugin IDs are fabricated. Compliance controls are synthetic *examples*; no licensed CIS benchmark content is copied. In real operation, each family/control relationship must be technically vetted before reliance.

## Design: severity is not organizational priority

The application preserves the scanner's source severity and VPR. Its ContextIQ *priority* is a **separate illustrative 0–100 work-ordering score**, not a modified CVSS, EPSS, VPR, predicted breach probability, or financial loss estimate.

- **Tenable VPR**: threat-driven dynamic score; use as source threat signal, not a value to overwrite. The current product's VPR model changed in 2026, which is another reason to retain source values and dates.
- **FIRST CVSS v4.0**: has Base, Threat, Environmental and Supplemental metric groups. This demo **does not** recalculate CVSS Environmental score or claim a CVSS vector.
- **FIRST EPSS**: estimates the probability of observed exploitation of a disclosed CVE within 30 days; the demo does not ingest EPSS or claim an exploitation probability.
- **CISA KEV**: provides evidence of known exploitation. There is **no live KEV data feed or KEV-based scoring rule** in this demo. Do not treat an invented CVE or synthetic finding as KEV.
- **NIST SP 800-40 Rev. 4**: supports risk-informed enterprise patch prioritization and verification, not assigning arbitrary scores without organizational calibration.
- **Tenable ACR**: useful asset context where available, but this implementation uses explicitly reviewed CMDB criticality rather than claiming to import current ACR. Do not add invented ACR values.

### What the policy can actually evaluate

The restricted DSL recognizes exact-match conditions on: severity, vendor VPR **only as exact equality**, environment, business tag, asset type, role, criticality, internet-exposure status, same-asset correlated evidence, finding kind and status. It does **not** support range/threshold conditions such as `vpr >= 9`, `epss > 0.5`, `in_kev: true`, or dynamic temporal predicates. Do not put those keys into YAML: validation will reject them. The new policy deliberately avoids exact VPR equality rules because minor VPR changes would make the behavior brittle.

It uses additive `score_add`, policy minimums `priority_floor`, evidence flags, and `require_review` (flags for human review, **not** workflow enforcement). Policy score caps at 100. Thresholds, increments, and prioritization outcomes are **illustrative**, not organization-approved or calibrated, and can saturate for extremely contextual cases.

### Evidence safeguards

1. Vulnerability and CIS findings correlate **only on an authoritative same-asset UUID** and a deliberately mapped service/control relationship. A CIS failure is supporting context, **not proof of exploit reachability**.
2. CMDB context requires `mapping_verified: yes` associated with a known Tenable asset UUID. Hostname or IP similarity is not sufficient. Unverified mappings do not contribute to criticality or exposure.
3. `internet_exposure: confirmed` is an *explicit input* from a reviewed source, not a network test carried out by this application; it does not imply a validated exploit route. `unknown` leads to a human review flag, not an assumed internet-facing state.
4. Business tags in current ContextIQ can also originate from the source asset inventory; for production use, confirm the provenance of such tags and do not interpret all tags as human-verified CMDB statements.
5. Scores apply at the **finding level**; Fix Groups take the maximum finding score, rather than summing findings or multiplying across hosts. Tie-breakers are deterministic and the resulting groups are only candidate remediation scopes.
6. Source import freshness and any stale/unknown context require human review. No autonomous patches, vendor writes, tickets, or scanning.

## 3-minute demonstration storyline

1. **0:00–0:40** — Display five fictional assets. Ask whether the highest scanner severity always deserves first remediation.
2. **0:40–1:20** — Run baseline and show the critical development library near the top without a business-context adjustment.
3. **1:20–2:10** — Show advanced policy. Explain the payment API rise using named rule IDs, corroborating SSH-access failure, verified payment classification, and explicitly labeled external exposure; compare with identity service's unknown exposure flag.
4. **2:10–2:40** — Show same dataset hash, different policy hash, before/after receipt movement, and unchanged vendor severity/VPR.
5. **2:40–3:00** — Close on review boundaries: analyst validates evidence, chooses scope and approves the policy; no remediation is performed by the agent.

## Validation and calibration before production

- Calibrate weights with security, incident response, asset owners and compliance teams using a *labeled historical dataset* and remediation capacity. Test ranking precision, fairness, stability, score saturation and false-positive escalation.
- Confirm trust boundaries for `criticality`, `environment`, `role`, `business_tag` and `internet_exposure`; add field-level provenance and freshness checks if deploying to production.
- Add sourced CVE-to-KEV and EPSS enrichment **only through explicit ingestion contracts**, dates, data quality gates and tests. Consider vulnerability applicability, compensating controls, observed reachability and service dependencies. Do not claim any of them exist today.
- Keep the baseline policy, original three-stage demo, and real tenant DB unchanged. Present this as a candidate human-reviewed policy example only.

## Authoritative references

- Tenable: [Risk metrics and VPR](https://docs.tenable.com/vulnerability-management/Content/Explore/Findings/RiskMetrics.htm)
- Tenable: [VPR model v2 change](https://developer.tenable.com/changelog/vulnerability-priority-rating-transition-to-version-2)
- Tenable: [Policy and risk context configuration](https://docs.tenable.com/quick-reference/vulnerability-management-adoption-roadmap/Content/policy-risk-context-configuration.htm)
- FIRST: [CVSS v4.0 specification](https://www.first.org/cvss/v4.0/specification-document)
- FIRST: [EPSS overview](https://www.first.org/epss/)
- CISA: [KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- NIST: [SP 800-40 Rev. 4](https://csrc.nist.gov/pubs/sp/800/40/r4/final)

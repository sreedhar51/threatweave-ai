# Gitleaks full-history findings — triage record

**Recorded:** 2026-11-04  
**Repository:** [ThreatWeave AI](https://github.com/sreedhar51/threatweave-ai)  
**Source:** Contributor-provided local Gitleaks Git-history scan, `gitleaks git --log-opts="--all" --redact ...`  
**Reported scan coverage:** 51 commits reachable from the locally fetched refs  
**Original scan result:** exit code **1**, **5** `generic-api-key` findings  
**Status:** Likely synthetic/documentation-only false positives; **independent Exchange screening not yet passed**

This is a transparent record of the *five reported matches*, not a declaration that Gitleaks passed, a proof that every historical ref was scanned, or a verified list of actual secrets. The reported output excluded credential values. The source contexts were reviewed at the two flagged historical revisions. **No secret values are reproduced here.**

## Finding inventory

| # | Gitleaks rule | Commit prefix | Historical file and line | Context | Assessment |
| --- | --- | --- | --- | --- | --- |
| 1 | `generic-api-key` | `0f71cf4a` | `docs/OWASP_AGENT_BEST_PRACTICES.md:58` | LLM02 documentation row describing protective patterns for credential redaction and fixture hygiene | Documentation-only, likely heuristic false positive |
| 2 | `generic-api-key` | `b06e465e` | `docs/OWASP_AGENT_BEST_PRACTICES.md:57` | Earlier LLM02 documentation row describing scrubbers, environment credentials and synthetic fixtures | Documentation-only, likely heuristic false positive |
| 3 | `generic-api-key` | `b06e465e` | `tests/test_owasp_guardrails.py:22` | Fabricated service-key string in a scrubber input/output test | Synthetic test fixture, likely heuristic false positive |
| 4 | `generic-api-key` | `b06e465e` | `tests/test_owasp_guardrails.py:23` | Fabricated access/secret-key examples in a scrubber test | Synthetic test fixture, likely heuristic false positive |
| 5 | `generic-api-key` | `b06e465e` | `tests/test_owasp_guardrails.py:23` | A second matched key-shaped field on the same synthetic test line | Synthetic test fixture, likely heuristic false positive |

Multiple findings on one line can result from independently detected key-shaped fields; **five scanner matches do not imply five distinct real credentials**.

## Triage basis and limits

- The two documentation matches occur in the OWASP LLM02 *Sensitive Information Disclosure* description, not in application configuration or a credential store. They explain secret scrubbing rather than supply usable secrets.
- The three test matches occur in a `raw_texts` list of intentionally fabricated key-like examples and their expected redacted outputs. The examples are shaped to trigger detection and validate defensive sanitization.
- These contexts strongly support a **likely false-positive** classification. They do **not** establish that no credential exists elsewhere in Git history, nor independently verify the ownership, issuance or revocation status of any string.
- Earlier repository documentation noted credentials visible in a separate screenshot. Confirmation that those particular credentials were rotated is a **separate operational check**; this finding inventory does not establish rotation.
- No Gitleaks rule has been disabled, no allowlist added, and no Git history rewritten. Neither the test suite nor the existing CodeQL checks substitute for a full-history secret scan.

## Submission disposition

**Open / requires reviewer confirmation.** A local Gitleaks scan with these five results exited 1. Tenable's Exchange reviewers independently screen the full repository Git history; their acceptance of documented false positives or exclusions **must not be assumed**.

Recommended follow-up:

1. Confirm locally that all matched examples are synthetic and that any previously exposed real credentials were rotated; do not publish or copy sensitive values into issues or PRs.
2. Ask Exchange maintainers how to handle documented `generic-api-key` false positives in the independent full-history screening.
3. If allowed, create a *minimal* finding-scoped Gitleaks exception referencing this review, not a blanket file, directory, or rule exclusion. An independent scanner may not use repository-specific exceptions.
4. If maintainers require history cleanup, plan it with a backup and coordinated branch/fork/PR handling; do not force-push casually.
5. Repeat `gitleaks git --log-opts="--all" --redact .` after any approved remediation and record its exact exit code and scan coverage.

## Reproduce without exposing matches

~~~powershell
git fetch --all --tags --prune
gitleaks git --log-opts="--all" --redact --report-format json --report-path "$env:TEMP\threatweave-gitleaks-report.json" .
$LASTEXITCODE
~~~

If reporting results publicly, include only rule ID, relative path, short commit hash and line number. Exclude `Secret`, `Match`, `Line`, raw JSON reports and any other field containing discovered values.

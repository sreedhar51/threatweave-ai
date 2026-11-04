<!-- DRAFT ONLY. Replace placeholders, validate schema, and personally accept agreement before submitting. -->
---
name: "ThreatWeave AI — Exposure Decision Agent"
author: "sreedhar51"
github_url: "https://github.com/sreedhar51/threatweave-ai"
description: "Correlate vulnerability and CIS evidence, apply organizational policy, and replay auditable prioritization decisions."
license: "MIT"
tier: "contributed"
tags: ["risk-prioritization", "policy-as-code", "compliance", "cis-misconfiguration", "evidence-replay"]
domains: ["vulnerability-management", "governance-risk-compliance"]
integrations: ["Tenable", "ServiceNow", "Anthropic"]
date_added: 2026-11-04
# REQUIRED: add the real ISO 8601 agreement date only after you accept it.
# contribution_agreement_date: 2026-11-04T00:00:00Z
works_with_tenable_hexa_mcp: false
---

# ThreatWeave AI

ThreatWeave is an evidence-driven cybersecurity investigation agent that combines Tenable vulnerability exports, optional CIS compliance results and verified CMDB asset context. Its deterministic policy engine generates contextual remediation priorities and Decision Receipts that explain what changed, why, and which source evidence supports each change.

## Integration support level

- **Tenable:** read-only VM async export API (mock-tested), authorized `.nessus` file import (tested), optional read-only Security Center analysis (mock-tested; tenant validation required).
- **ServiceNow:** offline CMDB CSV/JSON export import with explicit human-approved Tenable UUID mapping. **Not** a live ServiceNow connector.
- **Anthropic:** optional Claude analysis and policy drafting. No Anthropic key is needed for deterministic offline operation.

## What it offers

- Local/offline demonstrator and read-only Tenable bulk export connector.
- Conservative same-asset vulnerability-to-CIS correlations with validated control relationships.
- User-defined organizational rules; original vendor severity and VPR remain unchanged.
- Candidate remediation groups with finding-to-fix source traceability.
- Reproducible Decision Receipts and before/after policy replay.
- Standalone deterministic guided agent plus optional Claude reasoning and MCP tools.

## Install and run

See the repository README for quick-start, synthetic demo, optional UI, and MCP commands.

## Safety / limitations

Read-only. No network reachability or cross-host attack-path claims from IP addressing. Synthetic demo evidence is clearly labeled. Live Tenable access and optional SDK integrations require separate testing and credentials. No patch execution, API write-back, or unverified host merging. Security Center and ServiceNow API capabilities require separate tenant validation.

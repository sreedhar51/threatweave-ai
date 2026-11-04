# On-premises and CMDB DataBridge integration

## Nessus Manager / Nessus `.nessus` XML export (local)

```bash
threatweave --db runtime/onprem.db import nessus /path/to/authorized-scan.nessus
threatweave --db runtime/onprem.db correlate
threatweave --db runtime/onprem.db receipt --policy policies/business-context.yaml --out runtime/receipts/onprem.json
```

The streaming parser reads NessusClientData_v2 report hosts, host properties, and report items using XML `iterparse`. DTD and entity declarations are rejected, severity-0 **non-compliance** plugins are skipped, and compliance ERROR/WARNING remain scan-hygiene statuses (not FAIL). A host UUID is preferred. With no UUID the parser uses a non-IP host name if available, otherwise a unique report ordinal placeholder. Do not use these fallback identifiers to assert cross-source identity.

## Tenable Security Center (optional, read-only, tenant validation required)

The Security Center API is *synchronous* and paginated, unlike Tenable VM bulk exports. The collector makes only query calls: `POST /rest/analysis`, `type=vuln`, `sourceType=cumulative`, `tool=vulndetails`, `startOffset`/`endOffset`.

```bash
export SC_ACCESS_KEY='...'   # supply via local secret manager, not repository
export SC_SECRET_KEY='...'
threatweave --db runtime/onprem.db securitycenter-export \
  --url https://your-authorized-sc-host.example --page-size 200 --max-pages 5 \
  --ca-bundle /path/to/trusted-ca-bundle.pem
threatweave --db runtime/onprem.db correlate
```

The `x-apikey` header uses both keys. TLS verification is enabled; for private PKI use `--ca-bundle`, not `verify=False`. The client reads pluginText `cm:compliance-*` evidence conservatively, preserving FAIL vs WARNING/ERROR. Without an authoritative `hostUUID`, a per-finding unresolved identity is generated **without IP matching or merging**. Such records require identity reconciliation before cross-source correlation. The source supports bounded pagination and is **not live-validated** in this project.

Tenable reference: [Security Center integrations](https://developer.tenable.com/docs/sc-integrations) and [Analysis API](https://docs.tenable.com/security-center/api/Analysis.htm).

## ServiceNow CMDB export with human gate

First ingest Tenable assets, then propose CI-to-asset mappings by exact FQDN or hostname. No IP match is ever attempted:

```bash
threatweave --db runtime/onprem.db cmdb-propose ./servicenow-export.csv --out ./proposals.csv
```

Review each row and mark `mapping_verified=yes` **only after verifying** the identity evidence. Then import the approved CSV:

```bash
threatweave --db runtime/onprem.db import cmdb ./proposals.csv --provider servicenow-export
```

Unapproved or ambiguous mappings do not enrich an asset. A live ServiceNow API connector is a **future extension**, not implemented.

## Data integrity

Input fingerprints distinguish assets, vulnerabilities, compliance, CMDB and correlations. They make replay differences inspectable but cannot prove a source record is true. No automated remediation or remote configuration changes are available.

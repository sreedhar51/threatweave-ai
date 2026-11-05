# DataBridge connector contract

## Accepted record types

`asset`, `vulnerability`, `compliance`, and `cmdb`. Inputs can be `.csv`, `.json`, `.jsonl`, or `.ndjson` files.

### Asset fields

- Required: `uuid` / `asset_uuid` / `asset_id`.
- Optional: `hostname`, `operating_system`, `asset_type`, `environment`, `role`, `tags`, `last_seen`.

### Vulnerability fields

- Required: `asset.uuid` or `asset_uuid`; `plugin.id` or `plugin_id`.
- Optional: `port.port`, `port.protocol`, `severity`, `status`, `plugin.name`, `plugin.cve`, `plugin.solution`, `plugin.vpr.score`, `software_family`, `observed_at`, `output`.
- Identity is formed from asset UUID + plugin ID + port + protocol. Missing port defaults to `0`; missing protocol to `unknown` and should be reviewed if identity ambiguity matters.

### Compliance fields

- Required: `asset_uuid`, `compliance_full_id` (or `control_id`), `audit_file`.
- Optional: `title`, `status`, `expected_value`, `actual_value`, `observed_at`.
- A record with `FAIL`, `FAILED`, or `NON_COMPLIANT` can be considered for a *relevant* correlation rule; `WARNING` or `ERROR` are not converted into FAIL.
- Synthetic `CIS-REMOTE-ADMIN` identifiers in examples are illustrative, **not authentic licensed CIS control references**.

### CMDB fields (generic ServiceNow export)

- Required: `ci_sys_id` / `sys_id`.
- To link to a Tenable asset: `tenable_asset_uuid` and `mapping_verified: yes`.
- Optional: `business_service`, `business_criticality`, `environment`, `role`, `support_group`, `business_tags`, `internet_exposure`, `last_updated`.
- Without an explicit verified UUID mapping, the record is retained unlinked and does **not** affect risk.
- A verified UUID that does not yet exist in the imported Tenable asset set is held unlinked; import assets first.

Example generic CMDB CSV:

```csv
ci_sys_id,tenable_asset_uuid,mapping_verified,environment,business_criticality,business_service,business_tags,internet_exposure
synthetic-ci-001,demo-prod-042,yes,production,critical,Synthetic Payment Service,payments,unknown
```

Organizations should derive `mapping_verified` from an approved CMDB-Tenable identity mapping or a separately verified identity process, not from hostname similarity.

## Future connector interface

A provider must deliver normalized `asset`/`vulnerability`/`compliance`/`cmdb` records with stable source IDs, observation timestamps, source hashes, explicit matching evidence, and source licensing metadata where applicable. API connectors should be read-only by default. ServiceNow Table API, CrowdStrike, SentinelOne, and Wiz are **extension points, not implemented integrations**.

## Correlation rule governance

See the [correlation logic guide](CORRELATION_LOGIC.md) for exact matching conditions, classifier limitations, policy effects, and Claude proposal review.


`policies/correlation-rules.yaml` is a deterministic demonstration mapping. Production mappings must be validated by security specialists against accurate CIS checks, affected technology, vulnerability applicability, and mitigating-control semantics. A same-asset link yields a **candidate compounded exposure**, not a verified attack path.

## Tenable API

- API client uses `POST /assets/v2/export`, `POST /vulns/export`, `POST /compliance/export`.
- It polls status and downloads asynchronously generated chunks. Asset export v2 uses the legacy `/assets/export/{uuid}/...` for chunk/status endpoints.
- Supports HTTP 429 and transient 5xx retry with bounded delay.
- API keys stay in environment variables, requests use HTTPS to Tenable-owned domains.
- Export requests must use intentional documented filters and authorized tenant scope.
- Actual tenant record fields and API permissions must be validated live before competition use.

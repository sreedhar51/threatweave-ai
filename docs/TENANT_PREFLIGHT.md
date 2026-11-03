# Authorized Tenable Partner Lab preflight

**Do not commit or upload credentials.** A prior screenshot included an account password and API keys. Ask the tenant administrator to revoke/rotate those credentials before use. The repository intentionally does not contain their values.

The expected tenant base URL is `https://cloud.tenable.com`. Configure the **newly rotated** API access and secret keys as environment variables **locally** (or with your approved secrets manager). Do not paste secrets into shell commands that are captured by logs, screenshots, recorded demos, or GitHub Actions.

From the repository root, after `python -m pip install -e .`, run:

```bash
python scripts/tenant_preflight.py
```

The default preflight performs only **GET `/assets`** and **GET `/workbenches/vulnerabilities`** through the existing HTTPS Tenable client. It reports authentication, visible asset counts, OS/hostname coverage, rough asset types, plugin-level severity distribution, and VPR coverage. Workbench results are aggregates, not per-asset evidence. It does not print asset names, IPs, raw API responses, or keys. Tenable limits this endpoint to up to 5,000 assets; it is not a full inventory count.

**Optional**, to check whether the tenant has usable CIS compliance data on **one visible asset**:

```bash
python scripts/tenant_preflight.py --check-compliance
```

This initiates a narrowly scoped read-only compliance export (asset UUID, 50 findings per chunk, no more than five chunks processed locally), and prints only aggregate status counts. A `403` means insufficient permissions, not necessarily no compliance data. Empty results can reflect choosing an asset without compliance scans. This probe does not run a scan or modify findings. Do not present it as proof that all tenant assets have compliance data.

## Interpretation and full integration run

Successful GET requests confirm authentication and their specific read permissions **only**. It does *not* validate export permissions. For complete integration validation, use the repository's `tenable-export` commands with authorized, bounded filters and inspect ingestion rejection counts, source field mappings, and correlation counts in an isolated database. For a large estate, use the Tenable export APIs rather than repeatedly listing `/assets`.

Tenable VM documented shapes: assets contain `id` and often `hostname`/`operating_system` arrays; compliance contains `asset_uuid`, `compliance_full_id`, `audit_file`, `check_name`, `status`, and may contain `asset.id`. Source severity and VPR must remain unchanged. Correlations are supported only when the asset UUID matches and the relevant control rule is validated. IP addresses are never an identity join key.

Current validation status: **The application code and mocked API behavior have been tested locally; no real tenant connection was possible from the ChatGPT execution environment (DNS/network resolution blocked).** Real lab availability, scan coverage, rate limits, export schema and privilege grants remain unverified until the preflight is executed from an authorized network.

References: https://developer.tenable.com/reference/assets-list-assets , https://developer.tenable.com/reference/io-exports-compliance-create , https://developer.tenable.com/reference/io-exports-compliance-download

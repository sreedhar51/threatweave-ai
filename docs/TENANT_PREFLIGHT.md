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

## Windows laptop: safe connection smoke test

The keys shown in the emailed screenshots are **exposed**. Revoke/rotate them first.
This Tenant VM lab uses `https://cloud.tenable.com`; it is **not** a
Security Center server. Do not send Tenable VM keys to `/rest/analysis` or
use them as Cloud Security GraphQL keys. Cloud Security credentials require a
separate provisioned key if that product is in scope.

Open **PowerShell** in a trusted local checkout (not a cloud terminal) and run:

```powershell
git switch review/steps-1-5-evidence-foundations
git pull --ff-only
py -3.11 -m pip install -e '.[dev]'
py -3.11 -m pytest -q

# Hidden prompts: do NOT paste secrets in the chat, GitHub, or scripts.
$ak = Read-Host 'Rotated Tenable VM access key' -AsSecureString
$sk = Read-Host 'Rotated Tenable VM secret key' -AsSecureString
$env:TENABLE_ACCESS_KEY = [System.Net.NetworkCredential]::new('', $ak).Password
$env:TENABLE_SECRET_KEY = [System.Net.NetworkCredential]::new('', $sk).Password
$env:TENABLE_BASE_URL = 'https://cloud.tenable.com'

py -3.11 scripts/tenant_preflight.py
py -3.11 scripts/tenant_preflight.py --check-compliance

# Remove from the current session after testing.
Remove-Item Env:TENABLE_ACCESS_KEY,Env:TENABLE_SECRET_KEY -ErrorAction SilentlyContinue
```

The default preflight performs **GET** requests only. The optional compliance
check initiates a bounded **read-only export** job for one visible asset. It does
not scan, patch, or mutate findings. It prints aggregate coverage and status
counts; inspect them before attempting a larger export. A 401/403 indicates
an authentication/permission problem, not that the dataset is empty.

The base connector defaults to 4,000 assets per asset-export chunk (the
recommended performance range is 4,000–5,000). Documented vulnerability
export chunking is based on `num_assets`; compliance uses `num_findings`.
Keep explicit filters to avoid inadvertently fetching a huge estate or the
wrong time period. No unbounded export or automated repeated polling is
performed by this preflight.

## Tenable engineering guidance incorporated

- **VM**: use asynchronous export jobs; download only available chunks; guard
  against 429/transient 5xx responses; stop on failed exports; preserve Tenable
  UUID-based asset identity and original finding severity/VPR.
- **Security Center**: use serial, bounded, synchronous `/rest/analysis` with
  `vulndetails`, exclude informational and WAS findings by default, support
  limited retries on 429 and transient 5xx. Security Center and VM use
  **different authentication headers and separate keys**.
- **API identity**: send `Integration/1.0 (ThreatWeave Contributors; ThreatWeave AI; Build/0.1.0)`
  as the `User-Agent`. Tenable recommends this standard format to distinguish
  partner integrations and investigate API usage.
- **Production limitations**: read-only threat intelligence is only an
  initial integration. Tenable's official partner validation criteria may
  additionally require bidirectional asset synchronization for solutions
  that manage asset lifecycles; ThreatWeave is **not** claiming Tenable
  partner certification.

Source references:
- https://developer.tenable.com/docs/integration-kickstart
- https://developer.tenable.com/docs/vm-and-was-integrations
- https://developer.tenable.com/docs/sc-integrations
- https://developer.tenable.com/docs/user-agent-header
- https://docs.tenable.com/security-center/best-practices/large-enterprise-deployment/Content/API.htm
- https://pytenable.readthedocs.io/en/stable/

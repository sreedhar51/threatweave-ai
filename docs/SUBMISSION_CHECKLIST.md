# CyberAgents Exchange submission checklist

## Before publish

- [ ] Confirm **every competitor is eligible** under the official SWARM rules; eligibility may require age 18 or the applicable age of majority, whichever is higher. Do not circumvent age requirements.
- [ ] Confirm the actual final project submission deadline from official SWARM Discord; registration and project submission are distinct.
- [ ] Run `pytest -q` and the offline demo on the actual presentation machine.
- [ ] Install and test Streamlit dashboard, MCP SDK, and Claude integration in a real development environment, if claiming these features live.
- [ ] Confirm Tenable One tenant permissions; run one authorized export and verify actual API shapes. Do not claim a live connector was tested if not.
- [ ] Verify source-code and Git history are free of secrets and proprietary exports.
- [ ] Add screenshots and/or a backup recorded demo only using synthetic data or authorized redacted content.
- [ ] Ensure the public repository has a stable LICENSE and README.
- [ ] Add correct GitHub username and repository URL to the Exchange Agent listing draft.
- [ ] Review and explicitly accept the CyberAgents Contribution Agreement **yourself**; populate the *actual* acceptance timestamp. No acceptance has been made on your behalf.
- [ ] Validate listing metadata against current Exchange schema and allowed tags/integrations.
- [ ] Submit the listing through the official Submission Builder or manual PR, then complete the SWARM Discord notification.

## Which category?

**Agent**, with a supporting MCP server in the same repository. Do not submit four partially built listings.

## Manual template reference

Official: https://github.com/tenable/cyberagents-exchange/blob/main/CONTRIBUTING.md

Official rules: https://exchange.tenable.com/swarm-global-rules-nov2026/

Official Exchange: https://exchange.tenable.com/contributing/

A template with placeholders is in `exchange/agent-listing.DRAFT.md`; it is **not submission-ready** until corrected and validated.

# Operator guide — ThreatWeave AI

This repository ships a **read-only security decision agent**, not a remediation executor.

- **Start:** `python -m pip install -e '.[dev]'`; `python scripts/ship_check.py --repeat 3`.
- **Try the flow:** `threatweave demo --staged`, or `streamlit run dashboard/app.py` after `pip install -e '.[ui]'`.
- **Check the decision:** compare the three receipts (`stage1_vulnerabilities`, `stage2_plus_cis`, `stage3_plus_cmdb`). The source fingerprint delta must be `["compliance", "correlations"]`, followed by `["cmdb"]` under the SAME policy.
- **Human gate:** CI/CMDB mappings require explicit verification; generated policy rules are *drafts only*. No writes to any vendor environment.
- **Release gate:** `python -m pytest -q && python scripts/ship_check.py --repeat 3`. Failure blocks a release and must be explained.
- **Source material:** synthetic fixtures are for demos only. Follow `docs/TENANT_PREFLIGHT.md` for authorized live data; never commit tenant exports or API credentials.
- **Design limits:** no validated cross-host attack-path reconstruction, no confirmed patch rollouts, no production-scale performance guarantee, no claimed time savings without measurement.

See [`CLAUDE.md`](CLAUDE.md) for concise agent-specific instructions and [`docs/SWARM_READINESS.md`](docs/SWARM_READINESS.md) for the acceptance checklist.

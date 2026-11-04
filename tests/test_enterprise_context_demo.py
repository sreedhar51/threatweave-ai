"""Regression tests for advanced, fictional-only contextual prioritization."""
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from contextual_policy_demo import run_demo
from threatweave.policy import load_policy, evaluate_finding, validate_policy
from threatweave.engine import create_receipt
from threatweave.ingest import ingest_records
from threatweave.store import Store


def test_enterprise_policy_parses_and_uses_supported_restricted_dsl():
    policy = load_policy(ROOT / "policies/enterprise-context-demo.yaml")
    assert validate_policy(policy) is policy
    assert len(policy["rules"]) >= 12
    assert len({r["id"] for r in policy["rules"]}) == len(policy["rules"])
    assert all(not any(k in r["when"] for k in ("kev", "epss", "cvss", "vpr_gte"))
               for r in policy["rules"])


def test_enterprise_policy_does_not_assume_unknown_exposure_is_confirmed():
    p = load_policy(ROOT / "policies/enterprise-context-demo.yaml")
    finding = {"severity": "high", "vpr": 7.5, "observed_at": "2026-11-02", "kind": "vulnerability"}
    common = {"kind": "vulnerability", "severity": "high", "vpr": 7.5,
              "environment": "production", "criticality": "critical",
              "business_tag": ["identity"], "role": "identity_server",
              "compounded_exposure": False}
    unknown = evaluate_finding(finding, {**common, "internet_exposure": "unknown"}, p)
    confirmed = evaluate_finding(finding, {**common, "internet_exposure": "confirmed"}, p)
    assert "ENT-EXT-HIGH" not in {x["rule_id"] for x in unknown["contributions"]}
    assert "exposure_unknown_validate_before_escalation" in unknown["evidence_flags"]
    assert "ENT-EXT-HIGH" in {x["rule_id"] for x in confirmed["contributions"]}
    assert confirmed["score"] > unknown["score"]


def test_enterprise_synthetic_decision_replay_and_scanner_values():
    report = run_demo()
    assert report["same_dataset"] is True
    assert report["policy_changed"] is True
    assert report["matched_cis_relationships"] == 2
    assert report["records"] == {"asset": 5, "vulnerability": 5, "compliance": 2, "cmdb": 4}
    old = {g["label"]: g for g in report["before"]}
    new = {g["label"]: g for g in report["after"]}
    assert set(old) == set(new)
    for label in old:
        assert old[label]["vendor_severity"] == new[label]["vendor_severity"]
        assert old[label]["vendor_vpr"] == new[label]["vendor_vpr"]
    payment = new["Update synthetic SSH package on payment API"]
    identity = new["Update synthetic identity administration service"]
    dev = new["Update synthetic development library"]
    assert payment["rank"] < dev["rank"]
    assert payment["score"] > identity["score"] > dev["score"]
    assert "ENT-PAYMENT-SERVICE" in payment["matched_rules"]
    assert "ENT-COMPOUNDED" in payment["matched_rules"]
    assert "ENT-UNKNOWN-EXPOSURE" in identity["matched_rules"]
    assert "ENT-EXT-HIGH" not in identity["matched_rules"]


def test_unverified_cmdb_cannot_escalate_dev_asset(tmp_path):
    fixture = json.loads((ROOT / "examples/enterprise-context-demo.json").read_text())
    s = Store(tmp_path / "rejected-context.db")
    try:
        ingest_records(s, [fixture["assets"][0]], "asset", "synthetic")
        ingest_records(s, [fixture["vulnerability"][0]], "vulnerability", "synthetic")
        unverified = {
            "ci_sys_id": "synthetic-unverified-dev",
            "tenable_asset_uuid": "demo-dev-lib",
            "mapping_verified": "no",
            "environment": "production",
            "business_criticality": "critical",
            "business_tags": ["payments"],
            "internet_exposure": "confirmed",
        }
        ingest_records(s, [unverified], "cmdb", "synthetic")
        receipt = create_receipt(s, load_policy(ROOT / "policies/enterprise-context-demo.yaml"))
        dev = next(g for g in receipt["rankings"] if g["kind"] == "vulnerability")
        assert dev["matched_rules"] == []
        assert s.rows("SELECT verified FROM cmdb")[0]["verified"] == 0
    finally:
        s.close()

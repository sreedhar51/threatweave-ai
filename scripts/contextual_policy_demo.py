#!/usr/bin/env python3
"""Offline policy comparison using exclusively fictional enterprise data."""
import argparse
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from threatweave.store import Store
from threatweave.ingest import ingest_records
from threatweave.correlate import correlate
from threatweave.policy import load_policy
from threatweave.engine import create_receipt, compare_receipts


def run_demo():
    fixture = json.loads((ROOT / "examples/enterprise-context-demo.json").read_text(encoding="utf-8"))
    with tempfile.TemporaryDirectory(prefix="threatweave-enterprise-demo-") as temp:
        store = Store(Path(temp) / "fictional.db")
        try:
            accepted = {}
            for kind, key in (("asset", "assets"), ("vulnerability", "vulnerability"),
                              ("compliance", "compliance"), ("cmdb", "cmdb")):
                outcome = ingest_records(store, fixture[key], kind, "synthetic-enterprise")
                if outcome["rejected"]:
                    raise RuntimeError(f"Synthetic fixture {kind} rejected {outcome['rejected']} records")
                accepted[kind] = outcome["accepted"]
            correlations = correlate(store, ROOT / "policies/correlation-rules.yaml")
            baseline = create_receipt(store, load_policy(ROOT / "policies/default.yaml"))
            contextual = create_receipt(store, load_policy(ROOT / "policies/enterprise-context-demo.yaml"))
            changes = compare_receipts(baseline, contextual)
            def ranked(receipt):
                return [{"rank": g["rank"], "label": g["label"],
                         "vendor_severity": g["max_vendor_severity"],
                         "vendor_vpr": g["max_vendor_vpr"],
                         "score": g["score"], "priority": g["priority"],
                         "matched_rules": g["matched_rules"],
                         "evidence_flags": g["evidence_flags"]}
                        for g in receipt["rankings"] if g["kind"] == "vulnerability"]
            return {
                "data": "fictional synthetic test data only",
                "records": accepted,
                "baseline_policy": baseline["policy_id"],
                "contextual_policy": contextual["policy_id"],
                "same_dataset": changes["dataset_unchanged"],
                "policy_changed": not changes["policy_unchanged"],
                "matched_cis_relationships": store.count("correlations"),
                "before": ranked(baseline),
                "after": ranked(contextual),
                "decision_changes": changes["top_movements"],
                "limits": [
                    "Illustrative risk weights only; no approved production SLA",
                    "Original scanner severity and VPR are preserved",
                    "No verified exploitability, cross-host attack path, or live remediation",
                    "Internet exposure labels and CMDB mappings are fictional verified inputs",
                    "KEV/EPSS/CVSS environmental scoring are not integrated into this policy"
                ],
            }
        finally:
            store.close()


def main():
    parser = argparse.ArgumentParser(description="Compare synthetic enterprise contextual policy with baseline")
    parser.add_argument("--output", help="Optional JSON report path (fictional data only)")
    args = parser.parse_args()
    report = run_demo()
    content = json.dumps(report, indent=2)
    if args.output:
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(content + "\n", encoding="utf-8")
    print(content)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

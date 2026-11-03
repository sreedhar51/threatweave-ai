#!/usr/bin/env python3
"""Dependency-light local shipping gate; exits nonzero on an invariant failure."""
import argparse
import json
import sys
from pathlib import Path

# Can execute from source checkout without installing the package.
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from threatweave.shipcheck import run_ship_check


def main():
    parser=argparse.ArgumentParser(description='ThreatWeave deterministic offline release gate')
    parser.add_argument('--repeat',type=int,default=3,help='Clean independent runs, 2–5')
    parser.add_argument('--assets',type=int,default=0,help='Additional synthetic assets per stage (0–50000)')
    parser.add_argument('--seed',type=int,default=42)
    parser.add_argument('--output',help='Optional local JSON summary path; do not upload tenant data')
    args=parser.parse_args()
    try:
        report=run_ship_check(args.repeat,args.assets,args.seed)
        if args.output:
            p=Path(args.output)
            p.parent.mkdir(parents=True,exist_ok=True)
            p.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
        print(json.dumps(report,indent=2))
    except Exception as exc:
        print(json.dumps({'verdict':'FAIL','error_type':type(exc).__name__,
                          'error':str(exc)[:400]}),file=sys.stderr)
        return 1
    return 0


if __name__=='__main__':
    raise SystemExit(main())

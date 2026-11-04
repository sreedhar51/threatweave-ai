#!/usr/bin/env python3
"""Measure local synthetic ingestion and ranking, without tenant credentials."""
import argparse
import json
import sys
import tempfile
from pathlib import Path
from time import perf_counter
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from threatweave.store import Store
from threatweave.fixtures import generate
from threatweave.ingest import ingest_records
from threatweave.correlate import correlate
from threatweave.engine import rank_groups,evidence_for_group
from threatweave.policy import load_policy
ROOT=Path(__file__).resolve().parents[1]

def run(n=50000,seed=42):
    if not 0<=n<=50000: raise ValueError('--assets must be between 0 and 50000')
    with tempfile.TemporaryDirectory(prefix='threatweave-bench-') as temp:
        store=Store(Path(temp)/'benchmark.db')
        try:
            durations={}
            start=perf_counter()
            streams=generate(n_assets=n,seed=seed,store=None)
            reports=[ingest_records(store,records,kind,provider='synthetic-benchmark')
                     for kind,records in streams.items()]
            durations['ingest']=round(perf_counter()-start,3)
            start=perf_counter()
            correlation=correlate(store,ROOT/'policies/correlation-rules.yaml')
            durations['correlate']=round(perf_counter()-start,3)
            start=perf_counter()
            groups=rank_groups(store,load_policy(ROOT/'policies/business-context.yaml'))
            durations['rank_groups']=round(perf_counter()-start,3)
            start=perf_counter()
            evidence=evidence_for_group(store,groups[0]['fix_group_id'],limit=15) if groups else None
            durations['evidence_for_group']=round(perf_counter()-start,6)
            return {'synthetic_only':True,'assets_requested':n,
                    'ingestion':reports,'correlations':correlation['correlations'],
                    'groups':len(groups),'sample_evidence_count':len(evidence['evidence']) if evidence else 0,
                    'elapsed_seconds':durations}
        finally: store.close()

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--assets',type=int,default=50000)
    parser.add_argument('--seed',type=int,default=42)
    parser.add_argument('--out',help='Optional output JSON file')
    args=parser.parse_args()
    report=run(args.assets,args.seed)
    if args.out:
        path=Path(args.out);path.parent.mkdir(parents=True,exist_ok=True)
        path.write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps(report,indent=2))
if __name__=='__main__':main()

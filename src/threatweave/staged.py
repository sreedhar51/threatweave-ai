"""Three-stage offline demo with the *same* organizational policy in all runs."""
from pathlib import Path
from time import perf_counter
from .store import Store
from .fixtures import generate,load_staged_demo
from .correlate import correlate
from .engine import compare_receipts,create_receipt
from .policy import load_policy

ROOT = Path(__file__).resolve().parents[2]
HERO = 'demo-pay-web-01'


def run_staged_demo(output_dir, n_assets=0, seed=42):
    output_dir=Path(output_dir)
    output_dir.mkdir(parents=True,exist_ok=True)
    policy=load_policy(ROOT/'policies/business-context.yaml')
    receipts=[]
    timings={}
    hero={}
    for name,has_cis,has_cmdb in (
        ('stage1_vulnerabilities',False,False),
        ('stage2_plus_cis',True,False),
        ('stage3_plus_cmdb',True,True),
    ):
        start=perf_counter()
        db_path=output_dir/(name+'.db')
        if db_path.exists():
            db_path.unlink()  # Dedicated synthetic demo DB, never a user-supplied tenant DB.
        store=Store(db_path)
        try:
            load_staged_demo(store,with_cis=has_cis,with_cmdb=has_cmdb)
            if n_assets:
                generate(n_assets=n_assets,seed=seed,store=store,
                         with_cis=has_cis,with_cmdb=has_cmdb)
            correlate(store,ROOT/'policies/correlation-rules.yaml')
            receipt=create_receipt(store,policy,output_dir/(name+'.json'))
            receipts.append(receipt)
            hero[name]=[
                {'fix_group_id':g['fix_group_id'],'label':g['label'],
                 'rank':g['rank'],'score':g['score'],'priority':g['priority'],
                 'compounded_assets_count':g['compounded_assets_count'],
                 'matched_rules':g['matched_rules']}
                for g in receipt['rankings'] if g['kind']=='vulnerability'
                and any(r['asset_id']==HERO for r in g['evidence_refs'])
            ]
        finally:
            store.close()
        timings[name]=round(perf_counter()-start,3)
    return {
        'synthetic_demo':True,'hero_asset':HERO,'generated_assets_per_stage':n_assets,
        'policy_id':policy['policy_id'], 'policy_version':policy['version'],
        'stage1_to_stage2':compare_receipts(receipts[0],receipts[1]),
        'stage2_to_stage3':compare_receipts(receipts[1],receipts[2]),
        'hero_fix_groups':hero,
        'elapsed_seconds_per_stage':timings,
        'receipt_paths':[str(output_dir/(name+'.json')) for name in timings],
        'evidence_note':'All source data synthetic; no verified attack paths or live remediations.'
    }

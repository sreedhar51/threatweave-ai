"""Offline-first CLI: complete demo works without LLM or vendor API keys."""
import argparse
import json
from pathlib import Path
from .store import Store
from .ingest import ingest_file
from .fixtures import load_demo
from .correlate import correlate
from .policy import load_policy
from .engine import create_receipt, compare_receipts
from .tenable import TenableExportClient

ROOT=Path(__file__).resolve().parents[2]


def main(argv=None):
    parser=argparse.ArgumentParser(prog='threatweave',description='ThreatWeave evidence-backed prioritization agent')
    parser.add_argument('--db',default='runtime/threatweave.db')
    commands=parser.add_subparsers(dest='command',required=True)
    sub=commands.add_parser('demo',help='Load synthetic findings, generate receipts, and compare')
    sub.add_argument('--staged',action='store_true',help='Three-stage same-policy evidence replay')
    sub.add_argument('--assets',type=int,default=0,help='Additional synthetic benchmark assets for staged mode')
    sub.add_argument('--seed',type=int,default=42,help='Synthetic benchmark generation seed')
    sub=commands.add_parser('import',help='Import local authorized CSV/JSON/JSONL')
    sub.add_argument('record_type',choices=['asset','vulnerability','compliance','cmdb'])
    sub.add_argument('file')
    sub.add_argument('--provider',default='tenable')
    sub=commands.add_parser('cmdb-propose',help='Create reviewable, unapproved CMDB mapping CSV')
    sub.add_argument('file',help='ServiceNow CMDB CSV/JSON export')
    sub.add_argument('--out',required=True,help='Mapping proposals CSV (never auto-approved)')
    sub=commands.add_parser('tenable-export',help='Pull authorized Tenable API export')
    sub.add_argument('record_type',choices=['asset','vulnerability','compliance'])
    sub.add_argument('--body-file',help='Optional JSON export request specification')
    sub.add_argument('--poll-seconds',type=int,default=3)
    commands.add_parser('correlate',help='Run vetted same-asset CIS correlation rules')
    sub=commands.add_parser('investigate',help='Run standalone read-only agent investigation')
    sub.add_argument('--policy',default=str(ROOT/'policies/business-context.yaml'))
    sub=commands.add_parser('receipt',help='Generate deterministic ranking receipt')
    sub.add_argument('--policy',default=str(ROOT/'policies/default.yaml'))
    sub.add_argument('--out',default='runtime/receipts/receipt.json')
    sub=commands.add_parser('compare',help='Compare two saved Decision Receipts')
    sub.add_argument('before');sub.add_argument('after')
    args=parser.parse_args(argv)
    if args.command=='demo' and args.staged:
        from .staged import run_staged_demo
        if not 0 <= args.assets <= 500000: parser.error('--assets must be between 0 and 500000')
        result=run_staged_demo(Path(args.db).parent/'staged',args.assets,args.seed)
    elif args.command=='cmdb-propose':
        from .cmdb_map import propose_mappings
        store=Store(args.db)
        try:result=propose_mappings(store,args.file,args.out)
        finally:store.close()
    elif args.command=='compare':
        result=compare_receipts(json.loads(Path(args.before).read_text()),json.loads(Path(args.after).read_text()))
    else:
        store=Store(args.db)
        try:
            if args.command=='demo':
                reports=load_demo(store)
                correlate(store,ROOT/'policies/correlation-rules.yaml')
                before=create_receipt(store,load_policy(ROOT/'policies/default.yaml'), 'runtime/receipts/demo-before.json')
                after=create_receipt(store,load_policy(ROOT/'policies/business-context.yaml'), 'runtime/receipts/demo-after.json')
                result={'synthetic_demo':True,'ingestion':reports,'overview':store.overview(),
                        'before_top':before['rankings'][:3],'after_top':after['rankings'][:3],
                        'replay':compare_receipts(before,after)}
            elif args.command=='import':result=ingest_file(store,args.file,args.record_type,args.provider)
            elif args.command=='tenable-export':
                body=json.loads(Path(args.body_file).read_text()) if args.body_file else None
                client=TenableExportClient()
                try:result=client.ingest(store,args.record_type,body,poll_seconds=args.poll_seconds)
                finally:client.close()
            elif args.command=='correlate':result=correlate(store,ROOT/'policies/correlation-rules.yaml')
            elif args.command=='investigate':
                from .agent import guided_investigation
                # The guided agent owns its DB connection to keep tools reusable.
                result=guided_investigation(args.db,args.policy)
            elif args.command=='receipt':
                obj=create_receipt(store,load_policy(args.policy),args.out)
                result={'receipt_id':obj['receipt_id'],'saved_to':args.out,'groups':len(obj['rankings']),
                        'top_groups':obj['rankings'][:5]}
        finally:store.close()
    print(json.dumps(result,indent=2))
    return 0

if __name__=='__main__':main()

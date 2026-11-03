"""Evidence-qualified group ranking and deterministic decision receipts."""
import json
import math
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from .policy import evaluate_finding, load_policy, validate_policy, priority
from .utils import canonical,digest,now_utc,parse_time

ACTIVE={'OPEN','ACTIVE','REOPENED','NEW'}
FAILED={'FAIL','FAILED','NON_COMPLIANT'}


def group_key(f):
    kind=f['kind']
    # Identical solution text does not prove that a single patch resolves all findings.
    sol=' '.join(str(f.get('solution') or '').lower().split())
    family=' '.join(str(f.get('software_family') or 'unknown').lower().split())
    if kind=='compliance':
        key=['cis-control',f.get('audit_file') or 'unknown',f.get('control_id') or f['finding_id']]
        label=f"Review CIS control {f.get('control_id') or 'unknown'}"
        quality='candidate_configuration_group'
    elif sol:
        key=['vulnerability-solution',sol,family]
        label=(f['solution'] or 'Review remediation')[:140]
        quality='candidate_solution_family'
    else:
        key=['plugin',str(f.get('plugin_id') or f['finding_id'])]
        label=f"Investigate plugin {f.get('plugin_id') or 'unknown'}"
        quality='plugin_group_no_verified_fix'
    return digest(key)[:18],label,quality


def _contexts(store):
    # A verified mapping is a prerequisite; conflicts disqualify affected fields.
    ctx=defaultdict(list)
    for row in store.db.execute("SELECT * FROM cmdb WHERE verified=1 AND asset_id IS NOT NULL ORDER BY ci_id"):
        ctx[row['asset_id']].append(dict(row))
    return ctx


def _risk_context(asset, mappings, f, compounded):
    mapped=mappings.get(f['asset_id'],[])
    def val(field, asset_field=None):
        non_null={str(m[field]) for m in mapped if m[field] is not None and str(m[field])!=''}
        if len(non_null)>1: return None
        if non_null: return next(iter(non_null))
        return asset.get(asset_field or field)
    tags=[]
    try: tags+=json.loads(asset.get('tags_json') or '[]')
    except ValueError: pass
    for m in mapped:
        try: tags+=json.loads(m.get('business_tags_json') or '[]')
        except ValueError: pass
    criticality=val('criticality')
    environment=val('environment')
    role=val('role')
    internet=val('internet_exposure')
    return {'severity':f['severity'],'vpr':f['vpr'],'kind':f['kind'],'status':f['status'],
            'environment':environment,'business_tag':sorted(set(tags)),
            'asset_type':asset.get('asset_type'),'role':role,
            'criticality':criticality,'internet_exposure':internet,
            'compounded_exposure':bool(compounded),
            'mapping_conflict':any(len({str(m[k]) for m in mapped if m[k] is not None})>1
                                   for k in ('criticality','environment','role','internet_exposure'))}


def rank_groups(store, policy, max_groups=None):
    validate_policy(policy)
    cmdb=_contexts(store)
    corr_ids={r['vuln_id'] for r in store.db.execute('SELECT DISTINCT vuln_id FROM correlations')}
    groups={}
    cursor=store.db.execute('''SELECT f.*,a.hostname,a.os,a.asset_type,a.environment,a.role,
                         a.tags_json FROM findings f
                         LEFT JOIN assets a ON a.asset_id=f.asset_id ORDER BY f.finding_id''')
    for row in cursor:
        f=dict(row)
        if f['kind']=='vulnerability' and (f['status'] or '').upper() not in ACTIVE: continue
        if f['kind']=='compliance' and (f['status'] or '').upper() not in FAILED: continue
        context=_risk_context(f,cmdb,f,f['finding_id'] in corr_ids)
        outcome=evaluate_finding(f,context,policy)
        gid,label,quality=group_key(f)
        if gid not in groups:
            groups[gid]={'fix_group_id':gid,'label':label,'mapping_quality':quality,'kind':f['kind'],
                         'score':0,'priority':'low','finding_count':0,'assets':set(),
                         'servers':set(),'workstations':set(),'production_assets':set(),
                         'compounded_asset_ids':set(),'matched_rules':set(), 'rule_contributions':{},
                         'evidence_flags':set(),'evidence_refs':[],'critical_assets':set()}
        g=groups[gid]
        g['finding_count']+=1
        asset_id=f['asset_id']
        g['assets'].add(asset_id)
        if (f.get('asset_type') or '').lower()=='server': g['servers'].add(asset_id)
        if (f.get('asset_type') or '').lower()=='workstation': g['workstations'].add(asset_id)
        if context['environment'] and context['environment'].lower()=='production': g['production_assets'].add(asset_id)
        if context['criticality'] and str(context['criticality']).lower() in {'critical','high','1'}:
            g['critical_assets'].add(asset_id)
        if context['compounded_exposure']: g['compounded_asset_ids'].add(asset_id)
        if outcome['score']>g['score']: g['score']=outcome['score']
        g['evidence_flags'].update(outcome['evidence_flags'])
        for r in outcome['contributions']:
            g['matched_rules'].add(r['rule_id'])
            # Maximum per-finding contribution is illustrative; no across-host addition.
            key=r['rule_id']
            g['rule_contributions'][key]=max(g['rule_contributions'].get(key,0),r['delta'])
        if len(g['evidence_refs'])<10:
            g['evidence_refs'].append({'finding_id':f['finding_id'],'source_hash':f['source_hash'],
                                       'asset_id':asset_id,'kind':f['kind']})
    ranked=[]
    for g in groups.values():
        g['priority']=priority(g['score'])
        for k in ('assets','servers','workstations','production_assets','compounded_asset_ids','critical_assets'):
            g[k.replace('_asset_ids','_assets')+'_count' if k=='compounded_asset_ids' else k+'_count']=len(g[k])
            del g[k]
        g['matched_rules']=sorted(g['matched_rules'])
        g['rule_contributions']={k:g['rule_contributions'][k] for k in sorted(g['rule_contributions'])}
        g['evidence_flags']=sorted(g['evidence_flags'])
        ranked.append(g)
    ranked.sort(key=lambda g:(-g['score'],-g['assets_count'],-g['finding_count'],g['fix_group_id']))
    for i,g in enumerate(ranked,start=1): g['rank']=i
    return ranked if max_groups is None else ranked[:max_groups]


def create_receipt(store, policy, path=None):
    validate_policy(policy)
    result={'schema_version':'1.0','engine_version':'0.1.0',
            'dataset_hash':'sha256:'+store.snapshot_hash(),
            'policy_hash':'sha256:'+digest(policy),
            'policy_id':policy['policy_id'],'policy_version':policy['version'],
            'rankings':rank_groups(store,policy),
            'source_summary':store.overview(),
            'cross_asset_attack_paths':'not evaluated: network and identity reachability evidence unavailable'}
    # Receipt ID excludes wall-clock time, so identical inputs produce same identity.
    result['receipt_id']='DR-'+digest(result)[:16]
    result['generated_at']=now_utc()
    if path:
        out=Path(path)
        out.parent.mkdir(parents=True,exist_ok=True)
        out.write_text(json.dumps(result,indent=2,ensure_ascii=False),encoding='utf8')
    return result


def compare_receipts(before,after,limit=25):
    b={x['fix_group_id']:x for x in before['rankings']}
    a={x['fix_group_id']:x for x in after['rankings']}
    movements=[]
    for gid in sorted(b.keys()|a.keys()):
        old=b.get(gid); new=a.get(gid)
        if old and new and old['rank']==new['rank'] and old['score']==new['score']: continue
        movements.append({'fix_group_id':gid,
                          'label':(new or old)['label'],
                          'old_rank':old['rank'] if old else None,
                          'new_rank':new['rank'] if new else None,
                          'old_priority':old['priority'] if old else None,
                          'new_priority':new['priority'] if new else None,
                          'old_score':old['score'] if old else None,
                          'new_score':new['score'] if new else None,
                          'matched_rules_after':new['matched_rules'] if new else [],
                          'rule_contributions_after':new['rule_contributions'] if new else {},
                          'evidence_refs':(new or old)['evidence_refs'][:5],
                          'evidence_flags':(new or old)['evidence_flags']})
    movements.sort(key=lambda x:(-(abs((x['new_score'] or 0)-(x['old_score'] or 0))), x['fix_group_id']))
    same_dataset=before['dataset_hash']==after['dataset_hash']
    same_policy=before['policy_hash']==after['policy_hash']
    if same_dataset and not same_policy: cause='policy_changed'
    elif same_policy and not same_dataset: cause='source_data_or_context_changed'
    elif not same_dataset and not same_policy: cause='both_data_and_policy_changed_attribution_not_isolated'
    else: cause='no_input_change'
    return {'before_receipt_id':before['receipt_id'],'after_receipt_id':after['receipt_id'],
            'dataset_unchanged':same_dataset,'policy_unchanged':same_policy,'change_type':cause,
            'moved_group_count':len(movements),'top_movements':movements[:max(0,min(int(limit),100))]}


def evidence_for_group(store, gid, limit=25):
    limit=max(1,min(100,int(limit)))
    result=[]
    for r in store.db.execute('SELECT * FROM findings ORDER BY finding_id'):
        f=dict(r)
        if group_key(f)[0]==gid:
            result.append({k:f.get(k) for k in ('finding_id','asset_id','kind','source','title','severity',
                                                'status','plugin_id','control_id','audit_file','source_hash','source_excerpt')})
            if len(result)>=limit:break
    return {'fix_group_id':gid,'evidence':result,'limited_to':limit,
            'note':'Source excerpts and hashes; consult authorized original exports for full scanner output.'}

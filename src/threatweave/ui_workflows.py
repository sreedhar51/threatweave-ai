"""Testable, read-only UI helpers; only explicit approval writes local policy/receipt.

No Tenable/ServiceNow API calls. Do not treat an approved local policy as a
change to the running tenant or to global policy files.
"""
import json
import re
from pathlib import Path

import yaml

from .engine import compare_receipts, create_receipt
from .policy import validate_policy
from .utils import digest


def asset_choices(store, group_id=None, hostname_query='', limit=100):
    """Look up assets by authenticated UUID or hostname, never by IP."""
    limit = max(1, min(int(limit), 200))
    sql = "SELECT a.asset_id,a.hostname,COUNT(DISTINCT f.finding_id) AS findings "
    sql += "FROM assets a LEFT JOIN findings f ON f.asset_id=a.asset_id "
    params = []
    conditions=[]
    if group_id:
        conditions.append("EXISTS(SELECT 1 FROM findings x WHERE x.asset_id=a.asset_id AND x.group_id=?)")
        params.append(group_id)
    if hostname_query.strip():
        conditions.append("lower(coalesce(a.hostname,'')) LIKE ? ESCAPE '\\'")
        q=hostname_query.strip().casefold().replace('\\','\\\\').replace('%','\\%').replace('_','\\_')
        params.append('%'+q+'%')
    if conditions:
        sql += 'WHERE ' + ' AND '.join(conditions) + ' '
    sql += "GROUP BY a.asset_id ORDER BY findings DESC, a.hostname, a.asset_id LIMIT ?"
    return store.rows(sql, tuple(params+[limit]))


def rule_diff(active, proposed):
    """Diff rules by stable ID, distinguishing changed definitions from additions."""
    validate_policy(active)
    validate_policy(proposed)
    before={rule['id']:rule for rule in active['rules']}
    after={rule['id']:rule for rule in proposed['rules']}
    return {'added':sorted(after.keys()-before.keys()),
            'removed':sorted(before.keys()-after.keys()),
            'changed':sorted(k for k in before.keys()&after.keys() if before[k]!=after[k]),
            'unchanged':len([k for k in before.keys()&after.keys() if before[k]==after[k]])}


def add_drafted_rule_to_yaml(raw, draft):
    """Prepare editor text without activating a policy or persisting anything."""
    data=yaml.safe_load(raw)
    validate_policy(data)
    rule=draft.get('draft_rule') if isinstance(draft,dict) else None
    if not isinstance(rule,dict):
        raise ValueError('No valid draft rule supplied')
    proposal={**data,'rules':list(data['rules'])+[rule]}
    validate_policy(proposal)
    return yaml.safe_dump(proposal,sort_keys=False,allow_unicode=True)


def save_approved_policy(store, candidate, runtime_root):
    """Save a versioned local YAML and content-addressed receipt on explicit approval."""
    validate_policy(candidate)
    root=Path(runtime_root)
    policy_id=candidate['policy_id']
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,60}',policy_id):
        raise ValueError('Unsafe policy identifier for output filename')
    policy_hash=digest(candidate)
    receipt=create_receipt(store,candidate)
    policies=root/'policies'
    receipts=root/'receipts'
    policies.mkdir(parents=True,exist_ok=True)
    receipts.mkdir(parents=True,exist_ok=True)
    policy_path=policies/f'{policy_id}-{policy_hash[:12]}.yaml'
    receipt_path=receipts/f"{receipt['receipt_id']}.json"
    # Never overwrite an existing version with different content.
    policy_text=yaml.safe_dump(candidate,sort_keys=False,allow_unicode=True)
    receipt_text=json.dumps(receipt,indent=2,ensure_ascii=False)
    for path,content in ((policy_path,policy_text),(receipt_path,receipt_text)):
        if path.exists() and path.read_text(encoding='utf-8')!=content:
            # generated_at is not deterministic; retain the existing valid receipt
            if path==receipt_path:
                old=json.loads(path.read_text(encoding='utf-8'))
                old.pop('generated_at',None)
                new=json.loads(content)
                new.pop('generated_at',None)
                if old==new:
                    continue
            raise ValueError('Refusing to overwrite a different approved artifact')
        if not path.exists():
            path.write_text(content,encoding='utf-8')
    return {'policy_path':str(policy_path),'receipt_path':str(receipt_path),
            'receipt_id':receipt['receipt_id'],'policy_hash':policy_hash}


def rank_replay(before, after, limit=25):
    """Existing receipt comparison with per-group added/removed rule contribution deltas."""
    compared=compare_receipts(before,after,limit=limit)
    baseline={g['fix_group_id']:g for g in before['rankings']}
    updated={g['fix_group_id']:g for g in after['rankings']}
    for movement in compared['top_movements']:
        gid=movement['fix_group_id']
        old=baseline.get(gid) or {}
        new=updated.get(gid) or {}
        old_rules=set(old.get('matched_rules') or [])
        new_rules=set(new.get('matched_rules') or [])
        old_contributions=old.get('rule_contributions') or {}
        new_contributions=new.get('rule_contributions') or {}
        movement['rules_added']=sorted(new_rules-old_rules)
        movement['rules_removed']=sorted(old_rules-new_rules)
        movement['contribution_deltas']={
            rule:round(float(new_contributions.get(rule,0))-float(old_contributions.get(rule,0)),2)
            for rule in sorted(old_contributions.keys()|new_contributions.keys())
            if float(new_contributions.get(rule,0))!=float(old_contributions.get(rule,0))}
    return compared


def list_receipt_files(receipt_dir, limit=100):
    root=Path(receipt_dir)
    if not root.is_dir(): return []
    return sorted(root.glob('*.json'),key=lambda p:p.name)[:max(0,min(int(limit),100))]


def read_receipt(path, max_bytes=32_000_000):
    path=Path(path)
    if path.stat().st_size>max_bytes:
        raise ValueError('Receipt too large for interactive replay; use the CLI')
    payload=json.loads(path.read_text(encoding='utf-8-sig'))
    if not isinstance(payload,dict) or not all(k in payload for k in ('rankings','receipt_id','dataset_hash','policy_hash')):
        raise ValueError('File is not a valid Decision Receipt')
    return payload

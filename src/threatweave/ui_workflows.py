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



def asset_360(store, asset_id, policy, *, limit=200):
    """Read-only asset dossier; UUID selects one asset, hostname is display-only.

    Rows are bounded but counts cover all findings for the authoritative UUID.
    Links are explicit same-asset, rule-qualified CIS correlations, not attack paths.
    """
    from .correlate import get_asset_exposure
    from .policy import validate_policy

    validate_policy(policy)
    limit = max(1, min(int(limit), 200))
    # Load the identity/approved CMDB through the existing helper, but fetch
    # bounded vulnerability and CIS evidence independently. Ordering combined
    # findings by kind used to hide ALL vulnerabilities on CIS-heavy assets.
    exposure = get_asset_exposure(store, asset_id, limit=1, policy=None)
    if not exposure['asset']:
        return None

    counts = store.rows(
        """SELECT kind, upper(coalesce(status,'UNKNOWN')) AS status, COUNT(*) AS count
           FROM findings WHERE asset_id=? GROUP BY kind,upper(coalesce(status,'UNKNOWN'))
           ORDER BY kind,status""", (asset_id,))
    totals = {
        'vulnerabilities': sum(r['count'] for r in counts if r['kind'] == 'vulnerability'),
        'cis_findings': sum(r['count'] for r in counts if r['kind'] == 'compliance'),
        'cis_failed': sum(r['count'] for r in counts
                          if r['kind'] == 'compliance' and r['status'] in ('FAIL','FAILED','NON_COMPLIANT')),
        'cis_passed': sum(r['count'] for r in counts
                          if r['kind'] == 'compliance' and r['status'] in ('PASS','PASSED','COMPLIANT')),
        'cis_hygiene': sum(r['count'] for r in counts
                           if r['kind'] == 'compliance' and r['status'] in ('WARNING','ERROR')),
        'correlations': store.db.execute(
            'SELECT COUNT(*) FROM correlations WHERE asset_id=?', (asset_id,)).fetchone()[0],
        'verified_cmdb': len(exposure['cmdb']),
    }
    from .engine import _contexts, _risk_context
    from .policy import evaluate_finding
    per_kind = max(1, limit // 2)
    correlated_ids = {r['vuln_id'] for r in store.db.execute(
        'SELECT DISTINCT vuln_id FROM correlations WHERE asset_id=?', (asset_id,))}
    mapped = _contexts(store)
    rows = []
    for kind in ('vulnerability', 'compliance'):
        for record in store.db.execute(
            """SELECT * FROM findings WHERE asset_id=? AND kind=?
               ORDER BY finding_id LIMIT ?""", (asset_id,kind,per_kind)):
            f=dict(record)
            context = _risk_context(exposure['asset'], mapped, f,
                                    f['finding_id'] in correlated_ids)
            evaluation = evaluate_finding(f, context, policy)
            rows.append({
                'finding_id': f['finding_id'], 'source_kind': f['kind'],
                'title': f['title'], 'status': f['status'],
                'scanner_severity': f['severity'], 'scanner_vpr': f['vpr'],
                'contextual_score': evaluation['score'],
                'contextual_priority': evaluation['priority'],
                'matched_rules': ', '.join(c['rule_id'] for c in evaluation['contributions']),
                'evidence_flags': ', '.join(evaluation['evidence_flags']),
            })
    groups = store.rows(
        """SELECT f.group_id, COUNT(*) AS findings, MIN(f.kind) AS kind
           FROM findings f WHERE f.asset_id=? AND f.group_id IS NOT NULL
           GROUP BY f.group_id ORDER BY findings DESC, f.group_id LIMIT 25""", (asset_id,))
    # Hostname/IP never used as a join key: two identical hostnames stay separate.
    hostname = exposure['asset'].get('hostname')
    same_hostname = store.db.execute(
        'SELECT COUNT(*) FROM assets WHERE hostname=?', (hostname,)).fetchone()[0] if hostname else 0
    return {
        'asset': exposure['asset'],
        'counts': totals,
        'status_counts': counts,
        'displayed_findings': len(rows),
        'total_findings': totals['vulnerabilities'] + totals['cis_findings'],
        'truncated': len(rows) < totals['vulnerabilities'] + totals['cis_findings'],
        'findings': rows,
        'vulnerabilities': [x for x in rows if x['source_kind']=='vulnerability'],
        'cis': [x for x in rows if x['source_kind']=='compliance'],
        'correlated_cis_evidence': [
            {'vulnerability_finding_id':r['vuln_id'],
             'compliance_finding_id':r['compliance_id'],
             'compliance_title':r['title'], 'compliance_status':r['status'],
             'rule_id':r['rule_id'], 'rationale':r['rationale']}
            for r in store.rows(
                """SELECT c.vuln_id,c.compliance_id,c.rule_id,c.rationale,
                          f.title,f.status
                   FROM correlations c JOIN findings f
                   ON c.compliance_id=f.finding_id AND c.asset_id=f.asset_id
                   WHERE c.asset_id=? ORDER BY c.vuln_id,c.compliance_id,c.rule_id
                   LIMIT 100""", (asset_id,))],
        'cmdb': exposure['cmdb'],
        'fix_group_refs': groups,
        'same_hostname_asset_count': same_hostname,
        'identity_note': 'Authoritative UUID is the grouping key; hostname is display/search only.',
        'reachability_note': exposure['cross_asset_attack_path'],
    }



def asset_remediation_queue(store, asset_id, policy, *, limit=30):
    """Deterministic UUID-scoped, actionable finding groups with CIS link evidence.

    Uses the same ContextIQ evaluator and group_key as the global Fix Groups.
    A 'compounded' indicator means a rule-qualified same-UUID relationship,
    not a proven exploit chain or a multiplication of risk.
    """
    from .engine import ACTIVE, FAILED, VENDOR_SEVERITY_ORDER, _contexts, _risk_context, group_key
    from .policy import evaluate_finding, priority, validate_policy

    validate_policy(policy)
    limit = max(1, min(int(limit), 100))
    asset_rows = store.rows('SELECT * FROM assets WHERE asset_id=?', (asset_id,))
    if not asset_rows:
        return {'asset_id':asset_id, 'items':[], 'total_groups':0, 'missing_asset':True}
    asset = asset_rows[0]
    mapped = _contexts(store)
    links = store.rows(
        """SELECT c.vuln_id, c.compliance_id, c.rule_id, c.rationale,
                  f.title AS compliance_title, f.status AS compliance_status,
                  f.control_id AS control_id
           FROM correlations c
           JOIN findings f ON f.finding_id=c.compliance_id AND f.asset_id=c.asset_id
           WHERE c.asset_id=?
           ORDER BY c.vuln_id, c.compliance_id, c.rule_id""", (asset_id,))
    by_vuln = {}
    for link in links:
        by_vuln.setdefault(link['vuln_id'], []).append(link)

    groups = {}
    for row in store.db.execute(
        """SELECT * FROM findings WHERE asset_id=? AND kind IN ('vulnerability','compliance')
           ORDER BY finding_id""", (asset_id,)):
        finding = dict(row)
        kind = finding['kind']
        status = str(finding.get('status') or '').upper()
        if kind == 'vulnerability' and status not in ACTIVE:
            continue
        if kind == 'compliance' and status not in FAILED:
            continue
        related = by_vuln.get(finding['finding_id'], []) if kind=='vulnerability' else []
        outcome = evaluate_finding(
            finding, _risk_context(asset, mapped, finding, bool(related)), policy)
        gid, label, quality = group_key(finding)
        item = groups.setdefault(gid, {
            'fix_group_id':gid, 'label':label, 'kind':kind, 'mapping_quality':quality,
            'score':0.0, 'priority':'low', 'finding_count':0,
            'max_vendor_severity':None, 'max_vendor_vpr':None,
            'finding_ids':[], 'matched_rules':set(), 'evidence_flags':set(),
            'rule_contributions':{}, 'correlated_vuln_ids':set(),
            'linked_control_ids':set(), 'linked_cis_evidence':{}, 'top_finding_id':None})
        item['finding_count'] += 1
        if len(item['finding_ids']) < 15:
            item['finding_ids'].append(finding['finding_id'])
        original_severity = str(finding.get('severity') or '').lower()
        current_severity = str(item['max_vendor_severity'] or '').lower()
        if original_severity and VENDOR_SEVERITY_ORDER.get(original_severity,-1) > VENDOR_SEVERITY_ORDER.get(current_severity,-1):
            item['max_vendor_severity'] = finding['severity']
        vpr = finding.get('vpr')
        if vpr is not None and (item['max_vendor_vpr'] is None or vpr > item['max_vendor_vpr']):
            item['max_vendor_vpr'] = vpr
        if outcome['score'] > item['score'] or item['top_finding_id'] is None:
            item['score'] = outcome['score']
            item['top_finding_id'] = finding['finding_id']
        item['matched_rules'].update(c['rule_id'] for c in outcome['contributions'])
        item['evidence_flags'].update(outcome['evidence_flags'])
        for contribution in outcome['contributions']:
            rid = contribution['rule_id']
            item['rule_contributions'][rid] = max(
                item['rule_contributions'].get(rid, 0), contribution['delta'])
        if related:
            item['correlated_vuln_ids'].add(finding['finding_id'])
        for link in related:
            cid = link['compliance_id']
            item['linked_control_ids'].add(cid)
            if cid not in item['linked_cis_evidence']:
                item['linked_cis_evidence'][cid] = {
                    'compliance_finding_id':cid,
                    'control_id':link['control_id'],
                    'title':link['compliance_title'],
                    'status':link['compliance_status'],
                    'relation_rules':set(),
                    'rationale':set()}
            item['linked_cis_evidence'][cid]['relation_rules'].add(link['rule_id'])
            item['linked_cis_evidence'][cid]['rationale'].add(link['rationale'])

    items = []
    for item in groups.values():
        item['priority'] = priority(item['score'])
        item['compounded_vulnerabilities'] = len(item.pop('correlated_vuln_ids'))
        item['related_failed_cis_controls'] = len(item.pop('linked_control_ids'))
        item['matched_rules'] = sorted(item['matched_rules'])
        item['evidence_flags'] = sorted(item['evidence_flags'])
        item['rule_contributions'] = dict(sorted(item['rule_contributions'].items()))
        item['linked_cis_evidence'] = [
            {**{k:v for k,v in data.items() if k not in ('relation_rules','rationale')},
             'relation_rules':sorted(data['relation_rules']),
             'rationale':sorted(data['rationale'])}
            for _,data in sorted(item['linked_cis_evidence'].items())
        ]
        items.append(item)

    # Equal scores: explicit compounded evidence comes first; finding count
    # is only a deterministic tie-breaker, never an additional risk multiplier.
    items.sort(key=lambda i:(-i['score'], -i['compounded_vulnerabilities'],
                             -i['related_failed_cis_controls'], -i['finding_count'],
                             i['fix_group_id']))
    for rank,item in enumerate(items,start=1):
        item['asset_rank'] = rank
    verified_cmdb=store.rows(
        'SELECT ci_id, business_service, support_group, criticality, environment, role '
        'FROM cmdb WHERE asset_id=? AND verified=1 ORDER BY ci_id', (asset_id,))
    owners=sorted({m['support_group'] for m in verified_cmdb if m['support_group']})
    return {
        'asset_id':asset_id, 'hostname':asset.get('hostname'),
        'verified_support_groups':owners, 'owner_is_verified':bool(owners),
        'items':items[:limit], 'total_groups':len(items),
        'truncated':len(items)>limit, 'missing_asset':False,
        'policy_id':policy['policy_id'], 'policy_version':policy['version'],
        'interpretation':'Candidate investigation order; only explicit same-asset CIS rules count as compounded evidence. No exploit path or remediation success asserted.',
    }


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

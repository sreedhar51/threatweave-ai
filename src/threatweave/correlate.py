"""Conservative same-asset vulnerability + compliance correlation."""
from .utils import digest,read_yaml

FAIL_STATES={'FAIL','FAILED','NON_COMPLIANT'}
ACTIVE_STATES={'OPEN','ACTIVE','REOPENED','NEW'}


def correlate(store, rules_path):
    spec=read_yaml(rules_path) or {}
    rules=spec.get('rules') or []
    # Validate every rule before clearing the previously established links.
    normalized=[]
    for rule in rules:
        if not isinstance(rule,dict):
            raise ValueError('Correlation rules must be objects')
        raw_ids=rule.get('control_id')
        ids=raw_ids if isinstance(raw_ids,list) else ([raw_ids] if raw_ids is not None else [])
        title=rule.get('control_title_contains')
        if not all(isinstance(rule.get(k),str) and rule[k].strip() for k in ('id','software_family','rationale')):
            raise ValueError('Correlation rules require id, software_family and rationale')
        if not ids and not title:
            raise ValueError('Correlation rule requires control_id and/or control_title_contains')
        if any(not isinstance(value,str) or not value.strip() for value in ids):
            raise ValueError('Correlation control IDs must be nonempty strings')
        if title is not None and (not isinstance(title,str) or not title.strip()):
            raise ValueError('Correlation title matcher must be nonempty text')
        normalized.append((rule,ids,title))

    store.db.execute('DELETE FROM correlations')
    created=0
    for rule,ids,title in normalized:
        selectors=[]
        params=[rule['software_family']]
        if ids:
            selectors.append('c.control_id IN (' + ','.join('?' for _ in ids) + ')')
            params.extend(ids)
        if title:
            # Case-insensitive literal substring, treating % and _ as ordinary characters.
            selectors.append("lower(c.title) LIKE ? ESCAPE '\\'")
            escaped=title.casefold().replace('\\','\\\\').replace('%','\\%').replace('_','\\_')
            params.append('%'+escaped+'%')
        # A match on *either* known ID or title supports a candidate relationship;
        # always require a validated same-asset match and an explicit family rule.
        sql=('''SELECT v.finding_id AS vuln_id,c.finding_id AS compliance_id,v.asset_id
          FROM findings v JOIN findings c ON v.asset_id=c.asset_id
          WHERE v.kind='vulnerability' AND c.kind='compliance'
          AND lower(v.software_family)=lower(?)
          AND upper(v.status) IN ('OPEN','ACTIVE','REOPENED','NEW')
          AND upper(c.status) IN ('FAIL','FAILED','NON_COMPLIANT')
          AND (''' + ' OR '.join(selectors) + ')')
        matches=store.rows(sql,tuple(params))
        for row in matches:
            cid=digest([row['vuln_id'],row['compliance_id'],rule['id']])[:24]
            store.db.execute('INSERT OR REPLACE INTO correlations VALUES (?,?,?,?,?,?)',
               (cid,row['asset_id'],row['vuln_id'],row['compliance_id'],rule['id'],str(rule['rationale'])))
            created+=1
    store.commit()
    return {'correlations':created,'rules_checked':len(rules),'cross_asset_paths_validated':0}


def get_asset_exposure(store, asset_id, limit=100, policy=None):
    limit=max(1,min(int(limit),200))
    asset=store.rows('SELECT * FROM assets WHERE asset_id=?',(asset_id,))
    cmdb=store.rows('SELECT * FROM cmdb WHERE asset_id=? AND verified=1',(asset_id,))
    findings=store.rows('SELECT finding_id,kind,title,severity,vpr,status,control_id,software_family,source_hash FROM findings WHERE asset_id=? ORDER BY kind,finding_id LIMIT ?', (asset_id,limit))
    links=store.rows('SELECT correlation_id,vuln_id,compliance_id,rule_id,rationale FROM correlations WHERE asset_id=? LIMIT ?', (asset_id,limit))
    result={'asset':asset[0] if asset else None,'cmdb':cmdb,'findings':findings,'correlations':links,
            'cross_asset_attack_path':'unverified - topology/reachability evidence not provided'}
    if policy is not None:
        # ADDITIVE: default response is unchanged; opt-in policy view shares the
        # exact ContextIQ evaluator and context logic used for Fix Group ranking.
        from .engine import _contexts, _risk_context
        from .policy import evaluate_finding, validate_policy
        validate_policy(policy)
        mapped=_contexts(store)
        correlated_vulns={link['vuln_id'] for link in links}
        full_findings={r['finding_id']:r for r in store.rows(
            'SELECT * FROM findings WHERE asset_id=?',(asset_id,))}
        evaluations=[]
        for visible in findings:
            original=full_findings[visible['finding_id']]
            context=_risk_context(asset[0] if asset else {'asset_type':'unknown'},mapped,
                                  original,original['finding_id'] in correlated_vulns)
            evaluation=evaluate_finding(original,context,policy)
            evaluations.append({'finding_id':original['finding_id'],
                'kind':original['kind'],'vendor_severity':original['severity'],
                'vendor_vpr':original['vpr'],
                'contextual_score':evaluation['score'],
                'contextual_priority':evaluation['priority'],
                'matched_rules':[c['rule_id'] for c in evaluation['contributions']],
                'rule_contributions':evaluation['contributions'],
                'evidence_flags':evaluation['evidence_flags']})
        result['finding_evaluations']=evaluations
        result['correlated_cis_evidence']=[{
            'vulnerability_finding_id':link['vuln_id'],
            'compliance_finding_id':link['compliance_id'],
            'compliance_title':full_findings.get(link['compliance_id'],{}).get('title'),
            'compliance_status':full_findings.get(link['compliance_id'],{}).get('status'),
            'rule_id':link['rule_id'],'rationale':link['rationale']
        } for link in links]
    return result

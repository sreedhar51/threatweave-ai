"""Conservative same-asset vulnerability + compliance correlation."""
from .utils import digest,read_yaml

FAIL_STATES={'FAIL','FAILED','NON_COMPLIANT'}
ACTIVE_STATES={'OPEN','ACTIVE','REOPENED','NEW'}

def correlate(store, rules_path):
    spec=read_yaml(rules_path) or {}
    rules=spec.get('rules') or []
    store.db.execute('DELETE FROM correlations')
    created=0
    for rule in rules:
        if not rule.get('id') or not rule.get('software_family') or not rule.get('control_id'):
            raise ValueError('Correlation rules need id, software_family, control_id')
        matches=store.rows('''SELECT v.finding_id AS vuln_id,c.finding_id AS compliance_id,v.asset_id
          FROM findings v JOIN findings c ON v.asset_id=c.asset_id
          WHERE v.kind='vulnerability' AND c.kind='compliance'
          AND lower(v.software_family)=lower(?) AND c.control_id=?
          AND upper(v.status) IN ('OPEN','ACTIVE','REOPENED','NEW')
          AND upper(c.status) IN ('FAIL','FAILED','NON_COMPLIANT')''',
          (rule['software_family'],rule['control_id']))
        for row in matches:
            cid=digest([row['vuln_id'],row['compliance_id'],rule['id']])[:24]
            store.db.execute('INSERT OR REPLACE INTO correlations VALUES (?,?,?,?,?,?)',
               (cid,row['asset_id'],row['vuln_id'],row['compliance_id'],rule['id'],str(rule.get('rationale','Related failed control on the same asset'))))
            created+=1
    store.commit()
    return {'correlations':created,'rules_checked':len(rules),'cross_asset_paths_validated':0}


def get_asset_exposure(store, asset_id, limit=100):
    limit=max(1,min(int(limit),200))
    asset=store.rows('SELECT * FROM assets WHERE asset_id=?',(asset_id,))
    cmdb=store.rows('SELECT * FROM cmdb WHERE asset_id=? AND verified=1',(asset_id,))
    findings=store.rows('SELECT finding_id,kind,title,severity,vpr,status,control_id,software_family,source_hash FROM findings WHERE asset_id=? ORDER BY kind,finding_id LIMIT ?', (asset_id,limit))
    links=store.rows('SELECT correlation_id,vuln_id,compliance_id,rule_id,rationale FROM correlations WHERE asset_id=? LIMIT ?', (asset_id,limit))
    return {'asset':asset[0] if asset else None,'cmdb':cmdb,'findings':findings,'correlations':links,
            'cross_asset_attack_path':'unverified - topology/reachability evidence not provided'}

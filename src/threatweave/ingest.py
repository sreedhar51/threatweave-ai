"""Vendor-aware, bounded ingestion. Imported data is evidence, never agent instructions."""
import csv
import io
import json
from datetime import datetime, timezone
from pathlib import Path
from .utils import canonical, digest, numeric
from .software import classify_family


def get(obj, *paths):
    for path in paths:
        current = obj
        for part in path.split('.'):
            if isinstance(current, dict):
                current = current.get(part)
            else:
                current = None
                break
        if current is not None and current != '':
            return current
    return None


def tags(raw):
    if not raw:
        return []
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, list): return [str(x) for x in parsed]
        except (ValueError, TypeError):
            pass
        return [x.strip() for x in raw.split(';') if x.strip()]
    if isinstance(raw, dict):
        return [f"{k}:{v}" for k,v in raw.items()]
    if isinstance(raw, list):
        return [str(x.get('value',x.get('tag',''))) if isinstance(x,dict) else str(x) for x in raw]
    return []


def record_asset(record, source="tenable"):
    uid=get(record,'uuid','asset.uuid','asset_id','asset_uuid','id')
    if not uid: raise ValueError('Asset UUID is required; refusing fuzzy identity matching')
    hostname=get(record,'hostname','hostnames','fqdn','fqdns','name')
    if isinstance(hostname,list): hostname=hostname[0] if hostname else None
    os_name=get(record,'operating_system','operating_systems','os','os_name')
    if isinstance(os_name,list): os_name=os_name[0] if os_name else None
    asset_type=get(record,'asset_type','type')
    if not asset_type or str(asset_type).lower() in {'host','generic','unknown'}:
        s=str(os_name or '').lower()
        asset_type='server' if 'server' in s else 'workstation' if ('windows 10' in s or 'windows 11' in s or 'macos' in s) else 'unknown'
    return {'asset_id':str(uid),'hostname':hostname,'os':str(os_name) if os_name else None,
            'asset_type':str(asset_type).lower(),'environment':get(record,'environment'),
            'role':get(record,'role'),'tags':tags(get(record,'tags','resource_tags')),
            'source':source,'raw_hash':digest(record),'last_seen':get(record,'last_seen','last_seen_at')}


def record_finding(record, kind='vulnerability', source='tenable'):
    kind = 'compliance' if kind in {'compliance','cis'} else 'vulnerability'
    asset_id=get(record,'asset.uuid','asset.id','asset_uuid','asset_id','tenable_asset_uuid')
    if not asset_id: raise ValueError('Finding missing authoritative Tenable asset UUID')
    plugin_id=get(record,'plugin.id','plugin_id')
    port=get(record,'port.port','port')
    proto=get(record,'port.protocol','protocol')
    if isinstance(port,dict): port=port.get('port')
    if isinstance(proto,dict): proto=proto.get('protocol')
    port=str(port if port is not None else '0')
    proto=str(proto or 'unknown').lower()
    control_id=get(record,'compliance_full_id','control_id','check_id')
    audit_file=get(record,'audit_file','audit.file','benchmark')
    if kind=='vulnerability':
        if plugin_id is None: raise ValueError('Vulnerability missing plugin ID')
        raw_key=f"vuln:{source}:{asset_id}:{plugin_id}:{port}:{proto}"
    else:
        if not control_id or not audit_file: raise ValueError('Compliance finding requires control ID and audit file')
        raw_key=f"cis:{source}:{asset_id}:{control_id}:{audit_file}"
    cves=get(record,'plugin.cve','cves','cve') or []
    if isinstance(cves,str): cves=[x.strip() for x in cves.replace(';',',').split(',') if x.strip()]
    severity=str(get(record,'severity','plugin.severity') or ('medium' if kind=='compliance' else 'info')).lower()
    status=str(get(record,'status','state','compliance_result') or ('FAIL' if kind=='compliance' else 'OPEN')).upper()
    vpr=numeric(get(record,'plugin.vpr','vpr'))
    solution=get(record,'plugin.solution','solution','remediation')
    title=get(record,'plugin.name','check_name','title','name','control_title') or str(control_id or plugin_id)
    output=get(record,'output','plugin_output','evidence') or ''
    # Only a bounded excerpt is stored; source record hashes preserve import provenance.
    excerpt=str(output)[:1200]
    return {'finding_id':digest(raw_key)[:24], 'asset_id':str(asset_id), 'kind':kind,
            'source':source,'title':str(title),'severity':severity,'vpr':vpr,
            'plugin_id':str(plugin_id) if plugin_id is not None else None,
            'port':port,'protocol':proto,'cves':cves,'status':status,
            'observed_at':get(record,'scan.last_found','scan.last_seen','last_found','last_seen','observed_at'),
            'solution':str(solution) if solution else None,
            'software_family':(get(record,'software_family')
                               or (classify_family(record) if kind=='vulnerability' else None)),
            'control_id':str(control_id) if control_id else None,
            'expected_value':get(record,'expected_value','expected'),
            'actual_value':get(record,'actual_value','actual'),
            'audit_file':str(audit_file) if audit_file else None,
            'source_hash':digest(record),'source_excerpt':excerpt}


def record_cmdb(record):
    ci_id=get(record,'ci_sys_id','sys_id','ci_id')
    if not ci_id: raise ValueError('CMDB record missing CI sys_id')
    asset_id=get(record,'tenable_asset_uuid','asset_uuid','asset_id')
    verified=bool(asset_id and str(get(record,'mapping_verified','verified','match_status') or '').lower() in {'true','1','verified','yes'})
    if not verified: asset_id=None
    return {'ci_id':str(ci_id),'asset_id':str(asset_id) if asset_id else None,
            'verified':int(verified),'business_service':get(record,'business_service'),
            'criticality':get(record,'business_criticality','criticality'),
            'environment':get(record,'environment'),'role':get(record,'role'),
            'support_group':get(record,'support_group'),
            'business_tags':tags(get(record,'business_tags','tags')),
            'internet_exposure':get(record,'internet_exposure'),
            'observed_at':get(record,'last_updated','sys_updated_on','observed_at'),
            'source_hash':digest(record)}


def iter_records(filename):
    """CSV, JSON array/object, or streaming JSONL. JSON arrays currently load in memory."""
    path=Path(filename)
    if path.suffix.lower()=='.csv':
        with path.open(newline='',encoding='utf-8-sig') as f:
            yield from csv.DictReader(f)
    elif path.suffix.lower() in {'.jsonl','.ndjson'}:
        with path.open(encoding='utf8') as f:
            for line in f:
                if line.strip(): yield json.loads(line)
    elif path.suffix.lower()=='.json':
        with path.open(encoding='utf8') as f:
            value=json.load(f)
        if isinstance(value,list): yield from value
        elif isinstance(value,dict):
            payload=value.get('records') or value.get('data') or value.get('findings')
            if isinstance(payload,list): yield from payload
            else: yield value
        else: raise ValueError('JSON must contain objects')
    else:
        raise ValueError('Supported formats: .csv, .json, .jsonl, .ndjson')


def ingest_records(store, records, record_type, provider='tenable', max_rejections=30):
    if record_type not in {'asset','vulnerability','compliance','cmdb'}:
        raise ValueError('Unsupported record type')
    started_at=datetime.now(timezone.utc).isoformat()
    total=accepted=0
    errors=[]
    for record in records:
        total+=1
        try:
            if not isinstance(record,dict): raise ValueError('Expected object record')
            if record_type=='asset':
                store.upsert_asset(record_asset(record,provider))
            elif record_type=='cmdb':
                r=record_cmdb(record)
                # Verified mapping must reference an actual Tenable asset; no fuzzy merge.
                if r['asset_id'] and not store.db.execute('SELECT 1 FROM assets WHERE asset_id=?',(r['asset_id'],)).fetchone():
                    r['asset_id']=None
                    r['verified']=0
                store.upsert_cmdb(r)
            else:
                r=record_finding(record,record_type,provider)
                # If no asset export exists yet, create a placeholder with UUID only.
                if not store.db.execute('SELECT 1 FROM assets WHERE asset_id=?',(r['asset_id'],)).fetchone():
                    store.upsert_asset({'asset_id':r['asset_id'],'source':provider,'raw_hash':digest({'asset_id':r['asset_id']})})
                store.upsert_finding(r)
            accepted+=1
        except (ValueError,TypeError,KeyError) as exc:
            if len(errors)<max_rejections:
                errors.append({'record_number':total,'reason':str(exc)})
        if total%1000==0: store.commit()
    store.commit()
    report={'provider':provider,'record_type':record_type,'received':total,'accepted':accepted,
            'rejected':total-accepted,'errors':errors}
    store.record_ingest_run(provider,record_type,report,started_at)
    return report


def ingest_file(store, filename, record_type, provider='tenable'):
    return ingest_records(store,iter_records(filename),record_type,provider)

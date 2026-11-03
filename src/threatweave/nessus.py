"""Streaming, read-only Nessus v2 XML import with explicit DTD/entity rejection.

ReportHost UUID is authoritative when present. We never use an IP address for
identity; IP-only report hosts receive a distinct file-local unknown host ID.
"""
import ipaddress
import re
import xml.etree.ElementTree as ET
from collections import Counter
from pathlib import Path
from .compliance_tags import compliance_status
from .ingest import ingest_records

_BAD_DECLARATION = re.compile(rb'<!\s*(DOCTYPE|ENTITY)\b', re.I)
_SEVERITIES = {'0':'info', '1':'low', '2':'medium', '3':'high', '4':'critical'}


def _tag(element):
    return element.tag.rsplit('}',1)[-1].lower()


def _is_ip(value):
    try:
        ipaddress.ip_address(str(value).strip().strip('[]'))
        return True
    except ValueError:
        return False


def reject_xml_declarations(path):
    """Reject DTDs/entities before parsing, scanning in bounded chunks."""
    tail=b''
    with Path(path).open('rb') as f:
        while chunk := f.read(65536):
            data=tail+chunk
            if _BAD_DECLARATION.search(data):
                raise ValueError('Unsafe .nessus XML: DOCTYPE/ENTITY declarations are prohibited')
            tail=data[-32:]


def _properties(host_properties):
    fields={}
    for child in host_properties:
        if _tag(child)=='tag':
            name=str(child.attrib.get('name','')).lower()
            if name:
                fields[name]=(child.text or '').strip()
    return fields


def _host_asset(report_name, fields, index, seen):
    uuid=fields.get('host-uuid') or fields.get('host_uuid')
    fqdn=fields.get('host-fqdn') or fields.get('fqdn') or fields.get('hostname')
    candidate=(fqdn or report_name or '').strip()
    if uuid:
        asset_id=uuid
    elif candidate and not _is_ip(candidate):
        asset_id='nessus:'+candidate.casefold()
        # Two ReportHost entries with the same name are not trusted to be the same host.
        if asset_id in seen:
            asset_id=f'{asset_id}~report-{index}'
    else:
        asset_id=f'nessus:unknown-report-host-{index}'
    seen.add(asset_id)
    return {'uuid':asset_id,
            'hostname': candidate if candidate and not _is_ip(candidate) else None,
            'operating_system':fields.get('operating-system') or fields.get('os'),
            'last_seen':fields.get('host_end')}


def _cm_item(item):
    out={}
    for child in item:
        local=_tag(child)
        if local.startswith('compliance-'):
            out[local]=(child.text or '').strip()
    return out


def _finding_record(item, asset_id):
    attrs=item.attrib
    plugin_id=str(attrs.get('pluginID') or attrs.get('pluginId') or '')
    if not plugin_id:
        return None
    meta=_cm_item(item)
    check_name=meta.get('compliance-check-name') or attrs.get('pluginName') or plugin_id
    result=meta.get('compliance-result')
    if result:
        check_id=meta.get('compliance-check-id') or check_name
        audit_file=meta.get('compliance-audit-file') or 'unknown-audit-file'
        return ('compliance', {
            'asset_uuid':asset_id, 'compliance_full_id':check_id,
            'audit_file':audit_file,'title':check_name,
            'status':compliance_status(result),
            'actual_value':meta.get('compliance-actual-value'),
            'expected_value':meta.get('compliance-policy-value'),
            'output':meta.get('compliance-output') or meta.get('compliance-info') or '',
        })
    severity=str(attrs.get('severity','0'))
    if severity=='0':
        return None
    texts={_tag(child):child.text for child in item if _tag(child) in
           {'solution','plugin_output','synopsis','cpe','cve','description'}}
    return ('vulnerability', {
        'asset_uuid':asset_id,
        'plugin':{'id':plugin_id,'name':attrs.get('pluginName') or plugin_id,
                  'solution':texts.get('solution'),'cpe':texts.get('cpe'),
                  'cve':[c.text for c in item if _tag(c)=='cve' and c.text]},
        'port':{'port':attrs.get('port') or '0','protocol':attrs.get('protocol') or 'unknown'},
        'severity':_SEVERITIES.get(severity, severity),
        'status':'OPEN','output':texts.get('plugin_output') or '',
    })


def iter_nessus_records(path):
    """Yield (record_type, record) in document order with per-item XML clearing."""
    reject_xml_declarations(path)
    seen=set()
    host=None
    index=0
    for event, elem in ET.iterparse(str(path), events=('start','end')):
        local=_tag(elem)
        if event=='start' and local=='reporthost':
            index+=1
            host={'name':elem.attrib.get('name',''),'fields':{},'asset':None}
        elif event=='end' and local=='hostproperties' and host is not None:
            host['fields'].update(_properties(elem))
            host['asset']=_host_asset(host['name'],host['fields'],index,seen)
            yield ('asset',host['asset'])
            elem.clear()
        elif event=='end' and local=='reportitem' and host is not None:
            if host['asset'] is None:
                host['asset']=_host_asset(host['name'],host['fields'],index,seen)
                yield ('asset',host['asset'])
            record=_finding_record(elem,host['asset']['uuid'])
            if record:
                yield record
            elem.clear()
        elif event=='end' and local=='reporthost':
            if host is not None and host['asset'] is None:
                host['asset']=_host_asset(host['name'],host['fields'],index,seen)
                yield ('asset',host['asset'])
            host=None
            elem.clear()


def import_nessus(store, path, batch_size=1000):
    """Batched ingest through existing normalized record path; no entire XML in RAM."""
    buckets={'asset':[], 'vulnerability':[], 'compliance':[]}
    totals={kind:Counter() for kind in buckets}
    rejections=[]
    def flush(kind):
        batch=buckets[kind]
        if not batch:
            return
        result=ingest_records(store,batch,kind,'nessus-export')
        totals[kind].update({k:result[k] for k in ('received','accepted','rejected')})
        rejections.extend(result['errors'][:max(0,20-len(rejections))])
        batch.clear()
    for kind,record in iter_nessus_records(path):
        buckets[kind].append(record)
        if len(buckets[kind])>=batch_size:
            flush(kind)
    for kind in buckets:
        flush(kind)
    return {'provider':'nessus-export','read_only':True,'by_type':dict(totals),
            'accepted':sum(x['accepted'] for x in totals.values()),
            'rejected':sum(x['rejected'] for x in totals.values()),
            'errors':rejections,
            'identity_rule':'host UUID or name; never IP',
            'scan_hygiene':store.overview().get('compliance_status_counts',{})}

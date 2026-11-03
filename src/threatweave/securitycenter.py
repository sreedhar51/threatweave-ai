"""Optional read-only Tenable Security Center synchronous analysis collector.

Requires authorized keys and tenant validation. The API POST is a query only;
no writes, scans, recasts, or risk acceptances are performed. Unlike VM bulk
exports, this source is paginated and can load the on-prem console heavily.
"""
import hashlib
import json
import os
import time
from urllib.parse import urlparse
import httpx
from .compliance_tags import extract_compliance_tags, compliance_status
from .ingest import ingest_records

_LEVELS={'0':'info','1':'low','2':'medium','3':'high','4':'critical'}


class SecurityCenterClient:
    def __init__(self, base_url, access_key=None, secret_key=None,
                 transport=None, timeout=45, ca_bundle=None):
        parsed=urlparse(str(base_url))
        if parsed.scheme!='https' or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError('Security Center URL must be a bare HTTPS host')
        ak=access_key or os.getenv('SC_ACCESS_KEY')
        sk=secret_key or os.getenv('SC_SECRET_KEY')
        if not ak or not sk:
            raise ValueError('Authorized Security Center API keys are required')
        self.client=httpx.Client(base_url=base_url.rstrip('/'), transport=transport,
               timeout=timeout, verify=ca_bundle or True,
               headers={'x-apikey':f'accesskey={ak}; secretkey={sk};',
                        'Accept':'application/json', 'Content-Type':'application/json',
                        'User-Agent':'Integration/1.0 (ThreatWeave Contributors; ThreatWeave AI; Build/0.1.0)'})

    def close(self):
        self.client.close()

    def iter_analysis(self, *, page_size=500, max_pages=10, filters=None):
        """Yield bounded vulndetails rows; prevent accidental estate-scale exports."""
        page_size=int(page_size)
        max_pages=int(max_pages)
        if not 1<=page_size<=2000 or not 1<=max_pages<=1000:
            raise ValueError('Page size must be <=2000 and max_pages <=1000')
        query_filters=filters if filters is not None else [
            {'filterName':'severity','operator':'=','value':'1,2,3,4'},
            {'filterName':'wasVuln','operator':'=','value':'excludeWas'}]
        if not isinstance(query_filters,list):
            raise ValueError('Filters must be an explicit list')
        for page in range(max_pages):
            start=page*page_size
            body={'type':'vuln','sourceType':'cumulative',
                  'query':{'type':'vuln','tool':'vulndetails','filters':query_filters,
                           'startOffset':start,'endOffset':start+page_size}}
            # Serial bounded retries. Do not parallelize Security Center analysis.
            for attempt in range(3):
                response=self.client.post('/rest/analysis',json=body)
                if response.status_code not in (429,502,503,504):
                    break
                if attempt < 2:
                    retry_after=response.headers.get('Retry-After', '')
                    delay=min(5, int(retry_after)) if retry_after.isdigit() else 2**attempt
                    time.sleep(delay)
            response.raise_for_status()
            payload=response.json()
            if payload.get('error_code') not in (None,0,'0'):
                raise RuntimeError('Security Center analysis reported an error')
            data=payload.get('response',payload)
            rows=data.get('results',[]) if isinstance(data,dict) else []
            if not isinstance(rows,list):
                raise ValueError('Unexpected Security Center results response')
            for row in rows:
                if isinstance(row,dict):
                    yield row
            if not rows or len(rows)<page_size:
                return
            total=data.get('totalRecords') or data.get('totalRecordsCount')
            if total is not None and start+len(rows)>=int(total):
                return


def _repository_id(raw):
    repo=raw.get('repository') or {}
    return str(raw.get('repositoryId') or raw.get('repositoryID') or
               (repo.get('id') if isinstance(repo,dict) else repo) or 'unknown')


def _asset_id(raw):
    host=str(raw.get('hostUUID') or raw.get('hostUuid') or '').strip()
    if host:
        return host
    # IP may appear in the raw SC record but NEVER participates in asset identity.
    # The per-finding opaque placeholder prevents cross-host or cross-source merges.
    repo=_repository_id(raw)
    ident=str(raw.get('vulnUUID') or raw.get('vulnUuid') or '')
    if not ident:
        stable={k:raw.get(k) for k in ('pluginID','pluginId','port','protocol',
                                     'firstSeen','lastSeen','pluginText','dnsName')}
        ident=json.dumps(stable,sort_keys=True,default=str)
    key=hashlib.sha256((repo+'\0'+ident).encode('utf-8')).hexdigest()[:20]
    return f'sc-unresolved-{repo}-{key}'


def normalize_sc_record(raw):
    """Return normalized (kind, raw ingestion record) pairs, plus a source asset."""
    asset_id=_asset_id(raw)
    name=str(raw.get('dnsName') or raw.get('netbiosName') or '').strip()
    asset={'uuid':asset_id,'hostname':name or None,
           'operating_system':raw.get('operatingSystem') or None,
           'last_seen':raw.get('lastSeen') or None}
    plugin_id=raw.get('pluginID') or raw.get('pluginId') or raw.get('pluginIDString')
    if plugin_id in (None,''):
        return [('asset',asset)]
    common={'asset_uuid':asset_id, 'plugin_id':str(plugin_id),
            'port':raw.get('port') or '0', 'protocol':raw.get('protocol') or 'unknown',
            'title':raw.get('pluginName') or raw.get('pluginInfo') or str(plugin_id),
            'output':raw.get('pluginText') or '',
            'severity':_LEVELS.get(str(raw.get('severity') or '0'),str(raw.get('severity') or 'info').lower()),
            'status':'OPEN','solution':raw.get('solution') or None,
            'observed_at':raw.get('lastSeen') or None}
    tags=extract_compliance_tags(raw.get('pluginText') or '')
    if tags.get('compliance-result'):
        result={'asset_uuid':asset_id,
                'compliance_full_id':tags.get('compliance-check-id') or tags.get('compliance-check-name')
                                      or f'sc-plugin-{plugin_id}',
                'audit_file':tags.get('compliance-audit-file') or 'unknown-audit-file',
                'title':tags.get('compliance-check-name') or common['title'],
                'status':compliance_status(tags.get('compliance-result')),
                'expected_value':tags.get('compliance-policy-value'),
                'actual_value':tags.get('compliance-actual-value'),
                'observed_at':common['observed_at'],
                'output':tags.get('compliance-info') or ''}
        return [('asset',asset),('compliance',result)]
    return [('asset',asset),('vulnerability',common)]


def ingest_securitycenter(store, client, *, page_size=500, max_pages=10, filters=None):
    """Batch normalizations through the existing ingestion contract."""
    counters={kind:{'received':0,'accepted':0,'rejected':0} for kind in ('asset','vulnerability','compliance')}
    errors=[]
    batches={kind:[] for kind in counters}
    def flush(kind):
        if not batches[kind]:
            return
        result=ingest_records(store,batches[kind],kind,'securitycenter-export')
        for field in ('received','accepted','rejected'):
            counters[kind][field]+=result[field]
        errors.extend(result['errors'][:max(0,20-len(errors))])
        batches[kind].clear()
    for raw in client.iter_analysis(page_size=page_size,max_pages=max_pages,filters=filters):
        for kind,record in normalize_sc_record(raw):
            batches[kind].append(record)
            if len(batches[kind])>=500:
                flush(kind)
    for kind in counters:
        flush(kind)
    return {'provider':'securitycenter-export','read_only':True,
            'by_type':counters,'errors':errors,
            'identity_note':'hostUUID preferred; missing hostUUID remains a per-record unresolved identity, NEVER matched by IP',
            'tenant_validation':'required'}

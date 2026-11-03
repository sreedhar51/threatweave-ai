#!/usr/bin/env python3
"""Credential-safe, read-only Tenable tenant preflight.

Run locally after rotating the exposed credentials. Environment variables only.
Default action performs GET /assets and GET /workbenches/vulnerabilities (no exports or raw asset output).
Optional compliance probe starts a scoped export for one existing asset UUID and
reports only aggregate statuses; it does not persist records.
"""
import argparse
import collections
import json
import os
import sys
import time

import httpx
from threatweave.tenable import TenableExportClient
from threatweave.ingest import record_asset, record_finding


def summarize_assets(payload):
    records=payload.get('assets', []) if isinstance(payload, dict) else []
    if not isinstance(records,list):
        raise ValueError('Unexpected /assets response: assets is not a list')
    normalized=[]
    for item in records:
        try:
            normalized.append(record_asset(item))
        except (ValueError,KeyError,TypeError):
            pass
    return {
        'visible_assets_returned': len(records),
        'reported_total': payload.get('total') if isinstance(payload,dict) else None,
        'normalized_assets': len(normalized),
        'with_os': sum(bool(a['os']) for a in normalized),
        'with_hostname': sum(bool(a['hostname']) for a in normalized),
        'asset_types': dict(sorted(collections.Counter(a['asset_type'] for a in normalized).items())),
        'note': 'GET /assets is limited to 5000; this is not a full inventory export.'
    }


def summarize_workbench_vulnerabilities(payload):
    records=payload.get('vulnerabilities',[]) if isinstance(payload,dict) else []
    if not isinstance(records,list):
        raise ValueError('Unexpected workbench response: vulnerabilities is not a list')
    severity_map={0:'info',1:'low',2:'medium',3:'high',4:'critical'}
    severities=collections.Counter(severity_map.get(r.get('severity'),'unknown') for r in records)
    return {
        'distinct_plugins_returned':len(records),
        'reported_vulnerability_count':payload.get('total_vulnerability_count'),
        'severity_distribution_by_plugin':dict(sorted(severities.items())),
        'with_vpr':sum(r.get('vpr_score') is not None for r in records),
        'note':'Workbench aggregates by plugin, not asset-level vulnerability instances; it cannot establish CIS correlations.'
    }


def probe_compliance(client, asset_id, max_wait=60):
    """A single-asset export, bounded to at most 5 chunks, with no raw-data output."""
    counts=collections.Counter()
    accepted=0
    job=client.start_export('compliance', {'asset':[asset_id], 'num_findings':50})
    path=f'/compliance/export/{job}'
    downloaded=set()
    started=time.monotonic()
    while time.monotonic()-started < max_wait:
        status=client.request('GET', path+'/status').json()
        state=str(status.get('status','')).upper()
        if state in ('ERROR','CANCELLED'):
            raise RuntimeError('Compliance export did not finish: '+state)
        for chunk in status.get('chunks_available',[]) or []:
            if chunk in downloaded:continue
            if len(downloaded)>=5:
                return {'result':'partial: more than 5 chunks','findings_checked':accepted,'statuses':dict(counts)}
            response=client.request('GET',path+'/chunks/'+str(chunk))
            data=response.json()
            if not isinstance(data,list):
                raise ValueError('Unexpected compliance chunk payload')
            for record in data:
                try:
                    found=record_finding(record,'compliance')
                    counts[found['status']]+=1
                    accepted+=1
                except (TypeError,ValueError,KeyError):
                    counts['UNMAPPED']+=1
            downloaded.add(chunk)
        if state=='FINISHED':
            return {'result':'completed', 'findings_checked':accepted,'statuses':dict(sorted(counts.items())),
                    'correlation_note':'A matching vulnerability and validated CIS rule are still required.'}
        time.sleep(3)
    return {'result':'timed out polling; no writes performed','findings_checked':accepted,'statuses':dict(counts)}


def preflight(client, with_compliance=False):
    response=client.request('GET','/assets')
    payload=response.json()
    result={'tenant':'Tenable VM','connection':'authenticated','assets':summarize_assets(payload)}
    try:
        workbench=client.request('GET','/workbenches/vulnerabilities')
        result['vulnerabilities']=summarize_workbench_vulnerabilities(workbench.json())
    except httpx.HTTPStatusError as exc:
        result['vulnerabilities']={'status':'unavailable','http_status':exc.response.status_code}
    if with_compliance:
        assets=payload.get('assets', [])
        first=next((a.get('id') or a.get('uuid') for a in assets if a.get('id') or a.get('uuid')),None)
        result['compliance']=(probe_compliance(client,first) if first else
                              {'result':'not tested: no visible assets'})
    return result


def main(argv=None):
    parser=argparse.ArgumentParser(description='Read-only Tenable preflight; never prints raw data or credentials')
    parser.add_argument('--check-compliance',action='store_true',help='Probe one visible asset; initiates a scoped compliance export')
    args=parser.parse_args(argv)
    if not (os.getenv('TENABLE_ACCESS_KEY') and os.getenv('TENABLE_SECRET_KEY')):
        print(json.dumps({'connection':'not tested','reason':'Set rotated TENABLE_ACCESS_KEY and TENABLE_SECRET_KEY in your local environment'}))
        return 2
    try:
        client=TenableExportClient()
        try:
            result=preflight(client,args.check_compliance)
        finally:client.close()
        print(json.dumps(result,indent=2))
        return 0
    except httpx.HTTPStatusError as exc:
        code=exc.response.status_code
        reason='invalid/expired credentials' if code==401 else ('insufficient API permission' if code==403 else 'API request rejected')
        print(json.dumps({'connection':'failed','status_code':code,'reason':reason}))
        return 1
    except (httpx.RequestError,ValueError,RuntimeError) as exc:
        # Do not log exception strings: network libraries can include user secrets.
        print(json.dumps({'connection':'failed','reason':type(exc).__name__,
                          'suggestion':'Check network access, tenant permissions, and export availability locally'}))
        return 1


if __name__=='__main__':
    sys.exit(main())

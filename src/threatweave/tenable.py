"""Read-only Tenable Vulnerability Management asynchronous export client.

API calls are limited to documented export endpoints. Requires authorized tenant
credentials. No scanning, recast, accept-risk or remediation writes.
"""
import json
import os
import time
from urllib.parse import urlparse
import httpx
from .ingest import ingest_records

EXPORTS={
 'asset':('/assets/v2/export','/assets/export'),
 'vulnerability':('/vulns/export','/vulns/export'),
 'compliance':('/compliance/export','/compliance/export'),
}

class TenableExportClient:
    def __init__(self,access_key=None,secret_key=None,base_url=None,transport=None,
                 timeout=45):
        ak=access_key or os.getenv('TENABLE_ACCESS_KEY')
        sk=secret_key or os.getenv('TENABLE_SECRET_KEY')
        if not ak or not sk: raise ValueError('Tenable access and secret keys required')
        base=(base_url or os.getenv('TENABLE_BASE_URL','https://cloud.tenable.com')).rstrip('/')
        parsed=urlparse(base)
        if parsed.scheme!='https' or not parsed.hostname:
            raise ValueError('Tenable API URL must be HTTPS')
        # Explicit tenant hosts only; prevent arbitrary endpoints in normal execution.
        if transport is None and not (parsed.hostname=='cloud.tenable.com' or parsed.hostname.endswith('.tenable.com')):
            raise ValueError('Only Tenable-hosted API URLs are supported')
        self.client=httpx.Client(base_url=base,transport=transport,timeout=timeout,headers={
             'X-ApiKeys':f'accessKey={ak}; secretKey={sk}',
             'Accept':'application/json','Content-Type':'application/json',
             'User-Agent':'Integration/1.0 (ThreatWeave Contributors; ThreatWeave AI; Build/0.1.0)'})

    def close(self): self.client.close()

    def request(self, method, path, **kwargs):
        for attempt in range(5):
            response=self.client.request(method,path,**kwargs)
            if response.status_code not in (429,500,502,503,504):
                response.raise_for_status()
                return response
            if attempt==4: response.raise_for_status()
            wait=min(10,2**attempt)
            if response.headers.get('Retry-After','').isdigit():
                wait=min(10,int(response.headers['Retry-After']))
            time.sleep(wait)

    def start_export(self,kind,body=None):
        if kind not in EXPORTS: raise ValueError('Unsupported export kind')
        start_prefix=EXPORTS[kind][0]
        if body is None:
            body={'chunk_size':4000} if kind=='asset' else {}
        if not isinstance(body,dict): raise ValueError('Export body must be a JSON object')
        result=self.request('POST',start_prefix,json=body).json()
        export_id=result.get('export_uuid') or result.get('uuid')
        if not export_id: raise RuntimeError('Export did not return export UUID')
        return str(export_id)

    def fetch_export(self,kind,body=None,poll_seconds=3,max_wait_seconds=900,max_chunks=1000):
        if kind not in EXPORTS: raise ValueError('Unsupported export kind')
        job=self.start_export(kind,body)
        prefix=EXPORTS[kind][1]
        downloaded=set()
        start=time.monotonic()
        while True:
            state=self.request('GET',f'{prefix}/{job}/status').json()
            status=str(state.get('status','')).upper()
            if status in {'ERROR','FAILED','CANCELLED'}:
                raise RuntimeError(f'Export stopped with state {status}')
            available=state.get('chunks_available',[]) or []
            # Chunk IDs are not guaranteed to be consecutive or sorted.
            for chunk in sorted({int(c) for c in available}-downloaded):
                if len(downloaded)>=max_chunks: raise RuntimeError('Maximum allowed chunks exceeded')
                response=self.request('GET',f'{prefix}/{job}/chunks/{chunk}')
                body=response.content.decode('utf-8-sig')
                try:
                    parsed=json.loads(body)
                    if isinstance(parsed,list):
                        for item in parsed: yield item
                    elif isinstance(parsed,dict):
                        if isinstance(parsed.get('records'),list):
                            yield from parsed['records']
                        else: yield parsed
                    else: raise RuntimeError('Unexpected chunk JSON structure')
                except json.JSONDecodeError:
                    for line in body.splitlines():
                        if line.strip(): yield json.loads(line)
                downloaded.add(chunk)
            if status=='FINISHED':
                failed=state.get('chunks_failed') or []
                if failed: raise RuntimeError(f'Export reported failed chunks: {failed}')
                return
            if time.monotonic()-start>max_wait_seconds:
                raise TimeoutError('Timed out polling Tenable export; retry with a smaller scope')
            time.sleep(poll_seconds)

    def ingest(self,store,kind,body=None,**kwargs):
        return ingest_records(store,self.fetch_export(kind,body,**kwargs),kind,provider='tenable')

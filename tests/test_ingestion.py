import csv
import json
import httpx
import pytest
from threatweave.store import Store
from threatweave.ingest import ingest_file,ingest_records,record_finding
from threatweave.tenable import TenableExportClient


def test_csv_generic_asset_import(tmp_path):
    file=tmp_path/'assets.csv'
    with file.open('w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=['uuid','hostname','operating_system','asset_type'])
        w.writeheader();w.writerow({'uuid':'v-1','hostname':'unit-01','operating_system':'Windows 11','asset_type':'workstation'})
    s=Store(tmp_path/'db.db')
    try:
        result=ingest_file(s,file,'asset')
        assert result['accepted']==1
        assert s.count('assets')==1
    finally:s.close()


def test_ndjson_compliance_import(tmp_path):
    file=tmp_path/'compliance.jsonl'
    file.write_text(json.dumps({'asset_uuid':'x-1','compliance_full_id':'check-1','audit_file':'baseline.audit','status':'FAIL'})+'\n')
    s=Store(tmp_path/'db.db')
    try:
        result=ingest_file(s,file,'compliance')
        assert result['accepted']==1
        assert s.count('findings')==1
    finally:s.close()


def test_vuln_id_includes_port_protocol():
    base={'asset':{'uuid':'host1'},'plugin':{'id':100},'port':{'port':22,'protocol':'tcp'}}
    changed={'asset':{'uuid':'host1'},'plugin':{'id':100},'port':{'port':443,'protocol':'tcp'}}
    assert record_finding(base)['finding_id']!=record_finding(changed)['finding_id']


def test_compliance_id_includes_audit_file():
    a={'asset_uuid':'a','compliance_full_id':'control-1','audit_file':'v1.audit'}
    b={'asset_uuid':'a','compliance_full_id':'control-1','audit_file':'v2.audit'}
    assert record_finding(a,'compliance')['finding_id']!=record_finding(b,'compliance')['finding_id']


def test_missing_identity_rejected(tmp_path):
    s=Store(tmp_path/'bad.db')
    try:
        result=ingest_records(s,[{'plugin':{'id':'123'}}],'vulnerability')
        assert result['rejected']==1
        assert s.count('findings')==0
    finally:s.close()


def test_tenable_export_client_mocked_async_chunks():
    paths=[]
    def handler(request):
        paths.append((request.method,request.url.path))
        if request.method=='POST':
            return httpx.Response(200,json={'export_uuid':'fake-export'})
        if request.url.path.endswith('/status'):
            return httpx.Response(200,json={'status':'FINISHED','chunks_available':[7,2]})
        if request.url.path.endswith('/chunks/2'):
            return httpx.Response(200,json=[{'uuid':'asset-2','hostname':'two'}])
        if request.url.path.endswith('/chunks/7'):
            return httpx.Response(200,json=[{'uuid':'asset-7','hostname':'seven'}])
        return httpx.Response(404)
    c=TenableExportClient('dummy','dummy',transport=httpx.MockTransport(handler))
    try:
        records=list(c.fetch_export('asset',max_wait_seconds=1))
        assert [r['uuid'] for r in records]==['asset-2','asset-7']
        assert paths[0]==('POST','/assets/v2/export')
        assert ('GET','/assets/export/fake-export/status') in paths
    finally:c.close()


def test_tenable_client_rejects_non_https():
    with pytest.raises(ValueError):TenableExportClient('a','b',base_url='http://evil.example')

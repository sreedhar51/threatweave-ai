import httpx
from threatweave.ingest import record_finding
from threatweave.tenable import TenableExportClient
import importlib.util
from pathlib import Path
spec = importlib.util.spec_from_file_location("tenant_preflight", Path(__file__).resolve().parents[1] / "scripts/tenant_preflight.py")
preflight_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(preflight_module)
summarize_assets = preflight_module.summarize_assets
preflight = preflight_module.preflight
probe_compliance = preflight_module.probe_compliance
summarize_workbench_vulnerabilities = preflight_module.summarize_workbench_vulnerabilities


def test_tenable_documented_v2_asset_shape():
    doc={'id':'test-asset','hostname':['srv-a'],'operating_system':['Windows Server 2022']}
    result=summarize_assets({'assets':[doc],'total':1})
    assert result['normalized_assets']==1
    assert result['with_os']==1
    assert result['with_hostname']==1


def test_compliance_check_name_and_asset_id_are_parsed():
    record={'asset':{'id':'test-a'},'compliance_full_id':'hash-1',
            'audit_file':'example.audit','check_name':'Ensure SSH access is limited',
            'status':'FAILED','actual_value':'bad'}
    finding=record_finding(record,'compliance')
    assert finding['asset_id']=='test-a'
    assert finding['title']=='Ensure SSH access is limited'
    assert finding['status']=='FAILED'


def test_preflight_uses_read_only_assets_get_and_hides_record_data():
    calls=[]
    def handler(request):
        calls.append((request.method,request.url.path))
        assert request.method=='GET'
        if request.url.path=='/assets':
            return httpx.Response(200,json={'assets':[{'id':'aaa','hostname':['sensitive-internal-name']}],'total':1})
        return httpx.Response(200,json={'vulnerabilities':[{'plugin_id':11,'severity':3,'vpr_score':8.1}],'total_vulnerability_count':1})
    client=TenableExportClient('fake','fake',transport=httpx.MockTransport(handler))
    try:
        result=preflight(client)
        assert result['connection']=='authenticated'
        assert calls==[('GET','/assets'),('GET','/workbenches/vulnerabilities')]
        assert result['vulnerabilities']['with_vpr']==1
        assert 'sensitive-internal-name' not in str(result)
    finally:client.close()


def test_bounded_compliance_probe_reports_status_and_does_not_persist():
    calls=[]
    def handler(request):
        calls.append((request.method,request.url.path))
        if request.method=='POST':
            assert request.url.path=='/compliance/export'
            import json
            assert json.loads(request.content)['asset']==['asset-1']
            return httpx.Response(200,json={'export_uuid':'job-one'})
        if request.url.path.endswith('/status'):
            return httpx.Response(200,json={'status':'FINISHED','chunks_available':[2]})
        return httpx.Response(200,json=[{'asset_uuid':'asset-1','compliance_full_id':'one','audit_file':'demo.audit','check_name':'Some check','status':'FAILED'}])
    client=TenableExportClient('fake','fake',transport=httpx.MockTransport(handler))
    try:
        result=probe_compliance(client,'asset-1')
        assert result['findings_checked']==1
        assert result['statuses']=={'FAILED':1}
        assert not any(path.startswith('/scans') for _,path in calls)
    finally:client.close()


def test_workbench_summary_exposes_aggregates_not_plugins():
    raw={'vulnerabilities':[{'plugin_id':123,'plugin_name':'Sensitive sample','severity':4,'vpr_score':7.2}],
         'total_vulnerability_count':1}
    summary=summarize_workbench_vulnerabilities(raw)
    assert summary['severity_distribution_by_plugin']=={'critical':1}
    assert 'Sensitive sample' not in str(summary)

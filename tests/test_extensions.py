"""Regression coverage for staged changes 1-9, all synthetic and read-only."""
import copy
import csv
import json
from pathlib import Path
import httpx
import pytest
from threatweave.store import Store
from threatweave.fixtures import STAGED_ASSETS, STAGED_VULNS, STAGED_CIS, STAGED_CMDB, generate
from threatweave.ingest import ingest_records, record_finding
from threatweave.nessus import import_nessus
from threatweave.securitycenter import SecurityCenterClient, ingest_securitycenter, normalize_sc_record
from threatweave.cmdb_map import propose_mappings
from threatweave.correlate import correlate, get_asset_exposure
from threatweave.policy import load_policy
from threatweave.engine import create_receipt, rank_groups
from threatweave.staged import run_staged_demo
from conftest import ROOT


def test_stage_replay_isolates_compliance_and_cmdb(tmp_path):
    result=run_staged_demo(tmp_path/'staged',n_assets=0)
    assert result['stage1_to_stage2']['evidence_changed']==['compliance','correlations']
    assert result['stage2_to_stage3']['evidence_changed']==['cmdb']
    hero=result['hero_fix_groups']
    first=hero['stage1_vulnerabilities']
    after_cis=hero['stage2_plus_cis']
    after_cmdb=hero['stage3_plus_cmdb']
    ssh=lambda groups: next(g for g in groups if 'OpenSSH' in g['label'])
    openssl=lambda groups: next(g for g in groups if 'OpenSSL' in g['label'])
    assert ssh(after_cis)['score'] > ssh(first)['score']
    assert ssh(after_cis)['compounded_assets_count']>ssh(first)['compounded_assets_count']
    assert openssl(after_cmdb)['score'] > openssl(after_cis)['score']
    assert openssl(after_cmdb)['rank'] < openssl(after_cis)['rank']


def test_ip_independence_of_ranking(tmp_path):
    policy=load_policy(ROOT/'policies/business-context.yaml')
    ranks=[]
    for mode in ('unique','shared'):
        s=Store(tmp_path/(mode+'.db'))
        try:
            assets=copy.deepcopy(STAGED_ASSETS)
            for a in assets:
                a['ipv4']='192.0.2.55' if mode=='shared' else '192.0.2.56'
            ingest_records(s,assets,'asset','synthetic')
            ingest_records(s,copy.deepcopy(STAGED_VULNS),'vulnerability','synthetic')
            ingest_records(s,copy.deepcopy(STAGED_CIS),'compliance','synthetic')
            ingest_records(s,copy.deepcopy(STAGED_CMDB),'cmdb','synthetic')
            correlate(s,ROOT/'policies/correlation-rules.yaml')
            ranks.append(create_receipt(s,policy)['rankings'])
        finally:s.close()
    assert ranks[0]==ranks[1]


def test_openssh_family_classifies_raw_tenable_metadata():
    raw={'asset':{'uuid':'fake-1'},'plugin':{'id':3100,'name':'Unrelated name',
         'cpe':'cpe:/a:openbsd:openssh:9.4','vpr':{'score':8.8}},
         'severity':'high','port':{'port':22,'protocol':'tcp'}}
    finding=record_finding(raw)
    assert finding['software_family']=='openssh'
    assert finding['severity']=='high'
    assert finding['vpr']==8.8


def test_cmdb_proposals_unique_and_unapproved(tmp_path):
    s=Store(tmp_path/'x.db')
    try:
        ingest_records(s,[
           {'uuid':'a','hostname':'prod-01.example.invalid'},
           {'uuid':'b','hostname':'qa-01'},
           {'uuid':'c','hostname':'qa-01'},
        ],'asset')
        file=tmp_path/'cmdb.csv'
        with file.open('w',newline='') as handle:
            writer=csv.DictWriter(handle,fieldnames=['sys_id','fqdn','hostname','ip_address'])
            writer.writeheader()
            writer.writerows([
               {'sys_id':'ci-a','fqdn':'PROD-01.EXAMPLE.INVALID','hostname':'any','ip_address':'192.0.2.12'},
               {'sys_id':'ci-b','fqdn':'','hostname':'qa-01','ip_address':'192.0.2.12'},
               {'sys_id':'ci-c','fqdn':'','hostname':'other','ip_address':'192.0.2.12'},
            ])
        report=propose_mappings(s,file,tmp_path/'proposals.csv')
        assert report['matched']==1 and report['ambiguous']==1 and report['unmatched']==1
        with (tmp_path/'proposals.csv').open(newline='') as handle:rows=list(csv.DictReader(handle))
        assert rows[0]['tenable_asset_uuid']=='a'
        assert all(row['mapping_verified']=='' for row in rows)
        assert rows[2]['tenable_asset_uuid']==''  # IP similarity is ignored.
    finally:s.close()


def test_nessus_import_two_hosts_same_ip_and_hygiene(tmp_path):
    s=Store(tmp_path/'nessus.db')
    try:
        result=import_nessus(s,ROOT/'tests/fixtures/sample.nessus')
        assert result['by_type']['asset']['accepted']==2
        assert result['by_type']['vulnerability']['accepted']==1
        assert result['by_type']['compliance']['accepted']==2
        assert s.count('assets')==2
        assert s.count('findings')==3
        assert {r['asset_id'] for r in s.rows('SELECT asset_id FROM assets')}=={'nessus-fixture-host-a','nessus-fixture-host-b'}
        assert s.overview()['compliance_status_counts']=={'ERROR':1,'FAIL':1}
        assert s.overview()['compliance_scan_hygiene']=={'WARNING':0,'ERROR':1}
        assert correlate(s,ROOT/'policies/correlation-rules.yaml')['correlations']==1
    finally:s.close()


@pytest.mark.parametrize('unsafe',[
    '<!DOCTYPE r SYSTEM "file:///etc/passwd">',
    '<!ENTITY x "not trusted">',
    '<!DoCtYpE report []>',
])
def test_nessus_dtd_or_entity_rejected(tmp_path,unsafe):
    p=tmp_path/'bad.nessus';p.write_text('<?xml version="1.0"?>\n'+unsafe+'\n<NessusClientData_v2/>')
    s=Store(tmp_path/'db.db')
    try:
        with pytest.raises(ValueError,match='DOCTYPE/ENTITY'):
            import_nessus(s,p)
        assert s.count('assets')==0
    finally:s.close()


def test_nessus_without_uuid_never_uses_ip_as_asset_key(tmp_path):
    p=tmp_path/'noid.nessus'
    p.write_text('<NessusClientData_v2><Report>'
                 '<ReportHost name="192.0.2.1"><ReportItem pluginID="5" severity="1"/></ReportHost>'
                 '<ReportHost name="192.0.2.1"><ReportItem pluginID="6" severity="2"/></ReportHost>'
                 '</Report></NessusClientData_v2>')
    s=Store(tmp_path/'data.db')
    try:
        import_nessus(s,p)
        ids=[r['asset_id'] for r in s.rows('SELECT asset_id FROM assets')]
        assert len(ids)==2 and all('192.0.2.1' not in x for x in ids)
    finally:s.close()


def test_asset_exposure_policy_optional_does_not_change_default(populated):
    default=get_asset_exposure(populated,'demo-prod-042')
    assert 'finding_evaluations' not in default
    optional=get_asset_exposure(populated,'demo-prod-042',policy=load_policy(ROOT/'policies/business-context.yaml'))
    assert optional['findings']==default['findings']
    assert len(optional['finding_evaluations'])==len(default['findings'])
    vuln=next(f for f in optional['finding_evaluations'] if f['kind']=='vulnerability')
    assert vuln['vendor_vpr']==7.2 and vuln['vendor_severity']=='high'
    assert 'TW-COMPOUND' in vuln['matched_rules']
    assert optional['correlated_cis_evidence'][0]['compliance_status']=='FAIL'


def test_scan_hygiene_separates_warning_and_error(tmp_path):
    s=Store(tmp_path/'hygiene.db')
    try:
        ingest_records(s,[
            {'asset_uuid':'a','compliance_full_id':'c1','audit_file':'one.audit','status':'FAIL'},
            {'asset_uuid':'a','compliance_full_id':'c2','audit_file':'one.audit','status':'WARNING'},
            {'asset_uuid':'a','compliance_full_id':'c3','audit_file':'one.audit','status':'ERROR'},
        ],'compliance')
        assert s.overview()['compliance_status_counts']=={'ERROR':1,'FAIL':1,'WARNING':1}
        assert s.overview()['compliance_scan_hygiene']=={'WARNING':1,'ERROR':1}
    finally:s.close()


def test_securitycenter_mocked_read_only_pagination_and_no_ip_identity(tmp_path):
    calls=[]
    def handler(request):
        assert request.method=='POST' and request.url.path=='/rest/analysis'
        assert request.headers.get('x-apikey')=='accesskey=a; secretkey=b;'
        query=json.loads(request.content)
        assert query['query']['tool']=='vulndetails'
        calls.append(query['query']['startOffset'])
        if len(calls)==1:
            return httpx.Response(200,json={'error_code':0,'response':{'results':[
              {'hostUUID':'mock-host-a','repository':{'id':3},'pluginID':'789','pluginName':'Synthetic OpenSSH advisory',
               'severity':'3','port':'22','protocol':'tcp','pluginText':'Synthetic evidence'},
              {'repository':{'id':3},'ip':'192.0.2.70','pluginID':'790','vulnUUID':'v1',
               'severity':'2','pluginText':'<cm:compliance-check-name>SSH access is limited</cm:compliance-check-name>'
                            '<cm:compliance-check-id>TEST-SC-SSH</cm:compliance-check-id>'
                            '<cm:compliance-audit-file>synthetic.audit</cm:compliance-audit-file>'
                            '<cm:compliance-result>ERROR</cm:compliance-result>'},
            ],'totalRecords':3}})
        return httpx.Response(200,json={'error_code':0,'response':{'results':[
            {'repository':{'id':3},'ip':'192.0.2.70','pluginID':'791','vulnUUID':'v2','severity':'2'},
        ],'totalRecords':3}})
    client=SecurityCenterClient('https://sc.example.invalid','a','b',transport=httpx.MockTransport(handler))
    s=Store(tmp_path/'sc.db')
    try:
        report=ingest_securitycenter(s,client,page_size=2,max_pages=3)
        assert calls==[0,2]
        assert report['read_only'] is True
        assert report['by_type']['vulnerability']['accepted']==2
        assert report['by_type']['compliance']['accepted']==1
        ids=[row['asset_id'] for row in s.rows('SELECT asset_id FROM assets')]
        assert len(ids)==3
        assert not any('192.0.2.70' in value for value in ids)
        assert s.overview()['compliance_status_counts']=={'ERROR':1}
    finally:
        client.close()
        s.close()


def test_securitycenter_http_only_rejected():
    with pytest.raises(ValueError,match='HTTPS'):
        SecurityCenterClient('http://sc.example.invalid','a','b')

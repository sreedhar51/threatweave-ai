"""Regression tests for the deterministic, UUID-scoped owner remediation queue."""
from pathlib import Path

from threatweave.store import Store
from threatweave.fixtures import ASSETS,VULNS,CIS,CMDB
from threatweave.ingest import ingest_records
from threatweave.correlate import correlate
from threatweave.policy import load_policy
from threatweave.ui_workflows import asset_360, asset_remediation_queue

ROOT=Path(__file__).resolve().parents[1]


def _populate(store):
    for kind,records in (('asset',ASSETS),('vulnerability',VULNS),
                         ('compliance',CIS),('cmdb',CMDB)):
        assert ingest_records(store,records,kind,'synthetic')['rejected']==0
    correlate(store,ROOT/'policies/correlation-rules.yaml')


def test_owner_queue_shows_compounded_vulnerability_and_related_cis_without_multiplication(tmp_path):
    s=Store(tmp_path/'owner.db')
    try:
        _populate(s)
        policy=load_policy(ROOT/'policies/business-context.yaml')
        report=asset_remediation_queue(s,'demo-prod-042',policy)
        assert report['total_groups']==2
        assert not report['truncated']
        assert report['verified_support_groups']==['Platform Operations']
        vuln=next(x for x in report['items'] if x['kind']=='vulnerability')
        assert vuln['asset_rank']==1
        assert vuln['priority']=='urgent'
        assert vuln['compounded_vulnerabilities']==1
        assert vuln['related_failed_cis_controls']==1
        assert vuln['max_vendor_severity']=='high'
        assert 'TW-COMPOUND' in vuln['matched_rules']
        assert 'TW-PAYMENTS' in vuln['matched_rules']
        assert len(vuln['linked_cis_evidence'])==1
        assert len(vuln['linked_cis_evidence'][0]['relation_rules'])==1
        assert len(vuln['finding_ids'])==1
        assert asset_remediation_queue(s,'demo-prod-042',policy)==report
    finally:
        s.close()


def test_queue_not_empty_when_first_200_detailed_rows_are_cis(tmp_path):
    s=Store(tmp_path/'large.db')
    try:
        assert ingest_records(s,[{'uuid':'host-a','hostname':'same.example.invalid'}],
                              'asset','synthetic')['accepted']==1
        assert ingest_records(s,[{'asset':{'uuid':'host-a'},'plugin':{
            'id':99,'name':'Synthetic V'} ,'severity':'high','status':'OPEN'}],
            'vulnerability','synthetic')['accepted']==1
        controls=[{'asset_uuid':'host-a','compliance_full_id':f'SYNTH-{i}',
                   'audit_file':'synthetic.audit','status':'FAILED'} for i in range(260)]
        assert ingest_records(s,controls,'compliance','synthetic')['accepted']==260
        p=load_policy(ROOT/'policies/default.yaml')
        view=asset_360(s,'host-a',p,limit=200)
        assert view['counts']['vulnerabilities']==1
        assert view['counts']['cis_failed']==260
        assert len(view['vulnerabilities'])==1
        assert len(view['cis'])==199
        assert view['displayed_findings']==200
        assert view['truncated']
        q=asset_remediation_queue(s,'host-a',p,limit=30)
        assert q['total_groups']==261
        assert q['truncated'] and len(q['items'])==30
        assert q['items'][0]['kind']=='vulnerability'
        assert q['items'][0]['compounded_vulnerabilities']==0
        assert q['items'][0]['related_failed_cis_controls']==0
        assert not q['verified_support_groups']
    finally:
        s.close()


def test_unverified_mapping_and_duplicate_hostname_do_not_contaminate_queue(tmp_path):
    s=Store(tmp_path/'isolate.db')
    try:
        assert ingest_records(s,[{'uuid':'host-a','hostname':'duplicate.invalid'},
                                 {'uuid':'host-b','hostname':'duplicate.invalid'}],
                              'asset','synthetic')['accepted']==2
        assert ingest_records(s,[
            {'asset':{'uuid':'host-a'},'plugin':{'id':1,'name':'A'},'severity':'high'},
            {'asset':{'uuid':'host-b'},'plugin':{'id':2,'name':'B'},'severity':'critical'}
        ],'vulnerability','synthetic')['accepted']==2
        assert ingest_records(s,[{'ci_sys_id':'unverified','tenable_asset_uuid':'host-a',
                'mapping_verified':'no','business_criticality':'critical',
                'environment':'production','business_tags':['payments'],
                'support_group':'Fake Owner'}],
                'cmdb','synthetic')['accepted']==1
        p=load_policy(ROOT/'policies/business-context.yaml')
        a=asset_remediation_queue(s,'host-a',p)
        b=asset_remediation_queue(s,'host-b',p)
        assert a['total_groups']==b['total_groups']==1
        assert a['items'][0]['max_vendor_severity']=='high'
        assert b['items'][0]['max_vendor_severity']=='critical'
        assert a['verified_support_groups']==[]
        assert a['items'][0]['matched_rules']==[]
        assert asset_remediation_queue(s,'missing',p)['missing_asset']
    finally:
        s.close()


def test_queue_surfaces_cis_relationship_count_not_number_of_attack_paths(tmp_path):
    s=Store(tmp_path/'links.db')
    try:
        _populate(s)
        # Add a second approved relationship to the *same* compliance control.
        original=s.rows('SELECT * FROM correlations WHERE asset_id=?',('demo-prod-042',))[0]
        s.db.execute('INSERT INTO correlations VALUES (?,?,?,?,?,?)',(
            'second-synthetic-link',original['asset_id'],original['vuln_id'],
            original['compliance_id'],'REL-ALTERNATE','Alternate contextual rationale'))
        s.commit()
        q=asset_remediation_queue(s,'demo-prod-042',
                                  load_policy(ROOT/'policies/business-context.yaml'))
        vuln=next(x for x in q['items'] if x['kind']=='vulnerability')
        assert vuln['related_failed_cis_controls']==1
        assert len(vuln['linked_cis_evidence'])==1
        assert sorted(vuln['linked_cis_evidence'][0]['relation_rules'])==[
            'REL-ALTERNATE','REL-REMOTE-ADMIN']
        assert vuln['compounded_vulnerabilities']==1
    finally:
        s.close()

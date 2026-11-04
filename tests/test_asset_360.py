"""Read-only Asset 360 dossier checks: do not merge records by hostname or IP."""
from threatweave.store import Store
from threatweave.ingest import ingest_records
from threatweave.correlate import correlate
from threatweave.ui_workflows import asset_360, asset_choices
from threatweave.policy import load_policy
from threatweave.fixtures import ASSETS,VULNS,CIS,CMDB
from conftest import ROOT


def _populate(store):
    for kind, records in [('asset',ASSETS),('vulnerability',VULNS),
                          ('compliance',CIS),('cmdb',CMDB)]:
        report=ingest_records(store,records,kind,'synthetic')
        assert report['rejected']==0
    correlate(store,ROOT/'policies/correlation-rules.yaml')


def test_asset_360_combines_vulnerability_compliance_correlations_and_verified_cmdb(tmp_path):
    store=Store(tmp_path/'a.db')
    try:
        _populate(store)
        view=asset_360(store,'demo-prod-042',load_policy(ROOT/'policies/business-context.yaml'))
        assert view['asset']['asset_id']=='demo-prod-042'
        assert view['counts']['vulnerabilities']==1
        assert view['counts']['cis_findings']==1
        assert view['counts']['cis_failed']==1
        assert view['counts']['correlations']==1
        assert view['counts']['verified_cmdb']==1
        assert len(view['vulnerabilities'])==1
        assert len(view['cis'])==1
        assert len(view['correlated_cis_evidence'])==1
        vuln=view['vulnerabilities'][0]
        assert vuln['scanner_severity']=='high'
        assert 'TW-PAYMENTS' in vuln['matched_rules']
        assert 'TW-COMPOUND' in vuln['matched_rules']
        assert view['cmdb'][0]['criticality']=='critical'
        assert not view['truncated']
    finally:
        store.close()


def test_asset_360_duplicate_hostname_still_isolates_authoritative_uuids(tmp_path):
    store=Store(tmp_path/'same-hostname.db')
    try:
        ingest_records(store,[
            {'uuid':'uuid-a','hostname':'shared-host.example.invalid','ipv4s':['10.0.0.8']},
            {'uuid':'uuid-b','hostname':'shared-host.example.invalid','ipv4s':['10.0.0.8']}],
            'asset','synthetic')
        ingest_records(store,[
            {'asset':{'uuid':'uuid-a'},'plugin':{'id':101,'name':'A only'},'severity':'high'},
            {'asset':{'uuid':'uuid-b'},'plugin':{'id':102,'name':'B only'},'severity':'low'}],
            'vulnerability','synthetic')
        policy=load_policy(ROOT/'policies/default.yaml')
        a=asset_360(store,'uuid-a',policy)
        b=asset_360(store,'uuid-b',policy)
        assert a['same_hostname_asset_count']==2
        assert b['same_hostname_asset_count']==2
        assert a['counts']['vulnerabilities']==b['counts']['vulnerabilities']==1
        assert a['vulnerabilities'][0]['title']=='A only'
        assert b['vulnerabilities'][0]['title']=='B only'
        assert sorted(x['asset_id'] for x in asset_choices(store,hostname_query='shared-host'))==['uuid-a','uuid-b']
    finally:
        store.close()


def test_asset_360_counts_all_records_and_marks_truncation(tmp_path):
    store=Store(tmp_path/'limit.db')
    try:
        ingest_records(store,[{'uuid':'many','hostname':'many.example.invalid'}],'asset','synthetic')
        records=[{'asset':{'uuid':'many'},'plugin':{'id':1000+i,'name':f'Synthetic {i}'},
                  'severity':'medium','status':'OPEN'} for i in range(5)]
        assert ingest_records(store,records,'vulnerability','synthetic')['accepted']==5
        view=asset_360(store,'many',load_policy(ROOT/'policies/default.yaml'),limit=2)
        assert view['counts']['vulnerabilities']==5
        assert view['displayed_findings']==2
        assert view['total_findings']==5
        assert view['truncated']
        assert view['counts']['verified_cmdb']==0
        assert asset_360(store,'does-not-exist',load_policy(ROOT/'policies/default.yaml')) is None
    finally:
        store.close()

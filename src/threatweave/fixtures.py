"""Entirely synthetic competition demonstration data; no actual host identities."""
from .ingest import ingest_records

ASSETS=[
 {'uuid':'demo-dev-001','hostname':'DEV-APP-001','operating_system':'Ubuntu 22.04',
  'asset_type':'server','environment':'development','role':'developer_app','tags':['development']},
 {'uuid':'demo-prod-042','hostname':'PROD-ID-042','operating_system':'Windows Server 2022',
  'asset_type':'server','tags':['identity']},
 {'uuid':'demo-ws-007','hostname':'USER-LAP-007','operating_system':'Windows 11',
  'asset_type':'workstation','environment':'office','tags':['workstation']},
]
VULNS=[
 {'asset':{'uuid':'demo-dev-001'},'plugin':{'id':101,'name':'Example Critical Software Library Vulnerability',
   'solution':'Update example software library','vpr':{'score':9.4},'cve':['CVE-2099-0001']},
   'severity':'critical','port':{'port':0,'protocol':'tcp'},'status':'OPEN','software_family':'software_library',
   'observed_at':'2026-11-02T12:00:00Z'},
 {'asset':{'uuid':'demo-dev-001'},'plugin':{'id':102,'name':'Example Software Library Vulnerability',
   'solution':'Update example software library','vpr':{'score':5.2},'cve':['CVE-2099-0002']},
   'severity':'high','port':{'port':0,'protocol':'tcp'},'status':'OPEN','software_family':'software_library',
   'observed_at':'2026-11-02T12:00:00Z'},
 {'asset':{'uuid':'demo-prod-042'},'plugin':{'id':201,'name':'Example Remote Administration Service Vulnerability',
   'solution':'Update remote administration service','vpr':{'score':7.2},'cve':['CVE-2099-0010']},
   'severity':'high','port':{'port':3389,'protocol':'tcp'},'status':'OPEN','software_family':'remote_admin',
   'observed_at':'2026-11-02T12:00:00Z'},
 {'asset':{'uuid':'demo-ws-007'},'plugin':{'id':301,'name':'Example Workstation Vulnerability',
   'solution':'Update example workstation application','vpr':{'score':5.9},'cve':['CVE-2099-0030']},
   'severity':'medium','port':{'port':0,'protocol':'tcp'},'status':'OPEN','software_family':'workstation_app',
   'observed_at':'2026-11-02T12:00:00Z'},
]
CIS=[
 {'asset_uuid':'demo-prod-042','compliance_full_id':'CIS-REMOTE-ADMIN','audit_file':'synthetic-Windows-2022.audit',
  'title':'Example remote administration hardening check','status':'FAIL','expected_value':'restricted',
  'actual_value':'permissive','severity':'medium','observed_at':'2026-11-02T12:00:00Z'},
 {'asset_uuid':'demo-ws-007','compliance_full_id':'CIS-REMOTE-ADMIN','audit_file':'synthetic-Windows-11.audit',
  'title':'Example workstation remote administration check','status':'FAIL','expected_value':'restricted',
  'actual_value':'permissive','severity':'medium','observed_at':'2026-11-02T12:00:00Z'},
]
CMDB=[
 {'ci_sys_id':'synthetic-cmdb-ci-042','tenable_asset_uuid':'demo-prod-042',
  'mapping_verified':'yes','business_service':'Payment Authorization (synthetic)',
  'business_criticality':'critical','environment':'production','role':'identity_server',
  'business_tags':['payments','identity'],'support_group':'Platform Operations',
  'internet_exposure':'unknown','last_updated':'2026-11-02T12:00:00Z'},
]

def load_demo(store,with_cis=True,with_cmdb=True):
    reports=[ingest_records(store,ASSETS,'asset','synthetic'),
             ingest_records(store,VULNS,'vulnerability','synthetic')]
    if with_cis: reports.append(ingest_records(store,CIS,'compliance','synthetic'))
    if with_cmdb: reports.append(ingest_records(store,CMDB,'cmdb','synthetic'))
    return reports

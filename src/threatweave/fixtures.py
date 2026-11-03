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

# Staged evidence-only demo. Intentionally separate from the original fixtures,
# so `threatweave demo` retains its previous counts, rankings, and behavior.
STAGED_ASSETS = [
 {'uuid':'demo-pay-web-01','hostname':'pay-web-01.demo.invalid',
  'operating_system':'Ubuntu 24.04 LTS','asset_type':'server','role':'web_server',
  'tags':['web'],'last_seen':'2026-11-02T12:00:00Z'}
]
STAGED_VULNS = [
 {'asset':{'uuid':'demo-pay-web-01'},
  'plugin':{'id':401,'name':'Synthetic OpenSSH vulnerability','cpe':'cpe:/a:openbsd:openssh:9.0',
            'solution':'Upgrade OpenSSH package','vpr':{'score':7.9}},
  'port':{'port':22,'protocol':'tcp'},'severity':'high','status':'OPEN',
  'observed_at':'2026-11-02T12:00:00Z'},
 {'asset':{'uuid':'demo-pay-web-01'},
  'plugin':{'id':402,'name':'Synthetic OpenSSL vulnerability','cpe':'cpe:/a:openssl:openssl:3.0',
            'solution':'Upgrade OpenSSL on payment web server','vpr':{'score':8.1}},
  'port':{'port':443,'protocol':'tcp'},'severity':'high','status':'OPEN',
  'observed_at':'2026-11-02T12:00:00Z'},
]
STAGED_CIS = [
 {'asset_uuid':'demo-pay-web-01','compliance_full_id':'SYNTH-SSH-ACCESS-01',
  'audit_file':'synthetic-Ubuntu-24.04.audit','title':'Ensure SSH access is limited',
  'status':'FAIL','expected_value':'restricted','actual_value':'unrestricted',
  'observed_at':'2026-11-02T12:00:00Z'}
]
STAGED_CMDB = [
 {'sys_id':'synthetic-ci-pay-web-01','tenable_asset_uuid':'demo-pay-web-01',
  'mapping_verified':'yes','environment':'production',
  'business_criticality':'critical','business_service':'Synthetic Payments API',
  'business_tags':['payments'],'role':'web_server','support_group':'Synthetic Platform',
  'last_updated':'2026-11-02T12:00:00Z'}
]


def load_staged_demo(store, with_cis=False, with_cmdb=False):
    """Original fixture set plus the pay-web-01 hero host, without modifying it."""
    reports = load_demo(store, with_cis=with_cis, with_cmdb=with_cmdb)
    reports += [ingest_records(store, STAGED_ASSETS, 'asset', 'synthetic'),
                ingest_records(store, STAGED_VULNS, 'vulnerability', 'synthetic')]
    if with_cis:
        reports.append(ingest_records(store, STAGED_CIS, 'compliance', 'synthetic'))
    if with_cmdb:
        reports.append(ingest_records(store, STAGED_CMDB, 'cmdb', 'synthetic'))
    return reports


def generate(n_assets=5000, seed=42, *, store=None, with_cis=True, with_cmdb=True):
    """Deterministic synthetic scale fixtures, streamed through ingest_records.

    Without store returns type-to-generator mappings for caller-controlled
    ingestion; with store directly ingests the records. IPs are deliberately
    random benchmark addresses and are never identity keys.
    """
    import random
    n_assets = int(n_assets)
    if not 0 <= n_assets <= 500000:
        raise ValueError('Synthetic asset count must be between 0 and 500000')
    def assets():
        rng=random.Random(seed)
        for i in range(n_assets):
            yield {'uuid':f'bench-{i:07d}',
                   'hostname':f'bench-{i:07d}.lab.invalid',
                   'ipv4':f'198.{18+rng.randrange(2)}.{rng.randrange(256)}.{rng.randrange(256)}',
                   'operating_system':'Ubuntu 24.04' if i%2==0 else 'Windows 11',
                   'asset_type':'server' if i%2==0 else 'workstation',
                   'environment':'development',
                   'last_seen':'2026-11-02T12:00:00Z'}
    def vulnerabilities():
        for i in range(n_assets):
            linux = i % 2 == 0
            yield {'asset':{'uuid':f'bench-{i:07d}'},
                   'plugin':{'id':710 if linux else 711,
                             'name':'Synthetic OpenSSH test finding' if linux else 'Synthetic SMB test finding',
                             'cpe':'cpe:/a:openbsd:openssh:9.1' if linux else 'cpe:/a:example:smb:1',
                             'solution':'Inspect benchmark SSH package' if linux else 'Review benchmark SMB setting',
                             'vpr':{'score':2.3}},
                   'severity':'low','status':'OPEN',
                   'port':{'port':22 if linux else 445,'protocol':'tcp'},
                   'observed_at':'2026-11-02T12:00:00Z'}
    def compliance():
        for i in range(0,n_assets,6):
            yield {'asset_uuid':f'bench-{i:07d}','compliance_full_id':'SYNTH-SSH-CHECK',
                   'audit_file':'synthetic-benchmark.audit',
                   'title':'SSH access is limited', 'status':'FAIL',
                   'expected_value':'restricted','actual_value':'open',
                   'observed_at':'2026-11-02T12:00:00Z'}
    def cmdb():
        for i in range(0,n_assets,12):
            yield {'ci_sys_id':f'bench-ci-{i:07d}',
                   'tenable_asset_uuid':f'bench-{i:07d}',
                   'mapping_verified':'yes','environment':'development',
                   'business_criticality':'low','business_tags':['benchmark'],
                   'last_updated':'2026-11-02T12:00:00Z'}
    streams={'asset':assets(),'vulnerability':vulnerabilities()}
    if with_cis:
        streams['compliance']=compliance()
    if with_cmdb:
        streams['cmdb']=cmdb()
    if store is None:
        return streams
    return [ingest_records(store, records, kind, provider='synthetic-benchmark')
            for kind,records in streams.items()]

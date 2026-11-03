import copy
from threatweave.fixtures import ASSETS,VULNS,CIS,CMDB
from threatweave.ingest import ingest_records
from threatweave.store import Store
from threatweave.policy import load_policy,validate_policy
from threatweave.engine import create_receipt,compare_receipts,rank_groups
from threatweave.correlate import correlate,get_asset_exposure
from conftest import ROOT
import pytest


def test_synthetic_correlation_matches_verified_same_asset(populated):
    assert populated.count('correlations')==1
    result=get_asset_exposure(populated,'demo-prod-042')
    assert len(result['correlations'])==1
    assert result['cross_asset_attack_path'].startswith('unverified')


def test_same_control_different_asset_not_correlated(populated):
    r=populated.rows("SELECT * FROM correlations")
    assert r[0]['asset_id']=='demo-prod-042'
    assert not populated.rows("SELECT * FROM correlations WHERE asset_id='demo-ws-007'")


def test_replay_policy_only_and_rank_changes(populated):
    before=create_receipt(populated,load_policy(ROOT/'policies/default.yaml'))
    after=create_receipt(populated,load_policy(ROOT/'policies/business-context.yaml'))
    replay=compare_receipts(before,after)
    assert replay['change_type']=='policy_changed'
    prod=lambda receipt: next(x for x in receipt['rankings'] if x['label']=='Update remote administration service')
    assert prod(before)['rank']==2
    assert prod(after)['rank']==1
    assert prod(after)['priority']=='urgent'
    assert {'TW-PAYMENTS','TW-COMPOUND'}.issubset(set(prod(after)['matched_rules']))


def test_receipts_reproducible(populated):
    policy=load_policy(ROOT/'policies/business-context.yaml')
    a=create_receipt(populated,policy)
    b=create_receipt(populated,policy)
    assert a['receipt_id']==b['receipt_id']
    assert a['dataset_hash']==b['dataset_hash']
    assert a['rankings']==b['rankings']


def test_different_cmdb_evidence_changes_data_fingerprint(populated):
    policy=load_policy(ROOT/'policies/business-context.yaml')
    before=create_receipt(populated,policy)
    changed=copy.deepcopy(CMDB[0]);changed['ci_sys_id']='new-ci';changed['environment']='development'
    ingest_records(populated,[changed],'cmdb','synthetic')
    after=create_receipt(populated,policy)
    assert compare_receipts(before,after)['change_type']=='source_data_or_context_changed'
    assert after['dataset_hash']!=before['dataset_hash']


def test_unsupported_policy_field_rejected():
    policy={'policy_id':'bad','version':'1.0','rules':[{'id':'bad','when':{'eval_python':'x'},'then':{'score_add':30}}]}
    with pytest.raises(ValueError):validate_policy(policy)


def test_negative_score_and_unknown_exposure_not_assumed_safe(populated):
    policy=load_policy(ROOT/'policies/business-context.yaml')
    group=next(g for g in rank_groups(populated,policy) if g['label']=='Update remote administration service')
    assert 'TW-CRITICAL-EXPOSURE' not in group['matched_rules']
    policy['rules'][0]['then']['score_add']=-100
    with pytest.raises(ValueError):validate_policy(policy)


def test_cve_count_is_finding_count_not_cve_multiplication(populated):
    group=next(g for g in rank_groups(populated,load_policy(ROOT/'policies/default.yaml')) if 'software library' in g['label'])
    assert group['finding_count']==2
    assert group['assets_count']==1


def test_ambiguous_mapping_does_not_merge_assets(populated):
    bad={'ci_sys_id':'ambig','tenable_asset_uuid':'unknown-asset','mapping_verified':'yes','environment':'production'}
    result=ingest_records(populated,[bad],'cmdb','servicenow-export')
    assert result['accepted']==1
    cmdb=populated.rows("SELECT * FROM cmdb WHERE ci_id='ambig'")[0]
    assert cmdb['asset_id'] is None
    assert cmdb['verified']==0
    assert populated.count('assets')==3


def test_closed_finding_excluded_from_rankings(tmp_path):
    s=Store(tmp_path/'single.db')
    try:
        ingest_records(s,[ASSETS[0]],'asset')
        closed=copy.deepcopy(VULNS[0]);closed['status']='FIXED'
        ingest_records(s,[closed],'vulnerability')
        assert rank_groups(s,load_policy(ROOT/'policies/default.yaml'))==[]
    finally:s.close()


def test_guided_agent_requires_no_remote_api(populated):
    from threatweave.agent import guided_investigation
    result=guided_investigation(populated.path,str(ROOT/'policies/business-context.yaml'))
    assert result['read_only'] is True
    assert result['investigations'][0]['correlated_assets']==['demo-prod-042']
    assert result['investigations'][0]['cross_host_path'].startswith('not validated')

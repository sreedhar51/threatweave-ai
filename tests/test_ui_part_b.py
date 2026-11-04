"""Part B regression checks: user-visible decision safety and evidence traceability."""
from pathlib import Path
import json
import sqlite3
import pytest
import yaml

from threatweave.store import Store
from threatweave.ingest import ingest_records
from threatweave.policy import load_policy
from threatweave.engine import create_receipt, rank_groups, group_key
from threatweave.fixtures import load_demo
from threatweave.correlate import correlate
from threatweave.ui_workflows import (asset_choices,rule_diff,add_drafted_rule_to_yaml,
    save_approved_policy,rank_replay,list_receipt_files,read_receipt)

ROOT=Path(__file__).resolve().parents[1]


def test_ingest_history_created_per_call_and_legacy_migration(tmp_path):
    path=tmp_path/'history.db'
    s=Store(path)
    try:
        records=[{'uuid':'a1'},{'uuid':'a2'},{'other':'invalid'}]
        report=ingest_records(s,records,'asset',provider='tenant')
        assert report['accepted']==2 and report['rejected']==1
        runs=s.recent_ingest_runs()
        assert len(runs)==1 and runs[0]['total']==3
        assert runs[0]['accepted']==2 and runs[0]['rejected']==1
        assert runs[0]['started_at'] and runs[0]['finished_at']
        assert s.data_version()[2]==1
        # Reimport is a new auditable run but does not change evidence identity.
        identity=s.snapshot_hash()
        ingest_records(s,[{'uuid':'a1'}],'asset',provider='tenant')
        assert len(s.recent_ingest_runs())==2
        assert s.snapshot_hash()==identity
        s.db.execute('DROP INDEX idx_ingest_finished')
        s.db.execute('ALTER TABLE ingest_runs DROP COLUMN started_at')
        s.db.execute('ALTER TABLE ingest_runs DROP COLUMN finished_at')
        s.commit()
    finally: s.close()
    old=Store(path)
    try:
        ingest_records(old,[{'uuid':'a3'}],'asset')
        assert old.recent_ingest_runs()[0]['started_at']
    finally:old.close()


def test_asset_lookup_only_hostname_or_authoritative_uuid(tmp_path):
    s=Store(tmp_path/'assets.db')
    try:
        ingest_records(s,[{'uuid':'id1','hostname':'pay-web-01','ipv4s':['10.0.0.1']},
                          {'uuid':'id2','hostname':'other-host','ipv4s':['10.0.0.1']}],'asset')
        ingest_records(s,[{'asset':{'uuid':'id1'},'plugin':{'id':45,'name':'OpenSSH vuln','solution':'Fix A'},'severity':'high'}],'vulnerability')
        gid=s.db.execute("SELECT group_id FROM findings WHERE asset_id='id1'").fetchone()[0]
        results=asset_choices(s,group_id=gid)
        assert len(results)==1 and results[0]['asset_id']=='id1'
        assert [x['asset_id'] for x in asset_choices(s,hostname_query='PAY-WEB')]==['id1']
        assert asset_choices(s,hostname_query='10.0.0.1')==[]
    finally:s.close()


def test_approval_versioned_outputs_and_rule_level_diff(tmp_path):
    s=Store(tmp_path/'data.db')
    try:
        load_demo(s)
        active=load_policy(ROOT/'policies/default.yaml')
        proposed={**active,'rules':list(active['rules'])+[{
            'id':'TW-LOCAL-TEST','when':{'environment':'production'},'then':{'score_add':7}}]}
        diff=rule_diff(active,proposed)
        assert diff['added']==['TW-LOCAL-TEST']
        assert diff['removed']==[]
        draft_text=add_drafted_rule_to_yaml(yaml.safe_dump(active),{'draft_rule':proposed['rules'][-1]})
        assert yaml.safe_load(draft_text)==proposed
        with pytest.raises(ValueError):
            add_drafted_rule_to_yaml(draft_text,{'draft_rule':proposed['rules'][-1]})
        baseline=s.snapshot_hash()
        saved=save_approved_policy(s,proposed,tmp_path/'runtime')
        assert Path(saved['policy_path']).is_file()
        assert Path(saved['receipt_path']).is_file()
        assert yaml.safe_load(Path(saved['policy_path']).read_text())==proposed
        assert read_receipt(saved['receipt_path'])['receipt_id']==saved['receipt_id']
        assert s.snapshot_hash()==baseline
        second=save_approved_policy(s,proposed,tmp_path/'runtime')
        assert second==saved
        assert len(list_receipt_files(tmp_path/'runtime/receipts'))==1
    finally:s.close()


def test_replay_exact_rule_deltas(tmp_path):
    s=Store(tmp_path/'replay.db')
    try:
        load_demo(s)
        correlate(s,ROOT/'policies/correlation-rules.yaml')
        before=load_policy(ROOT/'policies/default.yaml')
        after=load_policy(ROOT/'policies/business-context.yaml')
        old=create_receipt(s,before)
        new=create_receipt(s,after)
        result=rank_replay(old,new)
        assert result['policy_unchanged'] is False
        assert result['dataset_unchanged'] is True
        assert result['top_movements']
        assert any(m['rules_added'] for m in result['top_movements'])
        assert any(m['contribution_deltas'] for m in result['top_movements'])
        assert all('rules_removed' in m for m in result['top_movements'])
    finally:s.close()


def test_ties_sort_compounded_before_asset_count(tmp_path):
    """Both groups reach score 100, but one has one compounded asset and fewer assets."""
    s=Store(tmp_path/'tie.db')
    try:
        ingest_records(s,[{'uuid':uid} for uid in ('a','b','c')],'asset')
        records=[{'asset':{'uuid':uid},'plugin':{'id':pid,'name':name,'solution':name,
                    'vpr':{'score':9.9}},'severity':'critical','status':'OPEN'}
                 for uid,pid,name in [('a',1,'Patch A'),('b',2,'Patch B'),('c',3,'Patch B')]]
        ingest_records(s,records,'vulnerability')
        # A same-asset corroborated CIS failure for one group (the stored correlation is explicit).
        ing=ingest_records(s,[{'asset_uuid':'a','compliance_full_id':'controlA',
                     'audit_file':'test.audit','status':'FAIL','check_name':'SSH access limited'}],'compliance')
        assert ing['accepted']==1
        vuln=s.db.execute("SELECT finding_id FROM findings WHERE kind='vulnerability' AND asset_id='a'").fetchone()[0]
        comp=s.db.execute("SELECT finding_id FROM findings WHERE kind='compliance' AND asset_id='a'").fetchone()[0]
        s.db.execute('INSERT INTO correlations VALUES (?,?,?,?,?,?)',('corr','a',vuln,comp,'ruleA','sample'))
        s.commit()
        policy={'policy_id':'test','version':'1','rules':[{'id':'PLUS','when':{'kind':'vulnerability'},'then':{'score_add':30}}]}
        groups=[g for g in rank_groups(s,policy) if g['kind']=='vulnerability']
        assert len(groups)==2
        assert groups[0]['score']==100 and groups[1]['score']==100
        assert groups[0]['compounded_assets_count']==1
        assert groups[0]['assets_count']==1 and groups[1]['assets_count']==2
        assert groups[0]['label']=='Patch A'
    finally:s.close()

"""Part A regression checks: source isolation, indexes and vendor evidence."""
import sqlite3
from pathlib import Path
import pytest
from threatweave.store import Store
from threatweave.data_sources import source_paths,load_synthetic_isolated
from threatweave.coverage import evidence_coverage
from threatweave.fixtures import load_demo
from threatweave.ingest import ingest_records
from threatweave.engine import group_key,rank_groups,evidence_for_group
from threatweave.staged import run_staged_demo
from threatweave.policy import load_policy
from threatweave.correlate import correlate

ROOT=Path(__file__).resolve().parents[1]

def test_source_isolation(tmp_path):
    # Create a project root with policies mirrored from the actual source.
    from shutil import copyfile
    (tmp_path/'policies').mkdir()
    copyfile(ROOT/'policies/correlation-rules.yaml',tmp_path/'policies/correlation-rules.yaml')
    tenant=tmp_path/'tenant.db'
    tenant.write_bytes(b'untouched tenant bytes')
    before=tenant.read_bytes()
    load_synthetic_isolated(tmp_path,tenant)
    assert tenant.read_bytes()==before
    assert (tmp_path/'runtime/demo.db').exists()
    with pytest.raises(ValueError): source_paths(tmp_path,tmp_path/'runtime/demo.db')

def test_group_migration_and_indexed_evidence(tmp_path):
    db=tmp_path/'old.db'
    store=Store(db)
    load_demo(store)
    original=store.rows('SELECT * FROM findings ORDER BY finding_id')
    expected={r['finding_id']:group_key(r)[0] for r in original}
    # Simulate the original pre-migration schema, which has no group_id.
    store.db.execute('DROP INDEX idx_f_group')
    store.db.execute('ALTER TABLE findings DROP COLUMN group_id')
    store.commit();store.close()
    upgraded=Store(db)
    try:
        found=upgraded.rows('SELECT finding_id,group_id FROM findings ORDER BY finding_id')
        assert {r['finding_id']:r['group_id'] for r in found}==expected
        target=expected[original[0]['finding_id']]
        result=evidence_for_group(upgraded,target,limit=25)
        assert [r['finding_id'] for r in result['evidence']]==sorted(
            row['finding_id'] for row in original if group_key(row)[0]==target)
        assert any(x[1]=='idx_f_group' for x in upgraded.db.execute('PRAGMA index_list(findings)'))
    finally: upgraded.close()

def test_coverage_equal_sql(tmp_path):
    store=Store(tmp_path/'coverage.db')
    try:
        load_demo(store)
        correlate(store,ROOT/'policies/correlation-rules.yaml')
        data=evidence_coverage(store)
        assert sum(x['count'] for x in data['software_families'])==store.db.execute(
            "SELECT COUNT(*) FROM findings WHERE kind='vulnerability'").fetchone()[0]
        assert sum(x['count'] for x in data['compliance_status'])==store.db.execute(
            "SELECT COUNT(*) FROM findings WHERE kind='compliance'").fetchone()[0]
        assert sum(x['count'] for x in data['correlation_rules'])==store.count('correlations')
        assert data['cmdb']['verified']==store.db.execute('SELECT COUNT(*) FROM cmdb WHERE verified=1').fetchone()[0]
    finally: store.close()

def test_vendor_fields_not_changed(tmp_path):
    store=Store(tmp_path/'vpr.db')
    try:
        ingest_records(store,[{'uuid':'vendor-host'}],'asset')
        ingest_records(store,[{'asset':{'uuid':'vendor-host'},'plugin':{'id':777,'name':'test',
                          'solution':'Apply Update','vpr':{'score':8.7}},
                          'severity':'high','status':'OPEN'}],'vulnerability')
        before=store.rows('SELECT severity,vpr FROM findings')
        groups=rank_groups(store,load_policy(ROOT/'policies/business-context.yaml'))
        assert groups[0]['max_vendor_severity']=='high'
        assert groups[0]['max_vendor_vpr']==8.7
        assert store.rows('SELECT severity,vpr FROM findings')==before
    finally: store.close()

def test_staged_hero_2000_assets(tmp_path):
    report=run_staged_demo(tmp_path/'stages',n_assets=2000)
    assert all(report['hero_fix_groups'][x] for x in
               ('stage1_vulnerabilities','stage2_plus_cis','stage3_plus_cmdb'))
    assert report['stage1_to_stage2']['evidence_changed']==['compliance','correlations']

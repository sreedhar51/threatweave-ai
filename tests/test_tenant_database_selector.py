"""Tenant selector safety and default precedence tests (no live tenant access)."""
from pathlib import Path

import pytest

from threatweave.data_sources import tenant_database_choices, source_paths


def test_tenant_lab_preferred_over_empty_legacy_default(tmp_path):
    runtime=tmp_path/'runtime'
    runtime.mkdir()
    (runtime/'threatweave.db').write_bytes(b'legacy-placeholder')
    (runtime/'tenant-lab.db').write_bytes(b'actual-existing-tenant')
    choices=tenant_database_choices(tmp_path)
    assert [p.name for p in choices]==['tenant-lab.db','threatweave.db']
    assert choices[0].read_bytes()==b'actual-existing-tenant'
    assert source_paths(tmp_path,choices[0])['Tenant']==choices[0]


def test_explicit_configured_path_takes_precedence(tmp_path):
    runtime=tmp_path/'runtime'
    runtime.mkdir()
    (runtime/'tenant-lab.db').write_bytes(b'lab')
    outside=tmp_path/'other'/'selected.db'
    outside.parent.mkdir()
    outside.write_bytes(b'configured')
    choices=tenant_database_choices(tmp_path,str(outside))
    assert choices[0]==outside.resolve()
    assert (runtime/'tenant-lab.db').resolve() in choices


def test_synthetic_databases_never_appear_as_tenant_options(tmp_path):
    runtime=tmp_path/'runtime'
    staged=runtime/'staged-ui'
    staged.mkdir(parents=True)
    for name in ('demo.db','enterprise-demo.db','tenant-lab.db'):
        (runtime/name).write_bytes(b'test')
    (staged/'stage3_plus_cmdb.db').write_bytes(b'test')
    choices=tenant_database_choices(tmp_path)
    assert [p.name for p in choices]==['tenant-lab.db']
    for blocked in ('demo.db','enterprise-demo.db'):
        with pytest.raises(ValueError):
            tenant_database_choices(tmp_path,str(runtime/blocked))
    with pytest.raises(ValueError):
        tenant_database_choices(tmp_path,str(staged/'stage3_plus_cmdb.db'))


def test_missing_override_rejected_and_no_blank_database_created(tmp_path):
    missing=tmp_path/'runtime'/'missing.db'
    assert tenant_database_choices(tmp_path)==[]
    with pytest.raises(ValueError,match='existing'):
        tenant_database_choices(tmp_path,str(missing))
    assert not missing.exists()


def test_streamlit_selector_is_read_only_and_preserves_separate_demo_loaders():
    app=(Path(__file__).resolve().parents[1]/'dashboard/app.py').read_text()
    assert "key='selected_tenant_db'" in app
    assert 'tenant_database_choices(ROOT,CONFIGURED_TENANT_DB)' in app
    assert 'if not available_tenants:' in app
    assert "key='load_enterprise_demo'" in app
    assert "key='load_demo'" in app

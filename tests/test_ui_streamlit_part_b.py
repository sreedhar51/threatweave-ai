"""Streamlit AppTest source-isolation smoke; only runs with optional UI dependency."""
from pathlib import Path
from shutil import copy2, copytree
import pytest

st=pytest.importorskip('streamlit')
from streamlit.testing.v1 import AppTest

ROOT=Path(__file__).resolve().parents[1]


def test_app_ui_tenant_synthetic_staged(tmp_path,monkeypatch):
    # Never open or overwrite user's actual runtime/demo.db from the test suite.
    copytree(ROOT/'src',tmp_path/'src')
    copytree(ROOT/'policies',tmp_path/'policies')
    (tmp_path/'dashboard').mkdir()
    copy2(ROOT/'dashboard/app.py',tmp_path/'dashboard/app.py')
    from threatweave.store import Store
    from threatweave.fixtures import load_demo
    tenant=tmp_path/'runtime/tenant.db'
    s=Store(tenant)
    load_demo(s)
    s.close()
    monkeypatch.setenv('THREATWEAVE_DB',str(tenant))
    at=AppTest.from_file(str(tmp_path/'dashboard/app.py'),default_timeout=35).run()
    assert not at.exception
    assert len(at.dataframe)>0

    at.selectbox(key='data_source').set_value('Synthetic demo').run()
    assert not at.exception
    at.button(key='load_demo').click().run()
    assert not at.exception
    assert len(at.dataframe)>0

    at.selectbox(key='data_source').set_value('Staged demo').run()
    assert not at.exception
    at.button(key='run_stages').click().run()
    assert not at.exception
    assert len(at.dataframe)>0

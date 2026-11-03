import pytest
from pathlib import Path
from threatweave.store import Store
from threatweave.fixtures import load_demo
from threatweave.correlate import correlate

ROOT=Path(__file__).resolve().parents[1]

@pytest.fixture
def populated(tmp_path):
    s=Store(tmp_path/'test.db')
    load_demo(s)
    correlate(s,ROOT/'policies/correlation-rules.yaml')
    yield s
    s.close()

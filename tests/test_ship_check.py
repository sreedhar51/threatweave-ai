import copy
import json
from pathlib import Path

import pytest

from threatweave.agent import _bounded_tool_result, TOOLS
from threatweave.shipcheck import AcceptanceFailure, evaluate_run, run_ship_check, STAGES
from threatweave.staged import run_staged_demo


def _sample(tmp_path):
    result=run_staged_demo(tmp_path/'demo')
    receipts=[json.loads((tmp_path/'demo'/f'{name}.json').read_text()) for name in STAGES]
    return result,receipts


def test_repeatability_three_clean_runs():
    out=run_ship_check(repeat=3)
    assert out['verdict']=='PASS'
    assert out['runs_checked']==3
    assert len(set(tuple(x['receipt_ids']) for x in out['executions']))==1
    assert out['decision']['cis_delta']==['compliance','correlations']
    assert out['decision']['cmdb_delta']==['cmdb']


def test_fails_loudly_on_wrong_evidence_attribution(tmp_path):
    result,receipts=_sample(tmp_path)
    result['stage1_to_stage2']['evidence_changed']=['assets']
    with pytest.raises(AcceptanceFailure, match='adding CIS'):
        evaluate_run(result,receipts)


def test_fails_loudly_on_missing_compound_rule(tmp_path):
    result,receipts=_sample(tmp_path)
    group=next(x for x in result['hero_fix_groups'][STAGES[1]] if 'OpenSSH' in x['label'])
    group['matched_rules']=[]
    with pytest.raises(AcceptanceFailure,match='compounding rule'):
        evaluate_run(result,receipts)


def test_fails_loudly_on_mismatched_policy_hash(tmp_path):
    result,receipts=_sample(tmp_path)
    receipts[1]['policy_hash']='sha256:changed'
    with pytest.raises(AcceptanceFailure,match='policy'):
        evaluate_run(result,receipts)


def test_tool_payload_is_valid_json_under_budget():
    payload=_bounded_tool_result({'findings':['x'*30000]})
    parsed=json.loads(payload)
    assert parsed['status']=='TRUNCATED'
    assert parsed['evidence_complete'] is False
    assert 'x'*500 not in payload


def test_agent_has_only_bounded_read_tools():
    names={t['name'] for t in TOOLS}
    assert names=={'get_overview','list_fix_groups','get_asset_exposure','get_group_evidence'}
    assert all('input_schema' in t for t in TOOLS)

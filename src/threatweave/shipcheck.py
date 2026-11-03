"""Offline, deterministic SWARM submission acceptance checks.

No API credentials, network requests, writes to vendor systems, or LLM required.
Each run receives its own synthetic, temporary database; scratch data is removed
when the check exits. Assertions fail loudly rather than inventing a pass.
"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path
from time import perf_counter

from .staged import run_staged_demo

STAGES = ('stage1_vulnerabilities', 'stage2_plus_cis', 'stage3_plus_cmdb')
REQUIRED_12 = ['compliance', 'correlations']
REQUIRED_23 = ['cmdb']


class AcceptanceFailure(AssertionError):
    """A required, checkable submission behavior did not hold."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise AcceptanceFailure(message)


def _hero_group(run: dict, stage: str, label: str) -> dict:
    groups = [g for g in run['hero_fix_groups'][stage] if label.casefold() in g['label'].casefold()]
    _require(len(groups) == 1, f'{stage}: expected exactly one {label} hero group; got {len(groups)}')
    return groups[0]


def evaluate_run(result: dict, receipts: list[dict]) -> dict:
    """Validate actual decision artifacts, not an LLM's description of them."""
    _require(result.get('synthetic_demo') is True, 'dataset must be explicitly labeled synthetic')
    _require(len(receipts) == 3, 'three receipts are required')
    _require(len({r['dataset_hash'] for r in receipts}) == 3, 'each evidence stage must differ')
    _require(len({r['policy_hash'] for r in receipts}) == 1, 'policy must remain identical across stages')
    for i, receipt in enumerate(receipts):
        _require(receipt.get('receipt_id', '').startswith('DR-'), f'stage {i+1}: missing receipt')
        _require(receipt.get('rankings'), f'stage {i+1}: empty decision list')
        _require('input_fingerprints' in receipt, f'stage {i+1}: no source fingerprints')
        _require('not evaluated' in receipt.get('cross_asset_attack_paths','').lower(),
                 f'stage {i+1}: attack-path uncertainty missing')
        ranks = [g['rank'] for g in receipt['rankings']]
        _require(ranks == list(range(1,len(ranks)+1)), f'stage {i+1}: unstable ranking indices')

    a=result['stage1_to_stage2']; b=result['stage2_to_stage3']
    _require(a.get('evidence_changed') == REQUIRED_12,
             f'adding CIS must change only {REQUIRED_12}; got {a.get("evidence_changed")}')
    _require(b.get('evidence_changed') == REQUIRED_23,
             f'adding CMDB must change only {REQUIRED_23}; got {b.get("evidence_changed")}')
    _require(a.get('policy_unchanged') and b.get('policy_unchanged'),
             'one constant policy must be used across evidence stages')

    ssh1=_hero_group(result,STAGES[0],'OpenSSH')
    ssh2=_hero_group(result,STAGES[1],'OpenSSH')
    ssh3=_hero_group(result,STAGES[2],'OpenSSH')
    ssl2=_hero_group(result,STAGES[1],'OpenSSL')
    ssl3=_hero_group(result,STAGES[2],'OpenSSL')
    _require(ssh2['compounded_assets_count'] > ssh1['compounded_assets_count'],
             'adding CIS did not establish a supported same-asset correlation')
    _require(ssh2['score'] > ssh1['score'], 'CIS correlation did not change the OpenSSH priority')
    _require(ssh3['score'] > ssh2['score'], 'CMDB enrichment did not change the OpenSSH priority')
    _require(ssl3['score'] > ssl2['score'], 'CMDB enrichment did not change the OpenSSL priority')
    _require('TW-COMPOUND' in ssh2['matched_rules'], 'compounding rule not attributed')
    _require('TW-PAYMENTS' in ssl3['matched_rules'], 'payments rule not attributed')
    return {
      'policy_unchanged':True,
      'cis_delta':a['evidence_changed'],
      'cmdb_delta':b['evidence_changed'],
      'openssh':{'before':ssh1['score'],'after_cis':ssh2['score'],'after_cmdb':ssh3['score'],
                 'ranks':[ssh1['rank'],ssh2['rank'],ssh3['rank']]},
      'openssl':{'before_cmdb':ssl2['score'],'after_cmdb':ssl3['score'],
                 'ranks':[ssl2['rank'],ssl3['rank']]},
      'source_evidence':'synthetic',
      'cross_host_attack_paths':'unverified',
    }


def run_ship_check(repeat: int=3, n_assets: int=0, seed: int=42) -> dict:
    """Require identical receipt IDs and complete ranking content on repeated clean runs."""
    if not 2 <= repeat <= 5:
        raise ValueError('repeat must be between 2 and 5')
    if not 0 <= n_assets <= 50000:
        raise ValueError('acceptance-check asset count must be between 0 and 50000')
    reference=None
    executions=[]
    for index in range(repeat):
        with tempfile.TemporaryDirectory(prefix='threatweave-acceptance-') as temp:
            t0=perf_counter()
            result=run_staged_demo(Path(temp),n_assets=n_assets,seed=seed)
            receipts=[json.loads((Path(temp)/f'{stage}.json').read_text(encoding='utf-8'))
                      for stage in STAGES]
            summary=evaluate_run(result,receipts)
            # Exclude generated_at and wall-clock timing; verify full decisions and provenance.
            deterministic=[{k:v for k,v in receipt.items() if k != 'generated_at'}
                           for receipt in receipts]
            serialized=json.dumps(deterministic,sort_keys=True,separators=(',',':'))
            if reference is None:
                reference=serialized
            else:
                _require(serialized == reference,
                         f'run {index+1} changed rankings, provenance, or receipt ID')
            executions.append({'run':index+1,'receipt_ids':[x['receipt_id'] for x in receipts],
                               'elapsed_seconds':round(perf_counter()-t0,3)})
    return {'verdict':'PASS','synthetic_only':True,'repeatability':'identical_receipts_and_rankings',
            'runs_checked':repeat,'generated_assets_per_stage':n_assets,
            'decision':summary,'executions':executions,
            'checks':['real_decision_receipts','same_policy_all_stages','source_specific_evidence_delta',
                      'same_asset_compounding','business_context_changes_priority',
                      'source_provenance','unverified_paths_remain_unverified','repeatability'],
            'not_verified':['live_tenable_authentication','third_party_connector_authentication',
                            'true_remediation_outcome','production_scale','actual_time_saved']}

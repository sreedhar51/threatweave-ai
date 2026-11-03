"""Streamlit three-tab ThreatWeave demo. Run: streamlit run dashboard/app.py"""
import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
import yaml
import streamlit as st
from threatweave.store import Store
from threatweave.ingest import ingest_file
from threatweave.fixtures import load_demo
from threatweave.correlate import correlate,get_asset_exposure
from threatweave.policy import load_policy,validate_policy
from threatweave.engine import create_receipt,compare_receipts,rank_groups,evidence_for_group

ROOT=Path(__file__).resolve().parents[1]
DB=os.getenv('THREATWEAVE_DB',str(ROOT/'runtime/threatweave.db'))
RECEIPTS=Path(os.getenv('THREATWEAVE_RECEIPTS',str(ROOT/'runtime/receipts')))

st.set_page_config(page_title='ThreatWeave AI',page_icon='🛡️',layout='wide')
st.title('ThreatWeave AI')
st.caption('Evidence-backed exposure correlation · Organizational policy · Decision Replay')
st.info('Read-only analysis. Sample data is synthetic. No patch execution, scan initiation, or Tenable write-back.')

store=Store(DB)
with st.sidebar:
    st.header('DataBridge')
    st.write('**Data source:** Local SQLite analytical store')
    if st.button('Load synthetic demo',use_container_width=True):
        load_demo(store)
        correlate(store,ROOT/'policies/correlation-rules.yaml')
        st.success('Synthetic assets, vulnerabilities, CIS and CMDB imported')
        st.rerun()
    record_type=st.selectbox('Import record type',['asset','vulnerability','compliance','cmdb'])
    provider=st.selectbox('Evidence provider',['tenable','servicenow-export','generic-export','synthetic'])
    f=st.file_uploader('Upload CSV, JSON, or JSONL',type=['csv','json','jsonl','ndjson'])
    if st.button('Import uploaded data',disabled=f is None):
        with tempfile.TemporaryDirectory() as td:
            suffix=Path(f.name).suffix
            path=Path(td)/('input'+suffix)
            path.write_bytes(f.getvalue())
            try:
                result=ingest_file(store,path,record_type,provider)
                st.json(result)
            except Exception as exc:
                st.error(f'Import failed: {exc}')
    if st.button('Recompute CIS correlations'):
        try:
            st.json(correlate(store,ROOT/'policies/correlation-rules.yaml'))
        except Exception as exc:
            st.error(str(exc))
    st.caption('Live Tenable export is available through the CLI using tenant API credentials.')

summary=store.overview()
a,b,c,d=st.columns(4)
a.metric('Assets',summary['assets'])
b.metric('Findings',summary['findings'])
c.metric('Verified CMDB records',len(store.rows('SELECT ci_id FROM cmdb WHERE verified=1')))
d.metric('CIS correlations',summary['correlations'])
st.caption('Compliance scan hygiene (not FAIL findings): '
           f"WARNING {summary.get('compliance_scan_hygiene',{}).get('WARNING',0)}  ·  "
           f"ERROR {summary.get('compliance_scan_hygiene',{}).get('ERROR',0)}")

tab_fixes,tab_policy,tab_replay=st.tabs(['Fix Groups & Assets','Policy & Investigation','Decision Replay'])

with tab_fixes:
    st.subheader('Evidence-backed candidate remediation groups')
    st.caption('Groups based on source solution text / check IDs. They are not verified one-patch fixes.')
    policy=load_policy(ROOT/'policies/business-context.yaml')
    groups=rank_groups(store,policy,max_groups=100)
    if groups:
        st.dataframe([{k:g.get(k) for k in ('rank','label','kind','priority','score','finding_count','assets_count','servers_count','workstations_count','production_assets_count','compounded_assets_count')}
                      for g in groups],use_container_width=True,hide_index=True)
        options={g['label']+' · '+g['fix_group_id']:g['fix_group_id'] for g in groups}
        chosen=st.selectbox('Inspect fix group evidence',list(options))
        st.json(evidence_for_group(store,options[chosen],limit=15))
    else:
        st.warning('No findings imported. Use “Load synthetic demo” in the sidebar.')
    st.subheader('Asset investigation')
    selected_id=st.text_input('Tenable asset UUID',value='demo-prod-042' if summary['assets'] else '')
    # Optional contextual view; unchecked preserves the prior asset response.
    contextual_asset=st.checkbox('Include contextual priority and CIS rationale',value=False)
    if st.button('Investigate asset') and selected_id:
        st.json(get_asset_exposure(store,selected_id,limit=30,
                 policy=policy if contextual_asset else None))

with tab_policy:
    st.subheader('Human-readable contextual policy')
    raw=st.text_area('Edit draft policy YAML (nothing is applied until approved)',
          value=(ROOT/'policies/business-context.yaml').read_text(),height=285)
    candidate=None
    try:
        candidate=validate_policy(yaml.safe_load(raw))
        st.success('Policy schema validated')
    except Exception as exc:
        st.error(f'Invalid policy: {exc}')
    if st.button('Preview policy (dry run)',disabled=candidate is None):
        preview=create_receipt(store,candidate)
        st.session_state['preview']=preview
    if st.session_state.get('preview'):
        preview=st.session_state['preview']
        st.caption('Unapproved dry-run — not an active policy change')
        st.json({'policy_hash':preview['policy_hash'],
                 'top_groups':preview['rankings'][:5]})
    approved=st.checkbox('I reviewed and approve saving this policy receipt locally')
    if st.button('Approve and generate receipt',disabled=candidate is None or not approved):
        receipt=create_receipt(store,candidate,RECEIPTS/'approved-policy.json')
        st.session_state['approved_receipt']=receipt
        st.success(f"Local Decision Receipt created: {receipt['receipt_id']}")
    with st.expander('Optional: Draft policy with Claude'):
        request=st.text_input('Describe the policy adjustment',value='Prioritize payment systems in production')
        if st.button('Ask Claude to draft rule'):
            try:
                from threatweave.agent import draft_rule
                output=draft_rule(request,candidate or load_policy(ROOT/'policies/default.yaml'))
                st.json(output)
                st.warning('Draft only. Manually review and add the rule to the YAML above.')
            except Exception as exc:
                st.error(str(exc))
    if st.button('Run standalone guided investigation (no API key)'):
        from threatweave.agent import guided_investigation
        st.json(guided_investigation(DB,str(ROOT/'policies/business-context.yaml')))
    with st.expander('Optional: Ask Claude to investigate'):
        question=st.text_area('Question for the read-only evidence agent',value='Which fixes changed priority because of the CIS evidence?')
        if st.button('Ask ThreatWeave Agent'):
            try:
                from threatweave.agent import investigate
                st.write(investigate(question,DB,str(ROOT/'policies/business-context.yaml')))
            except Exception as exc:
                st.error(str(exc))

with tab_replay:
    # Staged mode is an isolated synthetic demo; default mode remains unchanged.
    replay_mode=st.radio('Replay scenario',
        ['Policy change (same dataset)','Staged evidence (synthetic)'],horizontal=True)
    if replay_mode=='Policy change (same dataset)':
        st.subheader('DecisionTrace — policy change replay')
        st.write('This replay compares two policies against the **same unchanged dataset**.')
        if st.button('Generate baseline and contextual receipts'):
            base=create_receipt(store,load_policy(ROOT/'policies/default.yaml'),RECEIPTS/'baseline.json')
            contextual=create_receipt(store,load_policy(ROOT/'policies/business-context.yaml'),RECEIPTS/'contextual.json')
            st.session_state['replay']=compare_receipts(base,contextual)
        if st.session_state.get('replay'):
            replay=st.session_state['replay']
            st.metric('Changed group decisions',replay['moved_group_count'])
            st.caption('Cause: '+replay['change_type'])
            st.dataframe([{k:m.get(k) for k in ('label','old_rank','new_rank','old_priority','new_priority','old_score','new_score')}
                          for m in replay['top_movements']],hide_index=True,use_container_width=True)
            with st.expander('Complete evidence and rule-level differences'):
                st.json(replay)
        st.caption('The receipt fingerprint proves input consistency, not the truth of the underlying scanner evidence.')

    else:
        st.subheader('DecisionTrace — staged evidence replay')
        st.info('Synthetic scenario. Three independent databases; one unchanged policy.')
        st.caption('Stage 1: vulnerability evidence → Stage 2: add CIS results → Stage 3: add verified CMDB context.')
        if st.button('Run synthetic evidence stages'):
            from threatweave.staged import run_staged_demo
            with st.spinner('Computing three deterministic evidence snapshots...'):
                st.session_state['staged_evidence']=run_staged_demo(
                    ROOT/'runtime/staged-ui',n_assets=0)
        staged=st.session_state.get('staged_evidence')
        if staged:
            a,b=st.columns(2)
            a.metric('Groups moved after CIS',staged['stage1_to_stage2']['moved_group_count'])
            b.metric('Groups moved after CMDB',staged['stage2_to_stage3']['moved_group_count'])
            st.write('**CIS evidence added:**',staged['stage1_to_stage2']['evidence_changed'])
            st.write('**CMDB evidence added:**',staged['stage2_to_stage3']['evidence_changed'])
            st.subheader('pay-web-01 · synthetic hero asset')
            for name, groups in staged['hero_fix_groups'].items():
                with st.expander(name,expanded=name=='stage3_plus_cmdb'):
                    st.dataframe([{k:g.get(k) for k in
                         ('label','rank','score','priority','compounded_assets_count','matched_rules')}
                         for g in groups],hide_index=True,use_container_width=True)
            with st.expander('Complete stage-to-stage Decision Receipt comparisons'):
                st.json({'cis_added':staged['stage1_to_stage2'],
                         'cmdb_added':staged['stage2_to_stage3']})
            st.caption(staged['evidence_note'])

store.close()

"""Streamlit three-tab ThreatWeave demo. Run: streamlit run dashboard/app.py"""
import json
import os
import sys
import tempfile
import atexit
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
from threatweave.coverage import evidence_coverage
from threatweave.data_sources import source_paths, load_synthetic_isolated
from threatweave.utils import digest

ROOT=Path(__file__).resolve().parents[1]
TENANT_DB=Path(os.getenv('THREATWEAVE_DB',str(ROOT/'runtime/threatweave.db'))).resolve()
STAGED_DIR=(ROOT/'runtime/staged-ui').resolve()
try:
    DATA_PATHS=source_paths(ROOT,TENANT_DB)
except ValueError as exc:
    DATA_PATHS=None
    SOURCE_ERROR=str(exc)
DEMO_DB=DATA_PATHS['Synthetic demo'] if DATA_PATHS else (ROOT/'runtime/demo.db').resolve()
RECEIPTS=Path(os.getenv('THREATWEAVE_RECEIPTS',str(ROOT/'runtime/receipts')))

# A cached Store is reused across Streamlit reruns; clean up on process exit.
@st.cache_resource(show_spinner=False)
def store_registry():
    return {}

# SQLite cross-thread safety for use with st.cache_resource is enabled; the
# app uses the Store's lock when interacting with shared writes.
@st.cache_resource(show_spinner=False)
def open_store(path):
    resource=Store(path,check_same_thread=False)
    atexit.register(resource.close)
    store_registry()[path]=resource
    return resource

def release_stores():
    # Release Windows SQLite handles before replacing staged demo databases.
    for resource in list(store_registry().values()):
        try: resource.close()
        except Exception: pass
    store_registry().clear()
    open_store.clear()

@st.cache_data(show_spinner=False,max_entries=12)
def cached_ranked(db_path, version, policy_hash, policy_json, limit):
    with_store=Store(db_path)
    try:
        return rank_groups(with_store,json.loads(policy_json),max_groups=limit)
    finally:
        with_store.close()

@st.cache_data(show_spinner=False,max_entries=12)
def cached_receipt(db_path, version, policy_hash, policy_json):
    with_store=Store(db_path)
    try:
        return create_receipt(with_store,json.loads(policy_json))
    finally:
        with_store.close()

@st.cache_data(show_spinner=False,max_entries=12)
def cached_coverage(db_path, version):
    with_store=Store(db_path)
    try:
        return evidence_coverage(with_store)
    finally:
        with_store.close()

def invalidate_caches():
    cached_ranked.clear()
    cached_receipt.clear()
    cached_coverage.clear()

st.set_page_config(page_title='ThreatWeave AI',page_icon='🛡️',layout='wide')
st.title('ThreatWeave AI')
st.caption('Evidence-backed exposure correlation · Organizational policy · Decision Replay')

with st.sidebar:
    st.header('DataBridge')
    source=st.selectbox('Data source',['Tenant','Synthetic demo','Staged demo'],key='data_source')
    if source=='Tenant':
        path=TENANT_DB
    elif source=='Synthetic demo':
        path=DEMO_DB
    else:
        stage=st.selectbox('Stage',['Stage 1 · Vulnerabilities','Stage 2 · CIS','Stage 3 · CMDB'],index=2,key='selected_stage')
        stage_names=['stage1_vulnerabilities','stage2_plus_cis','stage3_plus_cmdb']
        path=STAGED_DIR/(stage_names[['Stage 1 · Vulnerabilities','Stage 2 · CIS','Stage 3 · CMDB'].index(stage)]+'.db')
    if DATA_PATHS is None:
        st.error(SOURCE_ERROR)
        st.stop()
    DB=str(path)
    store=open_store(DB)
    st.caption('Database: '+DB)
    st.write('**Source:** '+('Authorized imported tenant records' if source=='Tenant' else 'Isolated synthetic fixtures'))
    if st.button('Load synthetic demo',use_container_width=True,disabled=source!='Synthetic demo',key='load_demo'):
        # Never write demo fixtures into the tenant path.
        load_synthetic_isolated(ROOT,TENANT_DB)
        invalidate_caches()
        st.success('Isolated synthetic fixtures imported into runtime/demo.db')
        st.rerun()
    record_type=st.selectbox('Import record type',['asset','vulnerability','compliance','cmdb'],key='import_type')
    provider=st.selectbox('Evidence provider',['tenable','servicenow-export','generic-export','synthetic'],key='import_provider')
    f=st.file_uploader('Upload CSV, JSON, or JSONL',type=['csv','json','jsonl','ndjson'],key='import_file')
    if st.button('Import uploaded data',disabled=f is None or source=='Staged demo',key='import_uploaded'):
        with tempfile.TemporaryDirectory() as td:
            suffix=Path(f.name).suffix
            uploaded=Path(td)/('input'+suffix)
            uploaded.write_bytes(f.getvalue())
            try:
                with store.lock:
                    result=ingest_file(store,uploaded,record_type,provider)
                invalidate_caches()
                st.json(result)
            except Exception as exc:
                st.error(f'Import failed: {type(exc).__name__}')
    if st.button('Recompute CIS correlations',disabled=source=='Staged demo',key='recompute_correlations'):
        try:
            with store.lock:
                st.json(correlate(store,ROOT/'policies/correlation-rules.yaml'))
            invalidate_caches()
        except Exception as exc:
            st.error(f'Correlation failed: {type(exc).__name__}')
    st.caption('Live Tenable export is available through the CLI using tenant API credentials.')

st.info(('Authorized tenant evidence (not a synthetic demonstration).' if source=='Tenant' else
         'Synthetic demonstration evidence only.')+
        ' No automatic patch execution, scanning, or vendor write-back.')
with store.lock:
    summary=store.overview()
    version=store.data_version()
    coverage=cached_coverage(DB,version)

// Source badges are derived from stored provenance, not a user-supplied label.
asset_badges='  '.join(f"`{r['source']}: {r['count']:,} assets`" for r in coverage['asset_sources'])
finding_badges='  '.join(f"`{r['source']}: {r['count']:,} findings`" for r in coverage['finding_sources'])
st.markdown('**Evidence provenance:** '+(asset_badges or '`no assets`'))
st.caption('Finding sources: '+(finding_badges or 'none'))

a,b,c,d=st.columns(4)
a.metric('Assets',summary['assets'])
b.metric('Findings',summary['findings'])
c.metric('Verified CMDB records',coverage['cmdb']['verified'])
d.metric('CIS correlations',summary['correlations'])
st.caption('Compliance scan hygiene (not failed controls): '
           f"WARNING {summary.get('compliance_scan_hygiene',{}).get('WARNING',0)}  ·  "
           f"ERROR {summary.get('compliance_scan_hygiene',{}).get('ERROR',0)}")

st.subheader('Evidence coverage')
with st.expander('Coverage by source, software family, compliance status and correlation rule',expanded=True):
    x,y=st.columns(2)
    with x:
        st.markdown('**Asset sources**')
        st.dataframe(coverage['asset_sources'],use_container_width=True,hide_index=True)
        st.markdown('**Finding sources**')
        st.dataframe(coverage['finding_sources'],use_container_width=True,hide_index=True)
        st.markdown('**Vulnerability software families**')
        st.dataframe(coverage['software_families'],use_container_width=True,hide_index=True)
        st.caption(f"Unclassified vulnerabilities: {coverage['unclassified_vulnerabilities']:,}")
    with y:
        st.markdown('**Compliance status**')
        st.dataframe(coverage['compliance_status'],use_container_width=True,hide_index=True)
        st.markdown('**CMDB mapping state**')
        st.dataframe([coverage['cmdb']],use_container_width=True,hide_index=True)
        st.markdown('**Correlations by rule**')
        st.dataframe(coverage['correlation_rules'],use_container_width=True,hide_index=True)
    if not summary['types'] or not any(t['kind']=='compliance' and t['count'] for t in summary['types']):
        st.warning('No compliance findings in this dataset: CIS correlations cannot fire. Use Staged demo to illustrate the full flow.')
    if not coverage['cmdb']['verified']:
        st.info('No verified CMDB mappings: business criticality will not change rankings. See Staged demo for verified synthetic context.')

tab_fixes,tab_policy,tab_replay=st.tabs(['Fix Groups & Assets','Policy & Investigation','Decision Replay'])

with tab_fixes:
    st.subheader('Evidence-backed candidate remediation groups')
    st.caption('Groups based on source solution text / check IDs. They are not verified one-patch fixes.')
    policy=load_policy(ROOT/'policies/business-context.yaml')
    groups=cached_ranked(DB,version,digest(policy),json.dumps(policy,sort_keys=True),100)
    if groups:
        table=[{'rank':g['rank'],'label':g['label'],
                'tenable_severity':g.get('max_vendor_severity'),
                'tenable_vpr':g.get('max_vendor_vpr'),
                'contextual_priority':g['priority'],'score':g['score'],
                'assets':g['assets_count'],'production_assets':g['production_assets_count'],
                'compounded_assets':g['compounded_assets_count'],
                'why':', '.join(g['matched_rules']) or 'Vendor evidence only'} for g in groups]
        # Colored priority badges in dataframe only; scalar values remain unmodified.
        def highlight_priority(value):
            return ('color: #e05252; font-weight: bold' if value=='urgent' else
                    'color: #cc8c28; font-weight: bold' if value=='high' else
                    'color: #407eac' if value=='medium' else 'color: #299766')
        import pandas as pd
        st.dataframe(pd.DataFrame(table).style.map(highlight_priority,subset=['contextual_priority']),
                     use_container_width=True,hide_index=True)
        options={g['label']+' · '+g['fix_group_id']:g['fix_group_id'] for g in groups}
        chosen=st.selectbox('Inspect fix group evidence',list(options))
        with store.lock:
            evidence=evidence_for_group(store,options[chosen],limit=15)
        with st.expander('Show raw evidence'):
            st.json(evidence)
    else:
        st.warning('No findings imported. Use “Load synthetic demo” in the sidebar.')
    st.subheader('Asset investigation')
    selected_id=st.text_input('Tenable asset UUID',value='' if source=='Tenant' else ('demo-prod-042' if summary['assets'] else ''))
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
        preview=cached_receipt(DB,version,digest(candidate),json.dumps(candidate,sort_keys=True))
        st.session_state['preview']=preview
    if st.session_state.get('preview'):
        preview=st.session_state['preview']
        st.caption('Unapproved dry-run — not an active policy change')
        st.json({'policy_hash':preview['policy_hash'],
                 'top_groups':preview['rankings'][:5]})
    approved=st.checkbox('I reviewed and approve saving this policy receipt locally')
    if st.button('Approve and generate receipt',disabled=candidate is None or not approved):
        receipt=cached_receipt(DB,version,digest(candidate),json.dumps(candidate,sort_keys=True))
        RECEIPTS.mkdir(parents=True,exist_ok=True)
        (RECEIPTS/'approved-policy.json').write_text(json.dumps(receipt,indent=2),encoding='utf-8')
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
            base_policy=load_policy(ROOT/'policies/default.yaml')
            context_policy=load_policy(ROOT/'policies/business-context.yaml')
            base=cached_receipt(DB,version,digest(base_policy),json.dumps(base_policy,sort_keys=True))
            contextual=cached_receipt(DB,version,digest(context_policy),json.dumps(context_policy,sort_keys=True))
            RECEIPTS.mkdir(parents=True,exist_ok=True)
            (RECEIPTS/'baseline.json').write_text(json.dumps(base,indent=2),encoding='utf-8')
            (RECEIPTS/'contextual.json').write_text(json.dumps(contextual,indent=2),encoding='utf-8')
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
        staged_count=st.selectbox('Additional synthetic assets per stage',[0,5000,50000],key='staged_asset_count')
        if st.button('Run synthetic evidence stages',key='run_stages'):
            from threatweave.staged import run_staged_demo
            with st.spinner('Computing three deterministic evidence snapshots...'):
                release_stores()
                st.session_state['staged_evidence']=run_staged_demo(
                    STAGED_DIR,n_assets=staged_count)
                invalidate_caches()
                st.rerun()
        staged=st.session_state.get('staged_evidence')
        if staged:
            st.markdown('**Elapsed time per stage (seconds)**')
            st.dataframe([{'stage':key,'seconds':seconds} for key,seconds in
                          staged['elapsed_seconds_per_stage'].items()],hide_index=True,use_container_width=True)
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

# Cached Store closes at interpreter shutdown, not at each Streamlit rerun.

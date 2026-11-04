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
from threatweave.ui_workflows import (asset_choices, rule_diff,
    add_drafted_rule_to_yaml, save_approved_policy, rank_replay,
    list_receipt_files, read_receipt)

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
RUNTIME_POLICIES=ROOT/'runtime/policies'


def show_rows(title, rows, *, empty_message='No data available.'):
    st.markdown('**'+title+'**')
    if rows:
        st.dataframe(rows, hide_index=True, use_container_width=True)
    else:
        st.caption(empty_message)


def show_replay_results(replay):
    st.metric('Changed group decisions', replay['moved_group_count'])
    st.markdown('**Change type:** `'+replay['change_type']+'`')
    st.markdown('**Evidence changed:** '+(', '.join('`'+x+'`' for x in replay['evidence_changed']) or '`none / unavailable`'))
    rows=[]
    chart=[]
    for mover in replay['top_movements'][:20]:
        rows.append({k:mover.get(k) for k in
             ('label','old_rank','new_rank','old_priority','new_priority','old_score','new_score',
              'rules_added','rules_removed','contribution_deltas')})
        if mover.get('old_rank') is not None and mover.get('new_rank') is not None:
            chart.append({'group':str(mover['label'])[:48]+' · '+str(mover['fix_group_id'])[:6],
                          'before':mover['old_rank'],'after':mover['new_rank']})
    show_rows('Moved groups and exact policy contribution changes',rows)
    if chart:
        st.caption('Old/new ordinal ranks. Smaller rank number indicates higher priority.')
        st.bar_chart(chart,x='group',y=['before','after'])
    with st.expander('Show raw receipt comparison'):
        st.json(replay)


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
                show_rows('Import summary',[{k:result.get(k) for k in ('provider','record_type','received','accepted','rejected')}])
                with st.expander('Show raw evidence'):
                    st.json(result)
            except Exception as exc:
                st.error(f'Import failed: {type(exc).__name__}')
    if st.button('Recompute CIS correlations',disabled=source=='Staged demo',key='recompute_correlations'):
        try:
            with store.lock:
                correlation_report=correlate(store,ROOT/'policies/correlation-rules.yaml')
                show_rows('Correlation results',[correlation_report])
            invalidate_caches()
        except Exception as exc:
            st.error(f'Correlation failed: {type(exc).__name__}')
    st.markdown('**Data freshness**')
    with store.lock:
        recent_runs=store.recent_ingest_runs(limit=5)
        latest_obs=store.latest_observations()
    show_rows('Last five imports',recent_runs)
    show_rows('Latest observed finding per source',latest_obs,
              empty_message='No finding timestamps supplied.')
    st.caption('Live Tenable export is available through the CLI using tenant API credentials.')

st.info(('Authorized tenant evidence (not a synthetic demonstration).' if source=='Tenant' else
         'Synthetic demonstration evidence only.')+
        ' No automatic patch execution, scanning, or vendor write-back.')
with store.lock:
    summary=store.overview()
    version=store.data_version()
    coverage=cached_coverage(DB,version)

# Source badges are derived from stored provenance, not a user-supplied label.
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
    st.caption('Candidate solution groupings are not verified one-patch fixes. Tenable severity and VPR are unchanged.')
    policy=load_policy(ROOT/'policies/business-context.yaml')
    groups=cached_ranked(DB,version,digest(policy),json.dumps(policy,sort_keys=True),100)
    total_ties=0
    with store.lock:
        # COUNT groups at the maximum displayed score without materializing all groups in the browser.
        # Rank computation remains lazy and cacheable; this count describes only the displayed top 100.
        if groups:
            from collections import Counter
            score_frequency=Counter(g['score'] for g in groups)
            total_ties=sum(n for n in score_frequency.values() if n>1)
    st.caption(f'{total_ties} of {len(groups)} displayed Fix Groups share scores with another displayed group. '
               'Ties sort by compounded, critical, production and total assets, then finding count and stable ID.')
    if groups:
        table=[{'rank':g['rank'],'label':g['label'],
                'tenable_severity':g.get('max_vendor_severity'),
                'tenable_vpr':g.get('max_vendor_vpr'),
                'contextual_priority':g['priority'],'score':g['score'],
                'assets':g['assets_count'],'production_assets':g['production_assets_count'],
                'compounded_assets':g['compounded_assets_count'],
                'why':', '.join(g['matched_rules']) or 'Vendor evidence only'} for g in groups]
        def highlight_priority(value):
            return ('color: #e05252; font-weight: bold' if value=='urgent' else
                    'color: #cc8c28; font-weight: bold' if value=='high' else
                    'color: #407eac' if value=='medium' else 'color: #299766')
        import pandas as pd
        st.dataframe(pd.DataFrame(table).style.map(highlight_priority,subset=['contextual_priority']),
                     use_container_width=True,hide_index=True)
        options={g['label']+' · '+g['fix_group_id']:g['fix_group_id'] for g in groups}
        chosen=st.selectbox('Inspect fix group evidence',list(options),key='fix_group_pick')
        group_id=options[chosen]
        with store.lock:
            evidence=evidence_for_group(store,group_id,limit=25)
        show_rows('Supporting source evidence',evidence['evidence'])
        with st.expander('Show raw evidence'):
            st.json(evidence)
    else:
        st.warning('No findings available in this source. Choose an isolated demonstration source if needed.')
        group_id=None

    st.subheader('Asset investigation')
    hostname_query=st.text_input('Search by hostname (not IP)',key='asset_hostname_search')
    scope=st.radio('Asset selection scope', ['Current Fix Group','All assets'],horizontal=True,
                   key='asset_scope')
    with store.lock:
        candidates=asset_choices(store,
            group_id=group_id if scope=='Current Fix Group' else None,
            hostname_query=hostname_query,limit=100)
    if candidates:
        assets_by_label={
            (str(row['hostname'] or '(no hostname)')+' · '+row['asset_id']+
             ' · '+str(row['findings'])+' findings'):row['asset_id'] for row in candidates}
        asset_label=st.selectbox('Choose an asset (hostname and authoritative UUID)',
                                 list(assets_by_label),key='selected_asset')
        selected_id=assets_by_label[asset_label]
        st.caption('Only the top 100 matches are shown. Narrow by hostname to find others.')
    else:
        selected_id=None
        st.info('No matching assets. Try All assets or another hostname; IP addresses are not used for matching.')
    contextual_asset=st.checkbox('Include contextual priority and CIS rationale',value=True,
                                  key='contextual_asset')
    if st.button('Investigate asset',disabled=not selected_id,key='investigate_asset'):
        with store.lock:
            st.session_state['asset_investigation']={
                'db':DB,'asset_id':selected_id,
                'data':get_asset_exposure(store,selected_id,limit=150,
                        policy=policy if contextual_asset else None)}
    investigation=st.session_state.get('asset_investigation')
    if investigation and investigation.get('db')==DB and investigation.get('asset_id')==selected_id:
        result=investigation['data']
        if not result.get('asset'):
            st.warning('Selected asset not found in the current database.')
        else:
            asset=result['asset']
            st.markdown('**Asset:** '+str(asset.get('hostname') or '(no hostname)'))
            st.caption('Tenable UUID: '+str(asset.get('asset_id')))
            evaluation={x['finding_id']:x for x in result.get('finding_evaluations',[])}
            finding_rows=[]
            for finding in result.get('findings',[]):
                e=evaluation.get(finding['finding_id'],{})
                finding_rows.append({
                    'finding_id':finding['finding_id'], 'type':finding['kind'],
                    'title':finding['title'],'status':finding['status'],
                    'vendor_severity':finding['severity'], 'vendor_vpr':finding['vpr'],
                    'contextual_score':e.get('contextual_score'),
                    'contextual_priority':e.get('contextual_priority'),
                    'matched_rules':', '.join(e.get('matched_rules',[])),
                    'evidence_flags':', '.join(e.get('evidence_flags',[]))})
            show_rows('Findings: vendor vs contextual assessment',finding_rows)
            show_rows('Correlated CIS failures and rationale',result.get('correlated_cis_evidence',[]))
            show_rows('Verified CMDB context',[
                {'business_service':x.get('business_service'),
                 'criticality':x.get('criticality'),
                 'support_group':x.get('support_group'),
                 'environment':x.get('environment')} for x in result.get('cmdb',[])])
            st.caption('Cross-host reachability remains unverified; correlation only joins authoritative same-asset IDs.')
            with st.expander('Show raw evidence'):
                st.json(result)

with tab_policy:
    st.subheader('Human-readable contextual policy')
    active_policy=load_policy(ROOT/'policies/business-context.yaml')
    if 'pending_draft_yaml' in st.session_state:
        st.session_state['policy_editor_yaml']=st.session_state.pop('pending_draft_yaml')
    if 'policy_editor_yaml' not in st.session_state:
        st.session_state['policy_editor_yaml']=(ROOT/'policies/business-context.yaml').read_text(encoding='utf-8')
    raw=st.text_area('Edit draft YAML (no changes become active without approval)',
                     height=285,key='policy_editor_yaml')
    candidate=None
    try:
        candidate=validate_policy(yaml.safe_load(raw))
        st.success('Policy schema validated')
        changes=rule_diff(active_policy,candidate)
        st.markdown('**Rule diff against the active policy**')
        show_rows('Added / removed / modified rules',[
            {'change':name,'rule_ids':', '.join(changes[name]) or 'None'}
            for name in ('added','removed','changed')])
        st.caption(f"Unchanged rules: {changes['unchanged']}")
    except Exception as exc:
        st.error(f'Invalid policy: {type(exc).__name__}: {str(exc)[:180]}')
    if st.button('Preview policy (dry run)',disabled=candidate is None,key='preview_policy'):
        preview=cached_receipt(DB,version,digest(candidate),json.dumps(candidate,sort_keys=True))
        st.session_state['preview']={'db':DB,'receipt':preview}
    preview=st.session_state.get('preview')
    if preview and preview['db']==DB:
        result=preview['receipt']
        st.caption('Unapproved dry-run — no policy change is active')
        st.metric('Candidate Fix Groups',len(result['rankings']))
        show_rows('Top candidate decisions',[
            {k:g.get(k) for k in ('rank','label','priority','score','matched_rules')}
            for g in result['rankings'][:10]])
        with st.expander('Show raw receipt'):
            st.json(result)
    approved=st.checkbox('I reviewed the rule diff and approve saving this policy locally',key='approve_policy')
    if st.button('Approve policy and save versioned YAML + receipt',
                 disabled=candidate is None or not approved,key='approve_receipt'):
        try:
            with store.lock:
                saved=save_approved_policy(store,candidate,ROOT/'runtime')
            st.session_state['approved_policy']=candidate
            st.session_state['approved_receipt']=saved
            st.success('Saved local policy and Decision Receipt: '+saved['receipt_id'])
            show_rows('Saved artifacts',[saved])
        except (ValueError,OSError) as exc:
            st.error('Approval artifact save failed: '+str(exc)[:180])
    with st.expander('Optional: Draft policy with Claude'):
        request=st.text_input('Describe the policy adjustment',
                  value='Prioritize payment systems in production',key='claude_policy_request')
        if st.button('Ask Claude to draft rule',key='draft_claude_rule'):
            try:
                from threatweave.agent import draft_rule
                output=draft_rule(request,candidate or active_policy)
                st.session_state['claude_rule_draft']=output
            except Exception as exc:
                from threatweave.agent import ClaudeUnavailable
                st.error('Draft unavailable: '+(str(exc) if isinstance(exc,ClaudeUnavailable) else type(exc).__name__))
        proposed=st.session_state.get('claude_rule_draft')
        if proposed:
            show_rows('Draft rule — not approved',[proposed['draft_rule']])
            if st.button('Add to YAML editor (draft only)',key='add_claude_to_editor'):
                try:
                    st.session_state['pending_draft_yaml']=add_drafted_rule_to_yaml(raw,proposed)
                    st.session_state['preview']=None
                    st.rerun()
                except (ValueError,TypeError) as exc:
                    st.error('Draft rejected: '+str(exc)[:180])
    if st.button('Run standalone guided investigation (no API key)',key='guided_agent'):
        from threatweave.agent import guided_investigation
        output=guided_investigation(DB,str(ROOT/'policies/business-context.yaml'))
        show_rows('Read-only agent investigation',output.get('investigations',[]))
        with st.expander('Show raw evidence'):
            st.json(output)
    with st.expander('Optional: Ask Claude to investigate'):
        question=st.text_area('Question for the read-only evidence agent',
                    value='Which fixes changed priority because of CIS evidence?',key='claude_question')
        if st.button('Ask ThreatWeave Agent',key='ask_agent'):
            try:
                from threatweave.agent import investigate
                st.write(investigate(question,DB,str(ROOT/'policies/business-context.yaml')))
            except Exception as exc:
                from threatweave.agent import ClaudeUnavailable
                st.error('Agent unavailable: '+(str(exc) if isinstance(exc,ClaudeUnavailable) else type(exc).__name__))

with tab_replay:
    replay_mode=st.radio('Replay scenario',
        ['Policy/receipt comparison','Staged evidence (synthetic)'],horizontal=True,
        key='replay_mode')
    if replay_mode=='Policy/receipt comparison':
        st.subheader('DecisionTrace — compare saved evidence or policies')
        st.caption('A pair of policy inputs runs on the same active dataset; a saved receipt preserves its original evidence fingerprint.')
        policies={p.name: p for p in sorted((ROOT/'policies').glob('*.yaml'))
                  if p.name not in ('correlation-rules.yaml','software-families.yaml')}
        policies.update({'approved · '+p.name:p for p in sorted(RUNTIME_POLICIES.glob('*.yaml'))})
        saved=list_receipt_files(RECEIPTS)
        options={**{'Policy · '+name:('policy',path) for name,path in policies.items()},
                 **{'Receipt · '+name:('receipt',path) for name,path in ((p.name,p) for p in saved)}}
        if st.session_state.get('approved_policy'):
            options['Draft approved in this session']=('session',None)
        keys=list(options)
        if len(keys)<2:
            st.warning('Save two receipts or configure two policy files to compare.')
        else:
            before_label=st.selectbox('Before',keys,index=0,key='replay_before')
            after_label=st.selectbox('After',keys,index=1,key='replay_after')
            if st.button('Compare selected inputs',key='compare_selected_replay'):
                try:
                    def resolve(label):
                        kind,path=options[label]
                        if kind=='receipt':return read_receipt(path)
                        selected=(st.session_state['approved_policy'] if kind=='session'
                                  else load_policy(path))
                        return cached_receipt(DB,version,digest(selected),json.dumps(selected,sort_keys=True))
                    before=resolve(before_label)
                    after=resolve(after_label)
                    st.session_state['replay_result']={'db':DB,
                        'comparison':rank_replay(before,after,limit=25)}
                except (ValueError,OSError,KeyError,TypeError) as exc:
                    st.error('Replay unavailable: '+str(exc)[:180])
            compared=st.session_state.get('replay_result')
            if compared and compared['db']==DB:
                show_replay_results(compared['comparison'])
        st.caption('Rank movements explain computed decisions, not independent scanner correctness.')
    else:
        st.subheader('DecisionTrace — staged evidence replay')
        st.info('Synthetic scenario: three independent databases and one unchanged policy.')
        staged_count=st.selectbox('Additional synthetic assets per stage',[0,5000,50000],key='staged_asset_count')
        if st.button('Run synthetic evidence stages',key='run_stages'):
            from threatweave.staged import run_staged_demo
            with st.spinner('Computing three deterministic evidence snapshots...'):
                release_stores()
                st.session_state['staged_evidence']=run_staged_demo(STAGED_DIR,n_assets=staged_count)
                invalidate_caches()
                st.rerun()
        staged=st.session_state.get('staged_evidence')
        if staged:
            show_rows('Elapsed time per stage (seconds)',[
                {'stage':name,'seconds':seconds} for name,seconds in staged['elapsed_seconds_per_stage'].items()])
            a,b=st.columns(2)
            a.metric('Groups moved after CIS',staged['stage1_to_stage2']['moved_group_count'])
            b.metric('Groups moved after CMDB',staged['stage2_to_stage3']['moved_group_count'])
            st.markdown('**Evidence changed after CIS:** '+', '.join(staged['stage1_to_stage2']['evidence_changed']))
            st.markdown('**Evidence changed after CMDB:** '+', '.join(staged['stage2_to_stage3']['evidence_changed']))
            st.subheader('pay-web-01 · synthetic hero asset')
            for name,hero_groups in staged['hero_fix_groups'].items():
                with st.expander(name,expanded=name=='stage3_plus_cmdb'):
                    show_rows('Compounded candidate Fix Groups',[
                        {k:g.get(k) for k in ('label','rank','score','priority',
                         'compounded_assets_count','matched_rules')} for g in hero_groups])
            with st.expander('Show raw receipt comparisons'):
                st.json({'cis_added':staged['stage1_to_stage2'],
                         'cmdb_added':staged['stage2_to_stage3']})
            st.caption(staged['evidence_note'])

# Cached Store closes at interpreter shutdown, not at each Streamlit rerun.

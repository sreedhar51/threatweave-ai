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
from threatweave.data_sources import (source_paths, tenant_database_choices,
    load_synthetic_isolated, load_enterprise_synthetic_isolated)
from threatweave.utils import digest
from threatweave.ui_workflows import (asset_choices, asset_360, asset_remediation_queue, rule_diff,
    add_drafted_rule_to_yaml, save_approved_policy, rank_replay,
    list_receipt_files, read_receipt)

ROOT=Path(__file__).resolve().parents[1]
CONFIGURED_TENANT_DB=os.getenv('THREATWEAVE_DB')
DEFAULT_TENANT_DB=(ROOT/'runtime/tenant-lab.db').resolve()
STAGED_DIR=(ROOT/'runtime/staged-ui').resolve()
DEMO_DB=(ROOT/'runtime/demo.db').resolve()
RECEIPTS=Path(os.getenv('THREATWEAVE_RECEIPTS',str(ROOT/'runtime/receipts')))
RUNTIME_POLICIES=ROOT/'runtime/policies'


def show_rows(title, rows, *, empty_message='No data available.'):
    st.markdown('**'+title+'**')
    if rows:
        st.dataframe(rows, hide_index=True, use_container_width=True, height=260)
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
    source=st.selectbox('Data source',['Tenant','Synthetic demo','Enterprise demo','Staged demo'],key='data_source')
    try:
        available_tenants=tenant_database_choices(ROOT,CONFIGURED_TENANT_DB)
    except ValueError as exc:
        st.error('Invalid tenant database configuration: '+str(exc))
        st.stop()
    if source=='Tenant':
        if not available_tenants:
            st.error('No existing tenant database found in runtime/. Import Tenable data into tenant-lab.db or set THREATWEAVE_DB to an existing .db file.')
            st.stop()
        selected_tenant=st.selectbox('Tenant database',available_tenants,
                                     format_func=lambda p:p.name, key='selected_tenant_db')
        st.caption('Existing local SQLite files only; selecting never imports or replaces data.')
    else:
        selected_tenant=available_tenants[0] if available_tenants else DEFAULT_TENANT_DB
    TENANT_DB=selected_tenant
    try:
        DATA_PATHS=source_paths(ROOT,TENANT_DB)
    except ValueError as exc:
        st.error('Data-source isolation error: '+str(exc))
        st.stop()
    if source=='Tenant':
        path=TENANT_DB
    elif source=='Synthetic demo':
        path=DEMO_DB
    elif source=='Enterprise demo':
        path=DATA_PATHS['Enterprise demo']
    else:
        stage=st.selectbox('Stage',['Stage 1 · Vulnerabilities','Stage 2 · CIS','Stage 3 · CMDB'],index=2,key='selected_stage')
        stage_names=['stage1_vulnerabilities','stage2_plus_cis','stage3_plus_cmdb']
        path=STAGED_DIR/(stage_names[['Stage 1 · Vulnerabilities','Stage 2 · CIS','Stage 3 · CMDB'].index(stage)]+'.db')
    DB=str(path)
    store=open_store(DB)
    st.caption('Source: '+('Authorized tenant data' if source=='Tenant' else 'Isolated synthetic data'))
    with st.expander('Database path'):
        st.code(DB,language='text')
    st.write('**Source:** '+('Authorized imported tenant records' if source=='Tenant' else 'Isolated synthetic fixtures'))
    if st.button('Load synthetic demo',use_container_width=True,disabled=source!='Synthetic demo',key='load_demo'):
        # Never write demo fixtures into the tenant path.
        load_synthetic_isolated(ROOT,TENANT_DB)
        invalidate_caches()
        st.success('Isolated synthetic fixtures imported into runtime/demo.db')
        st.rerun()
    if st.button('Load enterprise demo (five fictional assets)',use_container_width=True,
                 disabled=source!='Enterprise demo',key='load_enterprise_demo'):
        release_stores()
        load_enterprise_synthetic_isolated(ROOT,TENANT_DB)
        invalidate_caches()
        st.success('Fictional enterprise dataset imported into an isolated local database')
        st.rerun()
    with st.expander('Data import, correlation maintenance and freshness',expanded=False):
        record_type=st.selectbox('Import record type',['asset','vulnerability','compliance','cmdb'],key='import_type')
        provider=st.selectbox('Evidence provider',['tenable','servicenow-export','generic-export','synthetic'],key='import_provider')
        f=st.file_uploader('Upload CSV, JSON, or JSONL',type=['csv','json','jsonl','ndjson'],key='import_file')
        if st.button('Import uploaded data',disabled=f is None or source in ('Staged demo','Enterprise demo'),key='import_uploaded'):
            with tempfile.TemporaryDirectory() as td:
                suffix=Path(f.name).suffix
                uploaded=Path(td)/('input'+suffix)
                uploaded.write_bytes(f.getvalue())
                try:
                    with store.lock:
                        result=ingest_file(store,uploaded,record_type,provider)
                    invalidate_caches()
                    show_rows('Import summary',[{k:result.get(k) for k in ('provider','record_type','received','accepted','rejected')}])
                    st.json(result)
                except Exception as exc:
                    st.error(f'Import failed: {type(exc).__name__}')
        if st.button('Recompute CIS correlations',disabled=source in ('Staged demo','Enterprise demo'),key='recompute_correlations'):
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
with st.expander('Evidence coverage and source quality · details',expanded=False):
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

tab_fixes,tab_policy,tab_replay=st.tabs(['Asset 360 & Fix Groups','Policy & Investigation','Decision Replay'])

with tab_fixes:
    try:
        st.subheader('Asset 360 · investigation and next actions')
        st.caption('Select an asset → review priority work → inspect supporting evidence. Identity is anchored to Tenable UUID; hostname is display/search only.')
        dossier_policy=load_policy(ROOT/'policies/enterprise-context-demo.yaml' if source=='Enterprise demo'
                                  else ROOT/'policies/business-context.yaml')
        dossier_search=st.text_input('Search assets by hostname (not IP)',key='asset360_search')
        with store.lock:
            dossier_choices=asset_choices(store,hostname_query=dossier_search,limit=100)
        if dossier_choices:
            dossier_options={
                str(a['hostname'] or '(hostname unknown)')+' · '+a['asset_id']+
                ' · '+str(a['findings'])+' findings':a['asset_id']
                for a in dossier_choices
            }
            dossier_label=st.selectbox('Select an asset · authoritative UUID',list(dossier_options),key='asset360_pick')
            dossier_id=dossier_options[dossier_label]
            with store.lock:
                dossier=asset_360(store,dossier_id,dossier_policy,limit=200)
            if dossier:
                counts=dossier['counts']
                a360,b360,c360,d360=st.columns(4)
                a360.metric('Vulnerabilities',counts['vulnerabilities'])
                b360.metric('CIS failures',counts['cis_failed'])
                c360.metric('Same-asset correlations',counts['correlations'])
                d360.metric('Verified CMDB records',counts['verified_cmdb'])
                asset360=dossier['asset']
                st.caption('Hostname: '+str(asset360.get('hostname') or '(unknown)')+
                           ' | Tenable asset UUID: '+str(asset360['asset_id']))
                if dossier['same_hostname_asset_count']>1:
                    st.warning('Multiple asset UUIDs share this hostname. Evidence remains isolated for the selected UUID.')
                if dossier['truncated']:
                    st.warning('Showing '+str(dossier['displayed_findings'])+' of '+
                               str(dossier['total_findings'])+
                               ' detailed findings (balanced between vulnerability and CIS evidence). '+
                               'Totals include all stored records for this UUID.')
                st.subheader('Asset owner priority queue · what should be investigated first?')
                st.caption('All active vulnerabilities and failed CIS checks are evaluated. Compounded means rule-qualified CIS support, not a proven attack path.')
                with store.lock:
                    owner_queue=asset_remediation_queue(store,dossier_id,dossier_policy,limit=30)
                owners=owner_queue.get('verified_support_groups',[])
                st.caption('Verified CMDB support groups: '+(', '.join(owners) if owners else
                           'unavailable — owner assignment requires review'))
                priorities=owner_queue['items']
                queue_rows=[{
                    'rank':x['asset_rank'], 'candidate_work':x['label'],
                    'priority':x['priority'], 'score':round(x['score'],1),
                    'severity':x['max_vendor_severity'],
                    'compounded_vulns':x['compounded_vulnerabilities'],
                    'related_failed_CIS':x['related_failed_cis_controls'],
                    'why':', '.join(x['matched_rules']) or 'Scanner evidence only'
                } for x in priorities]
                show_rows('Prioritized candidate remediation work',queue_rows,
                          empty_message='No active vulnerabilities or failed CIS checks for this UUID.')
                if owner_queue['truncated']:
                    st.caption('Showing the top '+str(len(priorities))+' of '+
                               str(owner_queue['total_groups'])+' asset-level candidate groups. '+
                               'Ranking evaluated all eligible findings for this UUID.')
                with st.expander('Explain a work item · policy and linked CIS evidence',expanded=False):
                    if priorities:
                        selected_work=st.selectbox(
                            'Explain a prioritized work item',
                            [str(x['asset_rank'])+' · '+x['label']+' · '+x['fix_group_id']
                             for x in priorities],key='asset360_work_item')
                        chosen_item=priorities[[
                            str(x['asset_rank'])+' · '+x['label']+' · '+x['fix_group_id']
                            for x in priorities].index(selected_work)]
                        st.markdown('**Decision explanation**')
                        st.json({
                            'asset_rank':chosen_item['asset_rank'],
                            'contextual_score':chosen_item['score'],
                            'priority':chosen_item['priority'],
                            'policy':owner_queue['policy_id'],
                            'source_severity':chosen_item['max_vendor_severity'],
                            'source_vpr':chosen_item['max_vendor_vpr'],
                            'rule_contributions':chosen_item['rule_contributions'],
                            'candidate_group_quality':chosen_item['mapping_quality'],
                            'sample_finding_ids':chosen_item['finding_ids'],
                            'evidence_flags':chosen_item['evidence_flags'],
                        })
                        show_rows('Related failed CIS controls supporting this work item',
                                  chosen_item['linked_cis_evidence'],
                                  empty_message='No explicit related failed CIS controls for this work item.')
                with st.expander('Detailed evidence · vulnerability, CIS, correlations and CMDB', expanded=False):
                    ev_vuln,ev_cis,ev_corr,ev_context=st.tabs([
                        'Vulnerabilities', 'CIS posture', 'Correlations', 'Business context'])
                    with ev_vuln:
                        st.caption('A bounded sample of vulnerability findings. The owner queue above evaluates every eligible finding.')
                        show_rows('Scanner values and contextual assessment',dossier['vulnerabilities'],
                                  empty_message='No vulnerabilities in the displayed sample.')
                    with ev_cis:
                        st.caption('WARNING and ERROR denote scan hygiene, not failed controls.')
                        show_rows('CIS status breakdown',[
                            x for x in dossier['status_counts'] if x['kind']=='compliance'],
                            empty_message='No CIS evidence recorded for this asset.')
                        show_rows('CIS control outcomes',dossier['cis'],
                                  empty_message='No CIS checks in the displayed sample.')
                    with ev_corr:
                        st.caption('Explicit same-UUID, rule-qualified relationships; co-location alone is not corroboration.')
                        show_rows('Related vulnerability/CIS evidence',dossier['correlated_cis_evidence'],
                                  empty_message='No rule-qualified same-asset correlations.')
                    with ev_context:
                        show_rows('Verified business context',[{
                            k:r.get(k) for k in ('ci_id','business_service','criticality',
                                                 'environment','role','support_group','internet_exposure')}
                            for r in dossier['cmdb']],
                            empty_message='No verified CMDB mapping; business criticality remains unknown.')
                        st.caption('Candidate Fix Group references: '+str(len(dossier['fix_group_refs']))+' shown.')
                        st.caption('Raw evidence provenance is available in the separate advanced section below.')
        else:
            st.info('No matching asset. Load a synthetic demonstration source or search a different hostname.')
        with st.expander('Asset evidence provenance · diagnostic details', expanded=False):
            if dossier_choices and dossier:
                st.json({'asset_uuid':dossier_id,'counts':dossier['counts'],
                         'fix_groups':dossier['fix_group_refs'],
                         'identity':dossier['identity_note'],
                         'reachability':dossier['reachability_note']})
            else:
                st.caption('Select an asset to see provenance.')
        with st.expander('Portfolio Fix Groups · cross-asset remediation view', expanded=False):
            st.subheader('Evidence-backed candidate remediation groups')
            st.caption('Candidate solution groupings are not verified one-patch fixes. Tenable severity and VPR are unchanged.')
            policy=load_policy(ROOT/'policies/enterprise-context-demo.yaml' if source=='Enterprise demo'
                               else ROOT/'policies/business-context.yaml')
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
                st.caption('Source references shown in the table above; inspect one group at a time.')
            else:
                st.warning('No findings available in this source. Choose an isolated demonstration source if needed.')
                group_id=None


        with st.expander('Advanced · legacy fix-group asset drilldown',expanded=False):
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
                    st.json(result)
    except Exception as exc:
        st.error('Unable to render fixes tab: ' + type(exc).__name__)

with tab_policy:
    try:
        st.subheader('Human-readable contextual policy')
        active_policy=load_policy(ROOT/'policies/enterprise-context-demo.yaml' if source=='Enterprise demo'
                                  else ROOT/'policies/business-context.yaml')
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
                    from threatweave.agent import run_investigation
                    record=run_investigation(question,DB,str(ROOT/'policies/business-context.yaml'))
                    for warning in record.get('warnings',[]):
                        st.warning(warning)
                    st.write(record['answer'])
                except Exception as exc:
                    from threatweave.agent import ClaudeUnavailable
                    st.error('Agent unavailable: '+(str(exc) if isinstance(exc,ClaudeUnavailable) else type(exc).__name__))
        with st.expander('Optional: Claude decision briefs (advisory)'):
            st.caption('Claude recommends the next human action for the top fix groups, citing finding IDs. '
                       'Ranks and scores stay exactly as the engine computed them.')
            brief_count=st.slider('Fix groups to brief',1,5,3,key='claude_brief_count')
            if st.button('Generate decision briefs',key='claude_briefs'):
                try:
                    from threatweave.briefs import generate_briefs
                    output=generate_briefs(DB,str(ROOT/'policies/business-context.yaml'),limit=brief_count)
                    st.caption('Bound to Decision Receipt '+output['receipt_id'])
                    show_rows('Decision briefs — advisory',[{
                        'rank':b['rank'],'fix_group':b['label'],'priority':b['priority'],'status':b['status'],
                        'recommendation':b.get('brief',{}).get('recommendation',''),
                        'confidence':b.get('brief',{}).get('confidence',''),
                        'summary':b.get('brief',{}).get('summary',b.get('reason','')),
                        'injection_flagged':b['injection_flagged']} for b in output['briefs']])
                    st.caption('Full advisory brief details')
                    st.json(output)
                except Exception as exc:
                    from threatweave.agent import ClaudeUnavailable
                    st.error('Briefs unavailable: '+(str(exc) if isinstance(exc,ClaudeUnavailable) else type(exc).__name__))
        with st.expander('Optional: AI finding-pair assessment (advisory only)'):
            st.caption('Explicit opt-in sends bounded finding evidence to Claude. No correlation, policy or score is changed; human review is required.')
            enabled=st.checkbox('Enable AI correlation analysis for this request',value=False,key='ai_pair_enabled')
            vulnerability_id=st.text_input('Vulnerability finding ID',key='ai_pair_vulnerability')
            compliance_id=st.text_input('Failed compliance finding ID',key='ai_pair_compliance')
            if st.button('Assess finding pair with Claude',disabled=not enabled,key='ai_pair_assess'):
                try:
                    from threatweave.correlation_assessment import assess_pair
                    result=assess_pair(DB,vulnerability_id,compliance_id,enabled=enabled)
                    st.caption('Advisory only; a valid citation does not establish factual correctness or an attack path.')
                    st.json(result)
                except Exception as exc:
                    from threatweave.agent import ClaudeUnavailable
                    st.error('Assessment unavailable: '+(str(exc) if isinstance(exc,(ClaudeUnavailable,ValueError)) else type(exc).__name__))
        with st.expander('Optional: Claude correlation proposals (drafts only)'):
            st.caption('Claude reviews same-asset vulnerability and CIS-failure pairs that no rule links yet. '
                       'Proposed rules are never applied; add approved ones to the rules file yourself.')
            if st.button('Review unlinked pairings',key='claude_correlation_proposals'):
                try:
                    from threatweave.correlation_proposals import propose_correlations
                    output=propose_correlations(DB,str(ROOT/'policies/correlation-rules.yaml'))
                    show_rows('Correlation proposals — not applied',[{
                        'software_family':p['candidate']['software_family'],
                        'control':p['candidate']['control_id'] or p['candidate']['control_title'],
                        'pairs':p['candidate']['pair_count'],'status':p['status'],
                        'decision':p.get('decision',''),'confidence':p.get('confidence',''),
                        'rationale':p.get('rationale',p.get('reason',''))} for p in output['proposals']],
                        empty_message='No unlinked same-asset pairings found.')
                    if output['draft_rules_yaml']:
                        st.code(output['draft_rules_yaml'],language='yaml')
                except Exception as exc:
                    from threatweave.agent import ClaudeUnavailable
                    st.error('Proposals unavailable: '+(str(exc) if isinstance(exc,ClaudeUnavailable) else type(exc).__name__))
    except Exception as exc:
        st.error('Unable to render policy tab: ' + type(exc).__name__)

with tab_replay:
    try:
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
    except Exception as exc:
        st.error('Unable to render replay tab: ' + type(exc).__name__)


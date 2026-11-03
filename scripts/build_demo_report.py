"""Create a portable, dependency-free, all-synthetic HTML demo report."""
import html
import json
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from threatweave.store import Store
from threatweave.fixtures import load_demo,ASSETS,VULNS,CIS,CMDB
from threatweave.correlate import correlate
from threatweave.policy import load_policy
from threatweave.engine import create_receipt,compare_receipts

ROOT=Path(__file__).resolve().parents[1]
out=ROOT/'examples/demo-report.html'
s=Store(ROOT/'runtime/report-build.db')
load_demo(s)
correlate(s,ROOT/'policies/correlation-rules.yaml')
a=create_receipt(s,load_policy(ROOT/'policies/default.yaml'))
b=create_receipt(s,load_policy(ROOT/'policies/business-context.yaml'))
diff=compare_receipts(a,b)
original={g['fix_group_id']:g for g in a['rankings']}
rows=[]
for g in b['rankings']:
    old=original.get(g['fix_group_id'])
    def esc(x):return html.escape(str(x))
    rows.append(f'<tr><td><strong>{esc(g["label"])}</strong><span class="sub">{esc(g["mapping_quality"])}</span></td>'
                f'<td>{old["rank"] if old else "–"}</td><td>{g["rank"]}</td>'
                f'<td>{old["score"] if old else "–"}</td><td>{g["score"]}</td>'
                f'<td>{esc(", ".join(g["matched_rules"]) or "Default only")}</td></tr>')

report=f'''<!doctype html><html lang="en"><head><meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>ThreatWeave AI — Synthetic Evidence Demo</title>
<style>
:root{{--bg:#0a1220;--panel:#111f31;--panel2:#16283d;--line:#27425a;--text:#e8f3fc;--muted:#95adc0;--blue:#50d6e8;--gold:#ffd080}}
*{{box-sizing:border-box}}body{{margin:0;background:radial-gradient(circle at 80% 0%,#183651,#0a1220 50%);color:var(--text);font:15px/1.6 Inter,ui-sans-serif,system-ui,-apple-system,sans-serif}}
main{{max-width:1040px;margin:0 auto;padding:44px 24px 80px}}.eyebrow{{letter-spacing:.2em;text-transform:uppercase;font-size:11px;font-weight:750;color:var(--blue)}}
h1{{font-size:clamp(34px,6vw,62px);line-height:1.06;margin:15px 0 12px;letter-spacing:-.045em}}h2{{font-size:23px;letter-spacing:-.025em;margin:45px 0 16px}}p{{color:var(--muted);max-width:760px}}
.tag{{display:inline-block;color:#102a32;background:#85e7ef;border-radius:999px;padding:3px 10px;font-size:12px;font-weight:750}}.note{{padding:14px 17px;border:1px solid var(--line);border-radius:10px;margin:24px 0;color:var(--muted)}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:13px;margin:28px 0}}.metric,.card{{background:linear-gradient(160deg,var(--panel),var(--panel2));border:1px solid var(--line);border-radius:14px;padding:22px}}
.metric strong{{display:block;font-size:34px;line-height:1.2;margin-bottom:4px}}.metric span{{color:var(--muted);font-size:13px}}.timeline{{display:flex;gap:10px;flex-wrap:wrap}}.pill{{background:var(--panel2);border:1px solid var(--line);border-radius:999px;padding:8px 13px;font-size:12px}}.arrow{{color:var(--blue);font-weight:900}}
table{{width:100%;border-collapse:collapse;font-size:13px}}th{{text-align:left;color:var(--muted);font-weight:600;padding:11px 9px;border-bottom:1px solid var(--line)}}td{{padding:14px 9px;border-bottom:1px solid var(--line);vertical-align:top}}.sub{{display:block;font-size:11px;color:var(--muted)}}.table-wrap{{overflow-x:auto;background:var(--panel);padding:15px;border:1px solid var(--line);border-radius:14px}}
.stat{{color:var(--gold);font-weight:750}}.foot{{color:var(--muted);font-size:12px;margin-top:42px}}
</style></head><body><main><div class="eyebrow">ThreatWeave AI / DecisionTrace v0.1</div>
<h1>Prove why security<br/>decisions changed.</h1>
<p>Evidence-qualified vulnerability/CIS correlation, asset-level business context, and reproducible organizational policy replay.</p>
<span class="tag">100% synthetic demonstration — no real tenants or licensed CIS benchmark data</span>
<div class="grid"><div class="metric"><strong>{s.count('assets')}</strong><span>Distinct assets</span></div>
<div class="metric"><strong>{s.count('findings')}</strong><span>Source findings</span></div>
<div class="metric"><strong>{s.count('correlations')}</strong><span>Validated same-asset correlation</span></div>
<div class="metric"><strong>{diff['moved_group_count']}</strong><span>Group decisions changed by policy</span></div></div>
<h2>Evidence journey</h2><div class="timeline"><span class="pill">Tenable asset &amp; vulnerability evidence</span><span class="arrow">→</span><span class="pill">Relevant failed CIS control</span><span class="arrow">→</span><span class="pill">Verified CMDB context</span><span class="arrow">→</span><span class="pill">Approved policy</span><span class="arrow">→</span><span class="pill">Decision Receipt</span></div>
<div class="note">A same-asset correlation is <strong>not</strong> proof of an inter-host attack path. ThreatWeave does not assume network reachability, authentication relationships, or patch success.</div>
<h2>Policy Decision Replay</h2><p>Identical dataset fingerprint under two distinct policies. Priorities change only because the policy changes.</p>
<div class="table-wrap"><table><thead><tr><th>Candidate fix group</th><th>Before rank</th><th>After rank</th><th>Before score</th><th>After score</th><th>Triggered rules</th></tr></thead><tbody>{''.join(rows)}</tbody></table></div>
<h2>Evidence integrity</h2><div class="grid"><div class="card"><div class="eyebrow">Dataset SHA-256</div><code>{a['dataset_hash'][:30]}…</code></div><div class="card"><div class="eyebrow">Baseline receipt</div><code>{a['receipt_id']}</code></div><div class="card"><div class="eyebrow">Contextual receipt</div><code>{b['receipt_id']}</code></div></div>
<p>ThreatWeave keeps original vendor severity and VPR unchanged. Its scores represent only a configurable organizational priority model. Source record hashes provide traceability—not independent truth verification.</p>
<div class="foot">Generated by the local ThreatWeave test fixtures. No network connection, real customer data, or LLM inference was used to compute the report.</div>
</main></body></html>'''
out.write_text(report,encoding='utf8')
print('Generated',out)
# Public, safe fixture exports
(ROOT/'examples/assets.json').write_text(json.dumps(ASSETS,indent=2))
(ROOT/'examples/vulnerabilities.json').write_text(json.dumps(VULNS,indent=2))
(ROOT/'examples/compliance.json').write_text(json.dumps(CIS,indent=2))
(ROOT/'examples/cmdb.json').write_text(json.dumps(CMDB,indent=2))
s.close()

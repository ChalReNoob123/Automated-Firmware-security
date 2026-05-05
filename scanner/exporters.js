/**
 * Scanner Exporters — JSON, CSV, STIX 2.1, Splunk CIM, HTML Dashboard
 */
import { TECHNIQUES } from './mitre.js';

/** Export findings as JSON */
export function exportJSON(session, findings) {
  return JSON.stringify({
    scanSession: {
      id: session.id, startedAt: new Date(session.started_at).toISOString(),
      completedAt: session.completed_at ? new Date(session.completed_at).toISOString() : null,
      status: session.status, riskScore: session.risk_score,
      summary: session.summary ? JSON.parse(session.summary) : null,
    },
    findings: findings.map(f => ({
      ...f,
      risk_factors: JSON.parse(f.risk_factors || '[]'),
      mitre_techniques: JSON.parse(f.mitre_techniques || '[]'),
      ads_streams: JSON.parse(f.ads_streams || '[]'),
    })),
    exportedAt: new Date().toISOString(),
    generator: 'SentinelGrid System Scanner v1.0',
  }, null, 2);
}

/** Export findings as CSV */
export function exportCSV(findings) {
  const headers = ['file_path','file_name','file_size','sha256','entropy','is_signed','signature_status','signer','has_ads','risk_score','status','directory_category','directory_criticality','mitre_techniques','risk_factors','created_at'];
  const escape = (v) => {
    if (v == null) return '';
    const s = String(v);
    return s.includes(',') || s.includes('"') || s.includes('\n') ? `"${s.replace(/"/g, '""')}"` : s;
  };
  const rows = findings.map(f => headers.map(h => escape(f[h])).join(','));
  return [headers.join(','), ...rows].join('\n');
}

/** Export as STIX 2.1 bundle */
export function exportSTIX(session, findings) {
  const stixObjects = [];

  // Identity for scanner
  stixObjects.push({
    type: 'identity', spec_version: '2.1',
    id: `identity--${session.id.slice(0, 36)}`,
    created: new Date(session.started_at).toISOString(),
    modified: new Date().toISOString(),
    name: 'SentinelGrid System Scanner',
    identity_class: 'system',
  });

  for (const f of findings) {
    if (f.risk_score < 20) continue;
    const techniques = JSON.parse(f.mitre_techniques || '[]');
    const factors = JSON.parse(f.risk_factors || '[]');

    // File observable
    const fileId = `file--${crypto?.randomUUID?.() || f.id}`;
    stixObjects.push({
      type: 'file', spec_version: '2.1', id: fileId,
      name: f.file_name,
      hashes: f.sha256 ? { 'SHA-256': f.sha256 } : undefined,
      size: f.file_size,
      extensions: { 'windows-pebinary-ext': { pe_type: f.file_name?.endsWith('.dll') ? 'dll' : 'exe' } },
    });

    // Indicator
    stixObjects.push({
      type: 'indicator', spec_version: '2.1',
      id: `indicator--${f.id}`,
      created: new Date(f.created_at).toISOString(),
      modified: new Date(f.created_at).toISOString(),
      name: `Suspicious file: ${f.file_name}`,
      description: factors.join('; '),
      indicator_types: [f.status === 'critical' ? 'malicious-activity' : 'anomalous-activity'],
      pattern: f.sha256 ? `[file:hashes.'SHA-256' = '${f.sha256}']` : `[file:name = '${f.file_name}']`,
      pattern_type: 'stix',
      valid_from: new Date(f.created_at).toISOString(),
      kill_chain_phases: techniques.map(t => ({
        kill_chain_name: 'mitre-attack',
        phase_name: TECHNIQUES[t]?.tactic || 'unknown',
      })),
    });
  }

  return JSON.stringify({
    type: 'bundle', id: `bundle--${session.id}`, spec_version: '2.1',
    objects: stixObjects,
  }, null, 2);
}

/** Export as Splunk CIM-compatible JSON events */
export function exportSplunkCIM(session, findings) {
  return findings.map(f => JSON.stringify({
    time: Math.floor(f.created_at / 1000),
    sourcetype: 'sentinelgrid:scanner',
    source: 'SentinelGrid',
    host: require('os').hostname(),
    event: {
      action: f.status === 'clean' ? 'allowed' : 'blocked',
      category: ['endpoint', 'file'],
      dataset: 'sentinelgrid.scanner',
      kind: 'alert',
      outcome: f.status,
      risk_score: f.risk_score,
      severity: f.risk_score >= 70 ? 'critical' : f.risk_score >= 40 ? 'high' : f.risk_score >= 20 ? 'medium' : 'low',
      file: {
        name: f.file_name, path: f.file_path, size: f.file_size,
        hash: { sha256: f.sha256 },
        code_signature: { exists: !!f.is_signed, subject_name: f.signer, valid: !!f.is_signed },
      },
      threat: {
        technique: JSON.parse(f.mitre_techniques || '[]').map(t => ({
          id: t, name: TECHNIQUES[t]?.name, reference: `https://attack.mitre.org/techniques/${t.replace('.', '/')}`,
        })),
      },
    },
  })).join('\n');
}

/** Generate interactive HTML dashboard report */
export function exportHTML(session, findings) {
  const summary = session.summary ? JSON.parse(session.summary) : {};
  const critical = findings.filter(f => f.status === 'critical');
  const suspicious = findings.filter(f => f.status === 'suspicious');
  const topRisks = findings.filter(f => f.risk_score >= 20).sort((a, b) => b.risk_score - a.risk_score).slice(0, 100);

  // Aggregate MITRE techniques
  const mitreCounts = {};
  for (const f of findings) {
    for (const t of JSON.parse(f.mitre_techniques || '[]')) {
      mitreCounts[t] = (mitreCounts[t] || 0) + 1;
    }
  }

  return `<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>SentinelGrid Scan Report — ${new Date(session.started_at).toLocaleDateString()}</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Segoe UI',system-ui,sans-serif;background:#0b1120;color:#e2e8f0;min-height:100vh}
.container{max-width:1400px;margin:0 auto;padding:2rem}
h1{font-size:1.75rem;font-weight:800;background:linear-gradient(135deg,#38bdf8,#818cf8);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.header{display:flex;align-items:center;justify-content:space-between;margin-bottom:2rem;padding:1.5rem;background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.08);border-radius:1rem;backdrop-filter:blur(12px)}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:1rem;margin-bottom:2rem}
.stat{padding:1.25rem;background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.06);border-radius:.75rem;text-align:center}
.stat .value{font-size:2rem;font-weight:800;margin:.5rem 0}
.stat .label{font-size:.7rem;text-transform:uppercase;letter-spacing:.15em;color:#94a3b8}
.critical .value{color:#f43f5e}.suspicious .value{color:#f59e0b}.clean .value{color:#34d399}
table{width:100%;border-collapse:collapse;font-size:.8rem;margin-top:1rem}
th{background:rgba(255,255,255,.06);padding:.75rem .5rem;text-align:left;font-weight:600;color:#94a3b8;text-transform:uppercase;font-size:.65rem;letter-spacing:.1em;cursor:pointer;user-select:none}
td{padding:.6rem .5rem;border-bottom:1px solid rgba(255,255,255,.04);max-width:400px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
tr:hover{background:rgba(255,255,255,.03)}
.badge{display:inline-block;padding:.15rem .5rem;border-radius:.25rem;font-size:.65rem;font-weight:700;text-transform:uppercase}
.b-critical{background:rgba(244,63,94,.15);color:#fb7185;border:1px solid rgba(244,63,94,.3)}
.b-suspicious{background:rgba(245,158,11,.15);color:#fbbf24;border:1px solid rgba(245,158,11,.3)}
.b-warning{background:rgba(251,146,60,.15);color:#fb923c;border:1px solid rgba(251,146,60,.3)}
.b-clean{background:rgba(52,211,153,.15);color:#6ee7b7;border:1px solid rgba(52,211,153,.3)}
.risk-bar{height:6px;border-radius:3px;background:#1e293b;position:relative;width:100px}
.risk-fill{height:100%;border-radius:3px;transition:width .3s}
.mitre{margin-top:2rem}.mitre-grid{display:flex;flex-wrap:wrap;gap:.5rem;margin-top:.75rem}
.mitre-tag{padding:.3rem .6rem;background:rgba(99,102,241,.12);border:1px solid rgba(99,102,241,.25);border-radius:.4rem;font-size:.7rem;color:#a5b4fc}
.search{padding:.5rem 1rem;background:rgba(255,255,255,.05);border:1px solid rgba(255,255,255,.1);border-radius:.5rem;color:#e2e8f0;width:100%;max-width:400px;margin-bottom:1rem;font-size:.85rem}
.search:focus{outline:none;border-color:#38bdf8}
</style></head><body>
<div class="container">
<div class="header">
  <div><h1>🛡 SentinelGrid Scan Report</h1><p style="color:#94a3b8;margin-top:.25rem;font-size:.85rem">Session: ${session.id} • ${new Date(session.started_at).toLocaleString()} • Duration: ${((summary.duration || 0) / 1000).toFixed(1)}s</p></div>
  <div style="text-align:right"><span class="badge ${session.risk_score >= 50 ? 'b-critical' : session.risk_score >= 25 ? 'b-suspicious' : 'b-clean'}" style="font-size:.85rem;padding:.4rem .8rem">Risk Score: ${session.risk_score?.toFixed?.(1) || '0'}</span></div>
</div>
<div class="stats">
  <div class="stat clean"><div class="label">Total Files</div><div class="value">${summary.totalFiles || findings.length}</div></div>
  <div class="stat critical"><div class="label">Critical</div><div class="value">${critical.length}</div></div>
  <div class="stat suspicious"><div class="label">Suspicious</div><div class="value">${suspicious.length}</div></div>
  <div class="stat clean"><div class="label">Clean</div><div class="value">${findings.filter(f=>f.status==='clean').length}</div></div>
  <div class="stat"><div class="label">Avg Risk</div><div class="value" style="color:#38bdf8">${(summary.avgRiskScore || 0).toFixed(1)}</div></div>
</div>
<div class="mitre"><h2 style="font-size:1.1rem;font-weight:700">MITRE ATT&CK Coverage</h2>
<div class="mitre-grid">${Object.entries(mitreCounts).sort((a,b)=>b[1]-a[1]).map(([t,c])=>`<span class="mitre-tag">${t} ${TECHNIQUES[t]?.name||''} (${c})</span>`).join('')}</div></div>
<h2 style="font-size:1.1rem;font-weight:700;margin-top:2rem">Findings (${topRisks.length} shown)</h2>
<input class="search" placeholder="Filter findings..." oninput="filterTable(this.value)">
<table id="findings-table"><thead><tr>
<th onclick="sortTable(0)">Risk</th><th onclick="sortTable(1)">Status</th><th onclick="sortTable(2)">File</th><th onclick="sortTable(3)">Path</th><th onclick="sortTable(4)">Size</th><th onclick="sortTable(5)">Entropy</th><th onclick="sortTable(6)">Signed</th><th onclick="sortTable(7)">ADS</th><th onclick="sortTable(8)">SHA-256</th><th>MITRE</th><th>Risk Factors</th>
</tr></thead><tbody>
${topRisks.map(f=>{
  const cls = f.status==='critical'?'b-critical':f.status==='suspicious'?'b-suspicious':f.status==='warning'?'b-warning':'b-clean';
  const riskColor = f.risk_score>=70?'#f43f5e':f.risk_score>=40?'#f59e0b':f.risk_score>=20?'#fb923c':'#34d399';
  const techs = JSON.parse(f.mitre_techniques||'[]').slice(0,3).join(', ');
  const factors = JSON.parse(f.risk_factors||'[]').join('; ');
  return `<tr><td><div class="risk-bar"><div class="risk-fill" style="width:${f.risk_score}%;background:${riskColor}"></div></div><span style="font-size:.7rem">${f.risk_score}</span></td><td><span class="badge ${cls}">${f.status}</span></td><td title="${f.file_name}">${f.file_name}</td><td title="${f.file_path}">${f.file_path?.slice(-60)}</td><td>${(f.file_size/1024).toFixed(1)}K</td><td>${f.entropy?.toFixed(2)||'-'}</td><td>${f.is_signed?'✅':'❌'}</td><td>${f.has_ads?'⚠️':'-'}</td><td title="${f.sha256||''}">${(f.sha256||'').slice(0,12)}…</td><td style="font-size:.65rem">${techs}</td><td style="font-size:.65rem;max-width:200px" title="${factors}">${factors.slice(0,80)}</td></tr>`;
}).join('')}
</tbody></table></div>
<script>
function sortTable(n){const t=document.getElementById('findings-table'),b=t.tBodies[0],rows=[...b.rows];let asc=t.dataset.sortCol==n?t.dataset.sortDir!=='asc':'true';t.dataset.sortCol=n;t.dataset.sortDir=asc?'asc':'desc';rows.sort((a,b)=>{let va=a.cells[n].textContent,vb=b.cells[n].textContent;let na=parseFloat(va),nb=parseFloat(vb);if(!isNaN(na)&&!isNaN(nb))return asc?na-nb:nb-na;return asc?va.localeCompare(vb):vb.localeCompare(va)});rows.forEach(r=>b.appendChild(r))}
function filterTable(q){const rows=document.querySelectorAll('#findings-table tbody tr');q=q.toLowerCase();rows.forEach(r=>{r.style.display=r.textContent.toLowerCase().includes(q)?'':'none'})}
</script></body></html>`;
}

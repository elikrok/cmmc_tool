
import os, json, webbrowser
from datetime import datetime
from pathlib import Path

CHECK_DESCRIPTIONS = {
    'AC.L1-3.1.1': 'Limit system access to authorized users, processes, or devices (AAA + TACACS).',
    'AC.L1-3.1.2': 'Limit users to permitted transactions and functions (privileges/roles), and disable Telnet.',
    'SC.L1-3.13.1': 'Boundary protection for external and key internal boundaries (SSH-only mgmt + ACLs).',
    'SC.L1-3.13.5': 'Separate publicly accessible system components (DMZ) from internal networks.',
    'CM.L1-3.4.1': 'Establish and maintain baseline configuration (Note: CMMC 2.0 Level 2 practice).'
}

CSS = """
body { font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif; margin: 24px; color: #1f2937; }
h1 { font-size: 28px; margin-bottom: 4px; }
.subtitle { color: #6b7280; margin-bottom: 20px; }
.card { border: 1px solid #e5e7eb; border-radius: 12px; padding: 16px; margin-bottom: 16px; box-shadow: 0 1px 2px rgba(0,0,0,0.04); }
.status-pass { color: #065f46; background: #ecfdf5; border: 1px solid #a7f3d0; padding: 2px 8px; border-radius: 999px; font-weight: 600; }
.status-fail { color: #991b1b; background: #fef2f2; border: 1px solid #fecaca; padding: 2px 8px; border-radius: 999px; font-weight: 600; }
.table { width: 100%; border-collapse: collapse; }
.table th, .table td { border-bottom: 1px solid #e5e7eb; padding: 10px; text-align: left; vertical-align: top; }
.small { color: #6b7280; font-size: 12px; }
code { background: #f3f4f6; padding: 2px 4px; border-radius: 6px; }
.badge { font-size: 12px; padding: 2px 8px; border-radius: 999px; border: 1px solid #e5e7eb; color: #374151; background: #f9fafb; }
.kpi { display: inline-block; min-width: 140px; padding: 10px 12px; margin-right: 10px; border-radius: 12px; background: #f9fafb; border: 1px solid #e5e7eb; }
.kpi b { font-size: 18px; display: block; color: #111827; }
.kpi span { color: #6b7280; font-size: 12px; }
.host-summary { margin: 8px 0 0 0; color: #374151; }
"""

def _status_tag(ok: bool) -> str:
    return '<span class="status-pass">PASSED</span>' if ok else '<span class="status-fail">FAILED</span>'

def _summarize(results):
    per_host = {}
    control_totals = {}
    for r in results:
        host = r.get('hostname', 'unknown')
        checks = r.get('checks', {})
        passed = sum(1 for d in checks.values() if d.get('passed'))
        total = len(checks)
        per_host[host] = {'passed': passed, 'total': total, 'compliant': bool(r.get('compliant'))}
        for ctrl, d in checks.items():
            control_totals.setdefault(ctrl, {'passed': 0, 'total': 0})
            control_totals[ctrl]['total'] += 1
            if d.get('passed'):
                control_totals[ctrl]['passed'] += 1
    return per_host, control_totals

def write_json_report(results, output_dir: str) -> str:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    path = out / 'compliance_report.json'
    payload = {
        'generated_utc': datetime.utcnow().isoformat() + 'Z',
        'devices': results
    }
    path.write_text(json.dumps(payload, indent=2), encoding='utf-8')
    return str(path)

def write_html_report(results, output_dir: str, open_in_browser: bool = False) -> str:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    ts = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%SZ')
    per_host, control_totals = _summarize(results)

    rows = []
    for r in results:
        hn = r.get('hostname', 'unknown')
        for ctrl, data in r.get('checks', {}).items():
            desc = CHECK_DESCRIPTIONS.get(ctrl, '')
            passed = bool(data.get('passed'))
            rows.append({'hostname': hn, 'control': ctrl, 'description': desc, 'status': passed, 'notes': data})

    html = ["<html><head><meta charset='utf-8'><title>CMMC Report</title><style>", CSS, "</style></head><body>"]
    html.append('<h1>CMMC Compliance Report</h1>')
    html.append(f"<div class='subtitle'>Generated {ts}. <span class='badge'>HTML + CSV + TXT</span></div>")

    # Executive Summary
    total_hosts = len(per_host)
    hosts_pass = sum(1 for h in per_host.values() if h['compliant'])
    total_controls = sum(v['total'] for v in control_totals.values())
    controls_pass = sum(v['passed'] for v in control_totals.values())
    html.append("<div class='card'>")
    html.append("<h2>Executive Summary</h2>")
    html.append(f"<div class='kpi'><b>{hosts_pass}/{total_hosts}</b><span>Devices compliant</span></div>")
    html.append(f"<div class='kpi'><b>{controls_pass}/{total_controls}</b><span>Controls passed (aggregate)</span></div>")

    html.append("<div class='host-summary'><b>Per-control pass rate:</b> ")
    rates = []
    for ctrl, agg in control_totals.items():
        rate = 0 if agg['total']==0 else round((agg['passed']/agg['total'])*100)
        rates.append(f"<span class='badge'><code>{ctrl}</code> {rate}%</span>")
    html.append(" &nbsp;".join(rates) + "</div>")
    html.append("</div>")

    # Device sections
    by_host = {}
    for r in results:
        by_host.setdefault(r.get('hostname','unknown'), []).append(r)

    for host, _ in by_host.items():
        html.append(f"<div class='card'><h2>{host}</h2><table class='table'>")
        html.append('<tr><th>Control</th><th>Description</th><th>Status</th><th>Notes (JSON)</th></tr>')
        for row in [row for row in rows if row['hostname'] == host]:
            html.append('<tr>')
            html.append(f"<td><code>{row['control']}</code></td>")
            html.append(f"<td>{row['description']}</td>")
            html.append(f"<td>{_status_tag(row['status'])}</td>")
            html.append(f"<td class='small'><pre>{json.dumps(row['notes'], indent=2)}</pre></td>")
            html.append('</tr>')
        html.append('</table></div>')

    html.append('</body></html>')
    path = out / 'compliance_report.html'
    path.write_text('\n'.join(html), encoding='utf-8')
    if open_in_browser:
        try:
            webbrowser.open_new_tab(path.resolve().as_uri())
        except Exception:
            pass
    return str(path)

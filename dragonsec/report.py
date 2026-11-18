import json
from pathlib import Path
from datetime import datetime
import re

def slug(s):
    return re.sub(r"[^A-Za-z0-9_-]+","_",str(s))[:40] or "scan"

def render_markdown(report):
    lines = [f"# {report.get('tool')} — {report.get('scan_type')}", "",
             f"- Target: `{report.get('target')}`",
             f"- Created: `{report.get('created_at')}`", "",
             "## Findings"]
    findings = report.get("findings", [])
    if not findings: lines.append("No findings generated. This is not a guarantee of security.")
    for f in findings:
        lines += [f"### [{f.get('severity')}] {f.get('title')}",
                  f"- Status: {f.get('status','REVIEW')}",
                  f"- Evidence: {f.get('evidence')}",
                  f"- Recommendation: {f.get('recommendation')}", ""]
    if report.get("ai_explanation"): lines += ["## AI explanation", report["ai_explanation"], ""]
    if report.get("notes"): lines += ["## Notes"] + [f"- {n}" for n in report["notes"]]
    return "\n".join(lines)

def save_report(report, outdir):
    d = Path(outdir); d.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    name = f"{stamp}-{slug(report.get('scan_type','scan'))}"
    jp, mp = d/(name+".json"), d/(name+".md")
    jp.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    mp.write_text(render_markdown(report), encoding="utf-8")
    return [str(jp), str(mp)]

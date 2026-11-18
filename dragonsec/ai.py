import os, json
from pathlib import Path
from dotenv import load_dotenv
load_dotenv()

def local_explanation(report):
    findings = report.get("findings", [])
    if not findings:
        return "কোনো finding পাওয়া যায়নি। এটি নিরাপত্তার নিশ্চয়তা নয়; scanner-এর সীমাবদ্ধতা ও manual review বিবেচনা করুন।"
    lines = ["Local AI-style summary (rule-based):"]
    counts = {}
    for f in findings: counts[f.get("severity","INFO")] = counts.get(f.get("severity","INFO"),0)+1
    lines.append("Severity counts: " + ", ".join(f"{k}={v}" for k,v in sorted(counts.items())))
    for f in findings[:12]:
        lines.append(f"- [{f.get('severity')}] {f.get('title')}: {f.get('recommendation')}")
    lines.append("No finding is confirmed exploitable unless independently validated.")
    return "\n".join(lines)

def explain_report(report):
    local = local_explanation(report)
    mode = os.getenv("AI_MODE", "hybrid").lower()
    key, base, model = os.getenv("AI_API_KEY",""), os.getenv("AI_BASE_URL","").rstrip("/"), os.getenv("AI_MODEL","")
    if mode not in ("hybrid","remote") or not (key and base and model):
        return local + "\nRemote AI is not configured; local analysis used."
    try:
        import requests
        payload = {"model": model, "messages": [
            {"role":"system","content":"You are a defensive cybersecurity educator. Analyze only the supplied sanitized scan summary. Do not provide exploit instructions. Distinguish observations from confirmed vulnerabilities. Give prioritized remediation."},
            {"role":"user","content":json.dumps({"scan_type":report.get("scan_type"),"findings":report.get("findings",[])}, ensure_ascii=False)}
        ], "temperature":0.2}
        resp = requests.post(base + "/chat/completions", headers={"Authorization":"Bearer "+key,
            "Content-Type":"application/json"}, json=payload, timeout=25)
        resp.raise_for_status()
        content = resp.json()["choices"][0]["message"]["content"]
        return "LOCAL SUMMARY:\n" + local + "\n\nREMOTE AI REVIEW:\n" + str(content)
    except Exception as e:
        return local + "\nRemote AI unavailable (" + type(e).__name__ + "); local analysis retained."

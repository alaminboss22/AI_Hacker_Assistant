import re, ssl, socket, zipfile, hashlib, os
from pathlib import Path
from urllib.parse import urlparse
from datetime import datetime, timezone
import requests

TIMEOUT = int(os.getenv("REQUEST_TIMEOUT", "12"))
MAX_FILE_MB = int(os.getenv("MAX_FILE_MB", "150"))
UA = "DragonAI-DefensiveScanner/1.0"

def finding(title, severity, evidence, recommendation, status="REVIEW"):
    return {"title": title, "severity": severity, "evidence": evidence,
            "recommendation": recommendation, "status": status}

def base(kind, target):
    return {"tool": "Dragon AI Hacker Assistant", "version": "1.0.0",
            "scan_type": kind, "target": str(target),
            "created_at": datetime.now(timezone.utc).isoformat(),
            "findings": [], "notes": ["Automated results are leads, not proof. Verify manually."]}

def _get(url, method="GET"):
    return requests.request(method, url, timeout=TIMEOUT, allow_redirects=True,
        headers={"User-Agent": UA}, stream=True)

def scan_website(url):
    r = base("Website passive review", url)
    try:
        resp = _get(url, "GET")
        h = {k.lower(): v for k,v in resp.headers.items()}
        r["http"] = {"status": resp.status_code, "final_url": resp.url,
                     "server_header_present": "server" in h,
                     "content_type": h.get("content-type", "")}
        if urlparse(url).scheme != "https":
            r["findings"].append(finding("HTTPS not used", "HIGH",
                "The supplied URL uses HTTP.", "Enable HTTPS and redirect HTTP to HTTPS.", "OBSERVED"))
        checks = [
            ("Strict-Transport-Security", "HSTS header missing", "MEDIUM",
             "Enable HSTS after confirming the entire site is HTTPS."),
            ("Content-Security-Policy", "Content Security Policy missing", "MEDIUM",
             "Define a restrictive CSP appropriate to the site."),
            ("X-Content-Type-Options", "X-Content-Type-Options missing", "LOW",
             "Set X-Content-Type-Options: nosniff."),
            ("Referrer-Policy", "Referrer-Policy missing", "LOW",
             "Set a privacy-appropriate Referrer-Policy."),
            ("Permissions-Policy", "Permissions-Policy missing", "INFO",
             "Restrict browser features the site does not need.")
        ]
        for header, title, sev, rec in checks:
            if header.lower() not in h and (header != "Strict-Transport-Security" or urlparse(url).scheme == "https"):
                r["findings"].append(finding(title, sev, f"{header} response header was not observed.", rec))
        cookies = resp.headers.get("Set-Cookie", "")
        if cookies:
            flags = cookies.lower()
            missing = [x for x in ("secure", "httponly", "samesite") if x not in flags]
            if missing:
                r["findings"].append(finding("Cookie security attributes need review", "MEDIUM",
                    "At least one Set-Cookie response did not show all expected flags: " + ", ".join(missing),
                    "Review each session cookie; use Secure, HttpOnly and an appropriate SameSite value."))
        resp.close()
    except requests.RequestException as e:
        r["findings"].append(finding("Connection failed", "INFO", type(e).__name__,
            "Confirm the URL, DNS, network access and server availability.", "NOT VERIFIED"))
    return r

def scan_api(url):
    r = base("API read-only review", url)
    try:
        resp = _get(url, "GET")
        h = {k.lower(): v for k,v in resp.headers.items()}
        r["http"] = {"status": resp.status_code, "final_url": resp.url,
                     "content_type": h.get("content-type", ""),
                     "allow_header": h.get("allow", ""),
                     "access_control_allow_origin": h.get("access-control-allow-origin", ""),
                     "access_control_allow_credentials": h.get("access-control-allow-credentials", "")}
        origin = h.get("access-control-allow-origin", "")
        cred = h.get("access-control-allow-credentials", "").lower()
        if origin == "*" and cred == "true":
            r["findings"].append(finding("CORS configuration appears inconsistent", "MEDIUM",
                "Wildcard Access-Control-Allow-Origin and credentials=true were both observed.",
                "Review CORS policy and allow only trusted origins. Browser behavior and actual impact need validation."))
        elif origin == "*":
            r["findings"].append(finding("Wildcard CORS observed", "INFO",
                "Access-Control-Allow-Origin: * was returned.",
                "Confirm the endpoint is intentionally public and does not expose sensitive authenticated data."))
        if resp.status_code >= 500:
            r["findings"].append(finding("Server error response", "LOW",
                f"Read-only GET returned HTTP {resp.status_code}.",
                "Review server logs and error handling; this alone does not prove a vulnerability."))
        resp.close()
    except requests.RequestException as e:
        r["findings"].append(finding("API request failed", "INFO", type(e).__name__,
            "Confirm the authorized endpoint and network availability.", "NOT VERIFIED"))
    r["notes"].append("Only one read-only GET request was made. No endpoint discovery, fuzzing or state changes.")
    return r

def scan_apk(path):
    p = Path(path)
    r = base("APK static review", p)
    if not p.is_file():
        r["findings"].append(finding("APK file not found", "INFO", str(p), "Provide a valid local APK path.", "NOT VERIFIED"))
        return r
    if p.stat().st_size > MAX_FILE_MB * 1024 * 1024:
        r["findings"].append(finding("APK exceeds configured size limit", "INFO",
            f"File is larger than {MAX_FILE_MB} MB.", "Increase MAX_FILE_MB only if you trust the file.", "NOT VERIFIED"))
        return r
    sha = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1024*1024), b""): sha.update(chunk)
    r["file"] = {"name": p.name, "size_bytes": p.stat().st_size, "sha256": sha.hexdigest()}
    markers = ["firebase", "admob", "applovin", "mbridge", "mintegral", "unity", "facebook", "pangle", "vungle"]
    urls, sdk, possible = set(), set(), []
    try:
        with zipfile.ZipFile(p) as z:
            names = z.namelist()
            r["apk_entries_count"] = len(names)
            manifest = next((n for n in names if n == "AndroidManifest.xml"), None)
            r["manifest_present"] = bool(manifest)
            if manifest:
                r["findings"].append(finding("Manifest needs Android-aware decoding", "INFO",
                    "APK contains AndroidManifest.xml; this scanner does not decode binary XML.",
                    "Use apktool or Android build tools to inspect permissions, exported components and network security settings.",
                    "NOT VERIFIED"))
            for name in names:
                low = name.lower()
                for m in markers:
                    if m in low: sdk.add(m)
            for name in names:
                if name.endswith("/") or z.getinfo(name).file_size > 8*1024*1024: continue
                if not name.lower().endswith((".xml",".json",".txt",".properties",".js",".html",".cfg",".ini")): continue
                try: data = z.read(name).decode("utf-8", "ignore")
                except Exception: continue
                urls.update(re.findall(r'https?://[A-Za-z0-9._~:/?#\[\]@!$&\'()*+,;=%-]+', data)[:100])
                if re.search(r'(?i)(api[_-]?key|secret|client[_-]?secret|private[_-]?key)\s*[:=]\s*["\'][^"\']{8,}', data):
                    possible.append(name)
            r["url_count"] = len(urls)
            r["url_samples"] = sorted(urls)[:30]
            r["sdk_markers"] = sorted(sdk)
            if possible:
                r["findings"].append(finding("Possible embedded credential pattern", "MEDIUM",
                    f"Pattern match in {len(set(possible))} file(s); values were deliberately not collected.",
                    "Inspect locally. Confirm whether it is a real secret; rotate only confirmed exposed credentials. False positives are common."))
            if sdk:
                r["findings"].append(finding("Third-party SDK markers", "INFO",
                    ", ".join(sorted(sdk)), "Identify exact SDK versions and review vendor security advisories. Marker presence is not a vulnerability."))
    except zipfile.BadZipFile:
        r["findings"].append(finding("Invalid APK archive", "INFO", "File is not a readable ZIP/APK archive.",
            "Verify the APK file and copy it again.", "NOT VERIFIED"))
    return r

def scan_config(target):
    p = Path(target)
    r = base("Local configuration review", p)
    if not p.exists():
        r["findings"].append(finding("Path not found", "INFO", str(p), "Provide an existing local file or directory.", "NOT VERIFIED"))
        return r
    files = [p] if p.is_file() else [x for x in p.rglob("*") if x.is_file()]
    files = [x for x in files if ".git" not in x.parts and "node_modules" not in x.parts and len(files) < 5000]
    patterns = [
        (re.compile(r'(?i)\bdebug\s*=\s*(true|1|yes)\b'), "Debug mode enabled in config", "MEDIUM",
         "Disable debug mode in production."),
        (re.compile(r'(?i)(password|passwd|db_password)\s*[:=]\s*["\'][^"\']+'), "Possible hardcoded password", "HIGH",
         "Move credentials to environment variables or a secret manager; rotate confirmed exposed credentials."),
        (re.compile(r'(?i)allow_url_fopen\s*=\s*on'), "PHP URL fopen enabled", "INFO",
         "Confirm this setting is required and restrict untrusted URL handling."),
        (re.compile(r'(?i)Access-Control-Allow-Origin\s*:\s*\*'), "Wildcard CORS in config", "INFO",
         "Confirm public cross-origin access is intended.")
    ]
    checked = 0
    for f in files:
        if f.suffix.lower() not in (".php",".env",".ini",".conf",".json",".yaml",".yml",".xml",".js",".ts",".py",".txt"): continue
        try:
            if f.stat().st_size > 2*1024*1024: continue
            content = f.read_text(errors="ignore")
        except Exception: continue
        checked += 1
        for pat,title,sev,rec in patterns:
            if pat.search(content):
                r["findings"].append(finding(title, sev, f"Pattern observed in local file: {f.name}; value omitted.", rec))
    r["files_checked"] = checked
    r["notes"].append("Local pattern review only. Values and full file contents are not copied to the report.")
    return r

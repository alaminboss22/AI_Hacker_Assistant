#!/usr/bin/env python3
import argparse, json, os, sys
from pathlib import Path
from datetime import datetime, timezone
from dragonsec.scans import scan_website, scan_api, scan_apk, scan_config
from dragonsec.ai import explain_report
from dragonsec.report import save_report, render_markdown

BANNER = r"""
 ____                              ___    ___
|  _ \ _ __ __ _  __ _  ___  _ __ / _ \  |_ _|
| | | | '__/ _` |/ _` |/ _ \| '_ \ | | |  | |
| |_| | | | (_| | (_| | (_) | | | | |_| |  | |
|____/|_|  \__,_|\__, |\___/|_| |_|\___/  |___|
                 |___/   HACKER ASSISTANT
"""

def main():
    p = argparse.ArgumentParser(description="Defensive security assistant for authorized assets.")
    sub = p.add_subparsers(dest="cmd")
    sub.add_parser("doctor", help="Check Python environment")
    for name in ("website", "api", "apk", "config"):
        q = sub.add_parser(name)
        q.add_argument("target", help="URL or local file/folder")
        q.add_argument("--out", default="reports", help="Report directory")
    a = sub.add_parser("analyze")
    a.add_argument("report", help="Existing JSON report")
    args = p.parse_args()
    print(BANNER)
    if args.cmd == "doctor":
        import requests
        print("Python:", sys.version.split()[0])
        print("requests:", requests.__version__)
        print("Home:", Path.home())
        print("Status: ready")
        return
    if args.cmd == "analyze":
        data = json.loads(Path(args.report).read_text(encoding="utf-8"))
        data["ai_explanation"] = explain_report(data)
        print(data["ai_explanation"])
        return
    if not args.cmd:
        p.print_help()
        return
    print("Authorization reminder: scan only assets you own or are permitted to test.")
    if args.cmd in ("website", "api"):
        from urllib.parse import urlparse
        u = urlparse(args.target)
        if u.scheme not in ("http", "https") or not u.hostname:
            p.error("Target must be a valid http:// or https:// URL")
    if args.cmd == "website":
        report = scan_website(args.target)
    elif args.cmd == "api":
        report = scan_api(args.target)
    elif args.cmd == "apk":
        report = scan_apk(args.target)
    else:
        report = scan_config(args.target)
    report["ai_explanation"] = explain_report(report)
    paths = save_report(report, args.out)
    print(render_markdown(report))
    print("\nSaved reports:")
    for x in paths: print(" ", x)

if __name__ == "__main__":
    main()

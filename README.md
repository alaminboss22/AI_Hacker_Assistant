# Dragon AI Hacker Assistant

A Termux-first, hybrid-AI **defensive security assistant** for systems you own or are explicitly authorized to assess.

## Included
- Website passive checks: HTTPS, security headers, cookie flags, redirect behavior, TLS certificate dates (where Python/OpenSSL supports it).
- API read-only checks: response headers, content type, status, and basic CORS configuration review. No fuzzing or state-changing requests.
- APK static review: archive inventory, binary-manifest notice, SDK markers, URL inventory, and cautious secret-pattern indicators (values are never printed).
- Local configuration review: detects risky configuration patterns in files you provide.
- Hybrid assistant: deterministic local explanations; optional remote AI via an OpenAI-compatible chat-completions endpoint.
- JSON and Markdown reports.

## Safety boundary
Only scan assets you own or have written permission to test. This tool does not exploit vulnerabilities, brute-force credentials, bypass anti-cheat, manipulate rewards, dump databases, or access user data. Website/API checks are low-impact GET/HEAD requests to the exact target only.

## Termux installation
```bash
pkg update -y
pkg install python git unzip openssl-tool -y
termux-setup-storage
cd ~
unzip ~/storage/shared/Download/Dragon_AI_Hacker_Assistant.zip
cd Dragon_AI_Hacker_Assistant
python -m pip install -r requirements.txt
cp .env.example .env
python dragon.py doctor
```

Run:
```bash
python dragon.py
```

## Commands
```bash
python dragon.py website https://example.com --out reports
python dragon.py api https://api.example.com/health --out reports
python dragon.py apk /path/to/your.apk --out reports
python dragon.py config /path/to/your/project --out reports
python dragon.py analyze reports/report-....json
```

`website` and `api` accept only HTTP(S) URLs and do not follow links or enumerate endpoints. Use only an authorized test URL. `config` scans local files only.

## Hybrid AI setup
Local analysis works without an AI key. To enable remote explanations, edit `.env`:
```ini
AI_MODE=hybrid
AI_BASE_URL=https://api.openai.com/v1
AI_MODEL=YOUR_AVAILABLE_MODEL
AI_API_KEY=YOUR_API_KEY
```
The API key is read from the environment/config and is never included in reports. Keep `.env` private; it is excluded from Git.

For another OpenAI-compatible provider, set its base URL and model. Network AI is optional; findings are generated locally first. Do not upload APKs, source code, credentials, or private reports to a remote AI provider unless you have permission.

## GitHub
```bash
git init
git add .
git commit -m "Initial Dragon AI Hacker Assistant"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/Dragon-AI-Hacker-Assistant.git
git push -u origin main
```

## Limitations
- Static APK review is not full Android decompilation. Install `apktool` separately if you want a decoded manifest; this version reports binary manifests as unverified rather than claiming no permissions.
- Pattern matches are leads, not confirmed secrets or vulnerabilities.
- CORS and headers are contextual; a missing header is not automatically exploitable.
- Remote AI can be wrong. Verify findings manually.

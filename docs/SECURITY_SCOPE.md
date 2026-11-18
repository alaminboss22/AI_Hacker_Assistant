# Security scope

Allowed: passive checks and static review of owned/authorized assets; local training labs; remediation guidance.

Not implemented: exploitation, credential attacks, brute force, stealth, persistence, malware, anti-cheat bypass, reward manipulation, destructive tests, database dumping, or scanning arbitrary IP ranges.

The tool intentionally sends at most one simple GET request per website/API command, follows normal HTTP redirects, and does not crawl or enumerate routes. Use a staging environment whenever possible.

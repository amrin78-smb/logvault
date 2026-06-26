---
name: logvault-enterprise-roadmap-status
description: Status of the LogVault enterprise-hardening roadmap — which phases are done, deferred, or skipped
metadata:
  type: project
---

Enterprise-hardening roadmap derived from a multi-agent audit (vs Log360/Splunk/Sentinel/Graylog/Wazuh), as of June 2026:

- **Phase 0 — security hygiene: DONE** (v1.5.0). Removed hardcoded credential fallbacks, scrubbed secrets from repo, conditional Secure cookies, collector source-IP allow-list + rate-limit (default off), `acknowledged_by`, alert threshold `>=` fix.
- **Phase 3 (scoped) — storage/durability/trust: DONE** (v2.0.0). Daily-partitioned `syslog_entries` + DROP-partition retention, HMAC hash-chain integrity (`prev_hash`/`entry_hash`, `LOG_INTEGRITY_KEY`), durable disk ingest spool, append-only audit trail (`audit_log` + `api/auditLog.js`, `GET /api/audit`).
- **Phase 1 — DEFERRED to SecVault** (compliance reports, MITRE). See [[secvault-division-of-labor]].
- **Phase 2 — detection maturity: PARTIAL.** GeoIP + threat-intel enrichment was pulled forward and shipped in **v2.1.0** (`collector/geoEnrich.js`: ip-api.com geo + optional AbuseIPDB scoring → `known_hosts`; `abuseipdb_api_key` app_setting; `GET /api/threats/known-bad`; "Known-Bad Sources" dashboard widget). Still deferred: UEBA/ML anomaly, IOC/STIX feeds, multi-channel alerting (Slack/Teams/PagerDuty), user-editable correlation rules, custom-parser UI, query language.
- **Phase 3 longer-term — SKIPPED**: HA/replication/DR, case management, SOAR, ITSM integration, multi-tenancy.

**Open Critical loose end:** the exposed `NEXTAUTH_SECRET` + DB passwords were scrubbed from the repo but NOT rotated — they remain in git history and live. Rotation is still pending.

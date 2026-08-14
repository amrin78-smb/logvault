---
name: logvault-enterprise-roadmap-status
description: Status of the LogVault enterprise-hardening roadmap — which phases are done, deferred, or skipped
metadata:
  type: project
---

Enterprise-hardening roadmap derived from a multi-agent audit (vs Log360/Splunk/Sentinel/Graylog/Wazuh). **Re-verified against live code + the production DB on 2026-08-14** — the June note understated what had shipped.

- **Phase 0 — security hygiene: DONE** (v1.5.0). Removed hardcoded credential fallbacks, scrubbed secrets from repo, conditional Secure cookies, collector source-IP allow-list + rate-limit (default off), `acknowledged_by`, alert threshold `>=` fix.
- **Phase 3 (scoped) — storage/durability/trust: DONE** (v2.0.0). Daily-partitioned `syslog_entries` + DROP-partition retention, HMAC hash-chain integrity (`prev_hash`/`entry_hash`, `LOG_INTEGRITY_KEY`), durable disk ingest spool, append-only audit trail (`audit_log` + `api/auditLog.js`, `GET /api/audit`).
- **Phase 1 — compliance reports DEFERRED to SecVault.** See [[secvault-division-of-labor]]. **MITRE was NOT deferred in practice** — LogVault shipped it anyway (see below).
- **Phase 2 — detection maturity: LARGELY SHIPPED**, contrary to the June note. Live modules: `collector/correlationEngine.js` (532 lines, sliding-window multi-event rules), `collector/riskScorer.js` (0-100 per entry), `collector/mitreMapper.js` (event-level technique tagging into `structured_data.mitre`) + `alert_rules.mitre_techniques` + a `mitre-coverage` report, `collector/geoEnrich.js` (ip-api.com geo + AbuseIPDB), and a full UEBA stack under `collector/analytics/` (`baselineBuilder`, `anomalyDetector`, `uebaRollup`, `relayHosts`) feeding `entity_baselines` / `anomaly_events` / `entity_risk`. `api/soc.js` adds a SOC console (overview, digest, kill-chain, entity timeline).
  Still genuinely absent: IOC/STIX feeds, multi-channel alerting (Slack/Teams/webhook — **SMTP is the ONLY channel**), user-editable correlation rules, custom-parser UI, query language.
- **Phase 3 longer-term — SKIPPED**: HA/replication/DR, case management, SOAR, ITSM integration, multi-tenancy.

**⚠ The binding constraint is LOG COVERAGE, not features** (measured 2026-08-14). 12.7M entries over 55 days, but **100% of the last 24h is `fortinet`** — and only allowed-traffic + VPN session logs (see [[logvault-fortigate-logging-scope]]). Consequences, all measured:
- **MITRE tagging matched 1 of 1,556,353 events in 7 days.** The mapper works; the source data contains almost nothing mappable.
- **5 of 7 alert rules have never fired** (Auth Failures, Repeated IPS Triggers, Emergency Events, Brute Force Login Success, VPN Brute Force) — they need auth/deny/UTM logs that aren't being sent. Only Port Scan (18) and Critical Threshold (9) fire.
- **UEBA anomalies are 97% `silent`** (2,073 of 2,079 in 7d — "entity went quiet"), with 3 `new_geo` and 3 `new_service`. Populated but low-signal.
Adding more detection sophistication returns close to nothing until more log sources are onboarded. Prioritise sources (Windows Security, switches, WLC, DNS, and FortiGate's own auth/deny/UTM facilities) over new analytics.

**Open Critical loose end:** the exposed `NEXTAUTH_SECRET` + DB passwords were scrubbed from the repo but NOT rotated — they remain in git history and live. Rotation is still pending.

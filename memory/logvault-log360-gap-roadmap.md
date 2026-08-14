---
name: logvault-log360-gap-roadmap
description: KIV — LogVault mapped against the ManageEngine Log360 architecture; what exists, what's missing, what belongs to SecVault, and the phased plan (nothing started)
metadata:
  type: project
---

**STATUS: KIV (2026-08-14). Analysis only — nothing built, nothing started.** Raised from a
Log360 "How Log360 works" architecture diagram; the question was which boxes LogVault already
covers and which are worth adding. Every claim below was measured against the live code and the
production DB on 2026-08-14, not inferred.

## The headline: the binding constraint is LOG COVERAGE, not features

Most of the engine is already built and running on near-empty input:

- **12.7M entries over 55 days, but 100% of the last 24h is `fortinet`** — and only
  allowed-traffic + VPN session logs (see [[logvault-fortigate-logging-scope]]). The parsers for
  cisco, paloalto, aruba, checkpoint, juniper, sangfor, sonicwall, forcepoint and windows have
  **no live feed at all**.
- **MITRE tagging matched 1 event out of 1,556,353 in 7 days.** `collector/mitreMapper.js` works;
  the source data contains almost nothing mappable.
- **5 of 7 alert rules have never fired** — Auth Failures, Repeated IPS Triggers, Emergency
  Events, Brute Force Login Success, VPN Brute Force. All need auth/deny/UTM logs that aren't
  being sent. Only Port Scan (18) and Critical Threshold (9) fire.
- **UEBA anomalies are 97% `silent`** (2,073 of 2,079 in 7d = "entity went quiet"), plus 3
  `new_geo` and 3 `new_service`. Populated but low-signal.

⚠ **Adding detection sophistication returns close to nothing until more sources are onboarded.**
Any future session tempted to start at "build the detection feature" should re-read this.

## Mapped against the Log360 diagram

**Already covered:** data collector/processor engine (syslog ingest, 11 parsers, taxonomy,
`riskScorer.js`, disk spool, daily partitions); contextual enrichment (GeoIP, DNS lookup, NetVault
asset sync, category, 0-100 risk); real-time correlation (`correlationEngine.js`, 532 lines,
sliding windows); behavioural analytics / UEBA (`collector/analytics/` — 2,808 baselines, 5,796
anomalies, 10,978 entity-risk rows); incident + user timelines (`api/soc.js` kill-chain and
entity-timeline, `KillChainTimeline.tsx`); security analytics + widgets (SOC overview, Security
tab); reporting (3 templates: security-summary, site-activity, mitre-coverage).

**Partial:** threat intelligence (AbuseIPDB + ip-api.com, 47,360 known hosts — but no IOC/STIX
feeds); "ML" anomaly detection (statistical baselines, NOT ML — the user is aware); MITRE (built,
but see the SecVault conflict below); long-term search (12.7M rows, but only 55 days).

**Missing — worth adding:** data archival bucket (retention DROPs partitions with no export —
data is destroyed at 55 days); response engine / playbooks (nothing exists); multi-channel
alerting (**SMTP is the ONLY channel** — no webhook/Slack/Teams/PagerDuty); incident workbench
(only an `acknowledged` flag, no case object/assignee/notes/status); third-party integration
(no outbound webhook, ticketing or SOAR).

**Missing — NOT ours:** the entire Security & Risk Posture module (standards repository, posture
dashboard, misconfiguration fixes, risk mitigation) is SecVault scope per
[[secvault-division-of-labor]].

**Recommend against:** the Dark web data processor — it requires a paid third-party dark-web
crawling subscription, not something to build in-house.

## ⚠ Unresolved contradiction to decide

[[secvault-division-of-labor]] assigns MITRE ATT&CK to SecVault, but **LogVault built it anyway**
(`collector/mitreMapper.js`, `alert_rules.mitre_techniques`, a `mitre-coverage` report,
`components/mitre.tsx`). That drifted rather than being decided. Pick one owner before either
product invests further.

## The phased plan (proposed, NOT started)

- **Phase A — log coverage. Do this first; almost no code.** Enable FortiGate's own auth/deny/UTM
  facilities; onboard Windows Security (NXLog), the Aruba controllers, switches and DNS. This is
  what makes everything already built start working — it revives the 5 dormant rules, gives MITRE
  something to match, and makes UEBA meaningful. (Bonus: the Aruba controller feed would also give
  SpanVault the radar ground truth its channel-change `inferred_cause` currently lacks.)
- **Phase B — outbound channel.** One generic webhook dispatcher → Teams/Slack, plus alert
  workflow (status, assignee, notes). Turns the Alerts tab into a workbench and is the same
  primitive that later opens ticketing/SOAR.
- **Phase C — archival + IOC feeds.** Export-before-drop to compressed cold storage (retention
  currently destroys data outright); free IOC feeds (abuse.ch URLhaus/Feodo, Spamhaus DROP)
  matched at ingest — no paid dependency.
- **Phase D — anomaly quality.** The `silent` detector produces 97% of the volume and almost none
  of the value. Same treatment given to the DDIVault alert tuning and the SpanVault pattern
  detector: sustain + floors, and never report absent data as a confirmed zero.

Recommendation on record: **start at Phase A or not at all** — B/C/D on top of one firewall's
allowed-traffic logs is polish on an empty pipeline.

See [[logvault-enterprise-roadmap-status]] for which earlier phases already shipped (that note was
itself stale until corrected on 2026-08-14 — it recorded UEBA and MITRE as deferred when both had
shipped).

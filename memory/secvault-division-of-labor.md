---
name: secvault-division-of-labor
description: SecVault (planned firewall-analyzer product) owns compliance/firewall scope; what LogVault deliberately does NOT build
metadata:
  type: project
---

The user is planning to build **SecVault**, a separate NocVault-suite product modeled on **ManageEngine Firewall Analyzer** (firewall traffic/bandwidth analytics, rule/policy optimization, firewall config change management, VPN/proxy reports, and firewall-device compliance reports: PCI/ISO/NIST/SANS ruleset audits).

Because SecVault will own that scope, LogVault **deliberately defers / will NOT build**:
- Out-of-box compliance reports (PCI-DSS/ISO27001/HIPAA/GDPR/SOX) and MITRE ATT&CK mapping → SecVault.
- Firewall traffic/bandwidth analytics, firewall rule optimization, VPN/proxy reports → SecVault.

LogVault **kept** (because SecVault, a firewall analyzer, can't vouch for LogVault's own stored logs): the immutable **audit trail** and **tamper-evident log integrity** — both shipped in Phase 3.

**Why:** avoid duplicating effort across suite products; SecVault is the compliance/firewall flagship, LogVault is the syslog/SIEM analyzer.
**How to apply:** when scoping a LogVault feature that's compliance- or firewall-analytics-shaped, default to "that belongs in SecVault" unless it's about LogVault's own log store integrity/accountability. See [[logvault-enterprise-roadmap-status]].

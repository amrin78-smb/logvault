# LogVault Changelog

<!--
RELEASE PROCESS
  1. Make and test your changes; ensure `frontend && npm run build` passes.
  2. Bump "version" in the root package.json (and frontend/package.json) using
     semantic versioning: MAJOR.MINOR.PATCH.
  3. Add a new "## vX.Y.Z — YYYY-MM-DD" section at the TOP of this file (below
     this comment), describing the changes under ### headings.
  4. Commit and push to main. The API reads the latest version + this section
     from GitHub raw and surfaces them in the in-app update notifier / Settings.

  Notes:
    - Keep the newest release at the top — the API parses the FIRST "## " header.
    - This comment block is stripped before parsing, so the indented example
      "## v..." lines below are never mistaken for a real release header.
    - Example header format: "## v1.1.0 — 2026-07-01"
-->

## v1.0.0 — 2026-06-08
### Initial Release
- Syslog collection for 10 vendors (Fortinet, Cisco, Palo Alto, Aruba, Sangfor, Forcepoint, Check Point, Juniper, Windows, SonicWall)
- Real-time dashboard with severity, traffic and alert widgets
- Smart Log Explorer with category and vendor filter chips
- Universal event taxonomy with 14 categories
- Risk scoring (0-100) per log entry
- Alert rules with deduplication and 30-minute suppression
- Email alerting via SMTP
- NetVault asset enrichment with site-based RBAC
- DNS reverse lookup enrichment
- Network Health tab with interface, routing, wireless monitoring
- License enforcement from NocVault hub
- Self-update from Settings UI

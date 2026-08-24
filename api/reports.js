'use strict';

/**
 * reports.js — Phase 1 reporting engine for LogVault.
 *
 * Ported from DDIVault's api/reports.js pattern: a REPORTS registry
 * `{ key: { title, gather(db, query, rbac) } }`, one generic Express router
 * handling GET /api/reports/:type?format=json|csv|pdf, shared pdfkit
 * rendering (cover page, summary tiles, vector charts, zebra-striped table).
 *
 * RBAC CONTRACT DIFFERS FROM DDIVAULT: DDIVault's router passes a plain
 * `allowedSiteIds` array into gather(). LogVault's rbacMiddleware instead
 * attaches the WHOLE `req.rbac` object ({ userId, role, isSuperAdmin,
 * isAdmin, allowedSiteIds }), and site-scoping is applied per-query via the
 * getSiteFilter/getStatsSiteFilter/getAlertSiteFilter helpers in ./rbac —
 * so every gather() here takes the full `rbac` object and calls those
 * helpers itself, exactly like the existing /api/stats/* endpoints in
 * server.js that these reports reuse the query logic from.
 *
 * pdfCharts.js's renderTrendChart (ported alongside this file) is a
 * single-series, 0-100%, time-axis primitive — DDIVault uses it only for its
 * DHCP scope-health per-scope trend blocks. LogVault's Phase 1 `charts[]`
 * payload (severity distribution, category breakdown, vendor breakdown,
 * top techniques, multi-day log volume) is multi-series/bar/categorical, so
 * it's rendered here via the generic ChartSpec `drawChart` primitive instead
 * (the same one DDIVault's own trend reports — dhcp-utilization-trend,
 * dns-query-trend, alert-anomaly-trend — use for this exact `{type, title,
 * x, series, yFormat}` shape). renderTrendChart stays available for a future
 * single-series per-device/per-site trend block.
 */

const express = require('express');
const PDFDocument = require('pdfkit');
const { getSiteFilter, getStatsSiteFilter, getAlertSiteFilter, getRollupSiteFilter } = require('./rbac');
const { escapeCsvCell } = require('./csv');
// renderTrendChart is ported into ./pdfCharts.js for future single-series
// trend blocks (see header comment above) but is not wired in here.

// ── Brand palette (matches LogVault's design system — same tokens as DDIVault) ──
const RED = '#C8102E';
const NAVY = '#1a2744';
const MUTED = '#64748b';
const LIGHT = '#f1f5f9';
const BORDER = '#e2e8f0';
const GREEN = '#16a34a';
const YELLOW = '#d97706';

// Reports cover longer periods than the live dashboard (default 24h stats
// endpoints cap at 720h). Same safeHours() shape as api/server.js, reused
// here with a higher ceiling (90 days) — LogVault reports are period-based,
// not the from/to date-range DDIVault reports use.
const MAX_REPORT_HOURS = 2160;
function safeHours(val, max = MAX_REPORT_HOURS) {
  const n = Math.min(parseInt(val || '24') || 24, max);
  return isNaN(n) || n <= 0 ? 24 : n;
}

// ── PDF glyph safety ──────────────────────────────────────────
// pdfkit's built-in Helvetica renders with WinAnsi (CP1252) encoding, which lacks
// many of the Unicode glyphs used in labels/summaries (→ ≥ ≤ – — • curly quotes,
// NBSP). pdfSafe maps them to ASCII equivalents. Applied ONLY at the pdfkit text
// layer — the JSON and CSV outputs keep the original Unicode untouched.
function pdfSafe(s) {
  if (s == null) return '';
  return String(s)
    .replace(/[→➜➔➙➡⇒⮕]/g, 'to')
    .replace(/≥/g, '>=')
    .replace(/≤/g, '<=')
    .replace(/[–—―]/g, '-')
    .replace(/•/g, '-')
    .replace(/[‘’‚‛]/g, "'")
    .replace(/[“”„‟]/g, '"')
    .replace(/ /g, ' ');
}
function installPdfSafeText(doc) {
  const origText = doc.text.bind(doc);
  doc.text = (text, ...rest) => origText(pdfSafe(text), ...rest);
  return doc;
}

async function companyName(db) {
  try {
    const r = await db.query("SELECT value FROM app_settings WHERE key = 'app_name'");
    return (r.rows[0] && r.rows[0].value) || 'LogVault';
  } catch { return 'LogVault'; }
}

// ── Input validation (hardening) ──────────────────────────────
class BadRequestError extends Error {
  constructor(message) { super(message); this.name = 'BadRequestError'; this.status = 400; }
}

// ── Chart primitives (generic ChartSpec renderer) ──────────────
const SERIES_COLORS = ['#3b82f6', RED, GREEN, YELLOW, '#8b5cf6', '#0ea5e9'];

function fmtAxis(v, yFormat) {
  const r = Math.round(v);
  if (yFormat === 'percent') return `${r}%`;
  if (yFormat === 'ms') return `${r}ms`;
  return `${r}`;
}

/**
 * Draw one ChartSpec into the PDF using vector primitives only.
 * chart: { type:'line'|'area'|'bar', title, x:[], series:[{label,points,color?}], yFormat }
 */
function drawChart(doc, x0, y0, w, h, chart) {
  const yFormat = chart.yFormat || 'number';
  const series = Array.isArray(chart.series) ? chart.series : [];
  const xs = Array.isArray(chart.x) ? chart.x : [];
  const n = xs.length;

  const padL = 38, padR = 12, padT = 8, padB = 34;
  const plotX = x0 + padL;
  const plotY = y0 + padT;
  const plotW = Math.max(10, w - padL - padR);
  const plotH = Math.max(10, h - padT - padB);

  // domain
  const vals = [];
  for (const s of series) for (const p of (s.points || [])) if (p != null && !isNaN(p)) vals.push(Number(p));
  let min = vals.length ? Math.min(...vals) : 0;
  let max = vals.length ? Math.max(...vals) : 1;
  if (min > 0) min = 0;              // all our metrics are non-negative → baseline at 0
  if (min === max) max = min + 1;    // avoid divide-by-zero

  doc.save();
  // plot border
  doc.rect(plotX, plotY, plotW, plotH).lineWidth(0.5).strokeColor(BORDER).stroke();

  // gridlines + y labels
  const gridN = 4;
  doc.font('Helvetica').fontSize(7);
  for (let i = 0; i <= gridN; i++) {
    const gy = plotY + (plotH * i / gridN);
    const val = max - (max - min) * i / gridN;
    doc.moveTo(plotX, gy).lineTo(plotX + plotW, gy).lineWidth(0.3).strokeColor(BORDER).stroke();
    doc.fillColor(MUTED).text(fmtAxis(val, yFormat), x0, gy - 3, { width: padL - 5, align: 'right' });
  }

  const xAt = (i) => n <= 1 ? plotX + plotW / 2 : plotX + (plotW * i / (n - 1));
  const yAt = (v) => plotY + plotH - (plotH * (Number(v) - min) / (max - min));

  series.forEach((s, si) => {
    const color = s.color || SERIES_COLORS[si % SERIES_COLORS.length];
    const pts = s.points || [];
    if (chart.type === 'bar') {
      const groupW = n > 0 ? plotW / n : plotW;
      const barW = Math.max(1, (groupW * 0.72) / series.length);
      pts.forEach((p, i) => {
        if (p == null || isNaN(p)) return;
        const bx = plotX + groupW * i + groupW * 0.14 + si * barW;
        const by = yAt(p);
        doc.rect(bx, by, barW, plotY + plotH - by).fill(color);
      });
    } else {
      // line / area — break the path on null points
      let run = [];
      const flush = () => {
        if (!run.length) return;
        if (chart.type === 'area') {
          doc.moveTo(run[0][0], plotY + plotH);
          run.forEach(pt => doc.lineTo(pt[0], pt[1]));
          doc.lineTo(run[run.length - 1][0], plotY + plotH);
          doc.closePath();
          doc.fillColor(color).fillOpacity(0.12).fill();
          doc.fillOpacity(1);
        }
        if (run.length === 1) {
          doc.circle(run[0][0], run[0][1], 1.6).fill(color);
        } else {
          doc.moveTo(run[0][0], run[0][1]);
          for (let k = 1; k < run.length; k++) doc.lineTo(run[k][0], run[k][1]);
          doc.lineWidth(1.2).strokeColor(color).stroke();
        }
        run = [];
      };
      pts.forEach((p, i) => {
        if (p == null || isNaN(p)) { flush(); }
        else run.push([xAt(i), yAt(p)]);
      });
      flush();
    }
  });

  // x labels (first / mid / last)
  doc.font('Helvetica').fontSize(7).fillColor(MUTED);
  const idxs = n <= 1 ? [0] : [0, Math.floor((n - 1) / 2), n - 1];
  const seen = new Set();
  idxs.forEach(i => {
    if (i == null || seen.has(i) || xs[i] == null) return;
    seen.add(i);
    doc.text(String(xs[i]), xAt(i) - 26, plotY + plotH + 4, { width: 52, align: 'center' });
  });

  // legend
  let lx = plotX;
  const ly = plotY + plotH + 16;
  doc.font('Helvetica').fontSize(7);
  series.forEach((s, si) => {
    const color = s.color || SERIES_COLORS[si % SERIES_COLORS.length];
    const label = s.label || `Series ${si + 1}`;
    doc.rect(lx, ly, 8, 8).fill(color);
    doc.fillColor(MUTED).text(label, lx + 11, ly, { width: 140, lineBreak: false });
    lx += 11 + doc.widthOfString(label) + 16;
  });
  doc.restore();
}

// ════════════════════════════════════════════════════════════
// REPORT DEFINITIONS — each returns { columns, rows, summary, charts }
// gather(db, q, rbac) — rbac is the WHOLE req.rbac object; each query calls
// getStatsSiteFilter/getSiteFilter/getAlertSiteFilter itself, matching the
// exact pattern the /api/stats/* endpoints in server.js already use.
// ════════════════════════════════════════════════════════════

// ── security-summary ────────────────────────────────────────
// Severity distribution + category breakdown + alert count (summary/charts),
// top talkers + top blocked + top failures (rows, one combined table with a
// Type column), and a log-volume trend chart. Query logic ported from
// /api/stats/summary, /api/stats/timeline, /api/stats/top-talkers,
// /api/stats/top-blocked, /api/stats/top-failures in server.js.
async function reportSecuritySummary(db, q, rbac) {
  const hours = safeHours(q.hours);

  // Severity distribution / category breakdown / daily trend / top talkers /
  // top blocked / top failures all now read the pre-aggregated rollup tables
  // (scripts/schema.sql "HOURLY ROLLUP TABLES"/"PHASE 2") instead of scanning
  // raw syslog_entries — perf pass, 2026-07. This report was hand-duplicating
  // the PRE-rollup raw query logic for every one of these; the dashboard
  // endpoints it claims to mirror (/api/stats/summary, /timeline,
  // /top-talkers, /top-blocked, /top-failures) were switched to rollups
  // weeks ago, but this copy never was — report generation had silently
  // regressed to 147s (7d) / 468s (30d) while the equivalent dashboard data
  // returns in tens of milliseconds. getRollupSiteFilter (permissive), not
  // getStatsSiteFilter — matches the dashboard endpoints exactly now.

  // Severity distribution (mirrors /api/stats/summary)
  const sfSev = getRollupSiteFilter(rbac, 2);
  const sevR = await db.query(`
    SELECT severity, severity_label, SUM(log_count)::bigint AS log_count
    FROM syslog_stats_rollup
    WHERE hour_bucket >= date_trunc('hour', NOW() - make_interval(hours => $1))
    ${sfSev.clause}
    GROUP BY severity, severity_label ORDER BY severity
  `, [hours, ...sfSev.params]);

  // Category breakdown (mirrors /api/stats/summary's category grouping)
  const sfCat = getRollupSiteFilter(rbac, 2);
  const catR = await db.query(`
    SELECT COALESCE(category, 'uncategorized') AS category, SUM(log_count)::bigint AS log_count
    FROM syslog_stats_rollup
    WHERE hour_bucket >= date_trunc('hour', NOW() - make_interval(hours => $1))
    ${sfCat.clause}
    GROUP BY COALESCE(category, 'uncategorized')
    ORDER BY log_count DESC
  `, [hours, ...sfCat.params]);

  // Alert count in window (relay-based site scoping, mirrors mitre-coverage's
  // alert branch) — unchanged; alert_events is small and this was already fast.
  const sfAlert = getAlertSiteFilter(rbac, 2, 'ae');
  const alertR = await db.query(`
    SELECT COUNT(*)::int AS c
    FROM alert_events ae
    WHERE ae.fired_at > NOW() - make_interval(hours => $1)
    ${sfAlert.clause}
  `, [hours, ...sfAlert.params]);

  // Log volume trend — daily buckets over the full (potentially 90-day)
  // window (mirrors /api/stats/timeline's >6h branch, just bucketed by day
  // instead of hour/6-hour).
  const sfTrend = getRollupSiteFilter(rbac, 2);
  const trendR = await db.query(`
    SELECT to_char(date_trunc('day', hour_bucket), 'YYYY-MM-DD') AS day, SUM(log_count)::bigint AS c
    FROM syslog_stats_rollup
    WHERE hour_bucket >= date_trunc('hour', NOW() - make_interval(hours => $1))
    ${sfTrend.clause}
    GROUP BY 1 ORDER BY 1
  `, [hours, ...sfTrend.params]);

  // Top talkers (mirrors /api/stats/top-talkers, limit 10). Display
  // enrichment (hostname/vendor fallback/country) stays a LIVE join to
  // known_hosts, same as the dashboard endpoint.
  const sfTalk = getRollupSiteFilter(rbac, 3);
  const talkR = await db.query(`
    SELECT
      COALESCE(kh.hostname, agg.actor) AS host,
      agg.actor AS source_ip,
      COALESCE(kh.vendor, agg.vendor) AS vendor,
      kh.country_name,
      agg.log_count::bigint AS log_count
    FROM (
      SELECT srcip AS actor, MAX(vendor) AS vendor, SUM(log_count) AS log_count
      FROM syslog_talker_rollup
      WHERE hour_bucket >= date_trunc('hour', NOW() - make_interval(hours => $1))
      ${sfTalk.clause}
      GROUP BY srcip
    ) agg
    LEFT JOIN known_hosts kh ON agg.actor ~ '^[0-9.]+$' AND host(kh.ip_address) = agg.actor
    ORDER BY agg.log_count DESC
    LIMIT $2
  `, [hours, 10, ...sfTalk.params]);

  // Top blocked (mirrors /api/stats/top-blocked, limit 10) — reads
  // syslog_dest_event_rollup WHERE event_class='blocked'.
  const sfBlocked = getRollupSiteFilter(rbac, 2);
  const blockedR = await db.query(`
    SELECT
      agg.dstip AS dst_ip, agg.service,
      kh.country_name,
      agg.deny_count::bigint AS deny_count
    FROM (
      SELECT dstip, service, SUM(log_count) AS deny_count
      FROM syslog_dest_event_rollup
      WHERE event_class = 'blocked'
        AND hour_bucket >= date_trunc('hour', NOW() - make_interval(hours => $1))
      ${sfBlocked.clause}
      GROUP BY dstip, service
    ) agg
    LEFT JOIN known_hosts kh
      ON agg.dstip ~ '^[0-9.]+$' AND host(kh.ip_address) = agg.dstip
    ORDER BY agg.deny_count DESC
    LIMIT 10
  `, [hours, ...sfBlocked.params]);

  // Top failures (mirrors /api/stats/top-failures, limit 10) — reads
  // syslog_dest_event_rollup WHERE event_class='failure'.
  const sfFail = getRollupSiteFilter(rbac, 2);
  const failR = await db.query(`
    SELECT
      agg.dstip AS dst_ip, agg.service,
      kh.country_name,
      agg.fail_count::bigint AS fail_count
    FROM (
      SELECT dstip, service, SUM(log_count) AS fail_count
      FROM syslog_dest_event_rollup
      WHERE event_class = 'failure'
        AND hour_bucket >= date_trunc('hour', NOW() - make_interval(hours => $1))
      ${sfFail.clause}
      GROUP BY dstip, service
    ) agg
    LEFT JOIN known_hosts kh
      ON agg.dstip ~ '^[0-9.]+$' AND host(kh.ip_address) = agg.dstip
    ORDER BY agg.fail_count DESC
    LIMIT 10
  `, [hours, ...sfFail.params]);

  const rows = [
    ...talkR.rows.map(r => ({
      type: 'Top Talker', host: r.host, detail: r.vendor || '—',
      country: r.country_name || '—', count: parseInt(r.log_count) || 0,
    })),
    ...blockedR.rows.map(r => ({
      type: 'Top Blocked', host: r.dst_ip, detail: r.service || '—',
      country: r.country_name || '—', count: parseInt(r.deny_count) || 0,
    })),
    ...failR.rows.map(r => ({
      type: 'Top Failure', host: r.dst_ip, detail: r.service || '—',
      country: r.country_name || '—', count: parseInt(r.fail_count) || 0,
    })),
  ];

  const totalLogs = sevR.rows.reduce((a, b) => a + (parseInt(b.log_count) || 0), 0);
  const criticalCount = sevR.rows
    .filter(r => r.severity <= 2)
    .reduce((a, b) => a + (parseInt(b.log_count) || 0), 0);
  const alertCount = (alertR.rows[0] && alertR.rows[0].c) || 0;
  const topCategory = catR.rows[0] ? `${catR.rows[0].category} (${catR.rows[0].log_count})` : '—';

  return {
    columns: [
      { key: 'type', label: 'Type', align: 'left' },
      { key: 'host', label: 'Host / IP', align: 'left' },
      { key: 'detail', label: 'Detail', align: 'left' },
      { key: 'country', label: 'Country', align: 'left' },
      { key: 'count', label: 'Count', align: 'right' },
    ],
    rows,
    summary: [
      { label: 'Total Logs', value: totalLogs.toLocaleString() },
      { label: 'Alert Count', value: alertCount, color: alertCount > 0 ? RED : GREEN },
      { label: 'Critical+ Events', value: criticalCount, color: criticalCount > 0 ? RED : GREEN },
      { label: 'Top Category', value: topCategory },
    ],
    charts: [
      {
        type: 'line',
        title: 'Log Volume Trend',
        x: trendR.rows.map(r => r.day),
        series: [{ label: 'Logs', points: trendR.rows.map(r => parseInt(r.c) || 0) }],
        yFormat: 'number',
      },
      {
        type: 'bar',
        title: 'Severity Distribution',
        x: sevR.rows.map(r => r.severity_label || String(r.severity)),
        series: [{ label: 'Events', points: sevR.rows.map(r => parseInt(r.log_count) || 0), color: RED }],
        yFormat: 'number',
      },
      {
        type: 'bar',
        title: 'Category Breakdown',
        x: catR.rows.map(r => r.category),
        series: [{ label: 'Events', points: catR.rows.map(r => parseInt(r.log_count) || 0), color: NAVY }],
        yFormat: 'number',
      },
    ],
  };
}

// ── site-activity ───────────────────────────────────────────
// Per-site log volume + device count (rows), vendor breakdown + top devices
// (charts), active alerts by site (rows column). Site attribution mirrors
// /api/hosts (known_hosts.site_id/site_name); the alert branch uses the same
// relay-based scoping as /api/stats/mitre-coverage's alert_tech CTE.
async function reportSiteActivity(db, q, rbac) {
  const hours = safeHours(q.hours);
  // Explicit cutoff rather than NOW() - make_interval: syslog_entries has 56
  // daily partitions, and only a real parameter value lets the planner prune
  // at plan time (~566ms planning -> 2.5ms, measured 2026-08-06).
  const since = new Date(Date.now() - hours * 3600 * 1000);

  // Per-site log volume + distinct device count.
  const sfSite = getStatsSiteFilter(rbac, 2, 'se');
  const siteR = await db.query(`
    SELECT COALESCE(kh.site_name, 'Unassigned') AS site,
           COUNT(*)::int AS log_count,
           COUNT(DISTINCT se.source_ip)::int AS device_count
    FROM syslog_entries se
    LEFT JOIN known_hosts kh ON kh.ip_address = se.source_ip
    WHERE se.received_at > $1
    ${sfSite.clause}
    GROUP BY COALESCE(kh.site_name, 'Unassigned')
    ORDER BY log_count DESC
  `, [since, ...sfSite.params]);

  // Vendor breakdown per site (drives both the top-vendor-per-site column and
  // the overall vendor breakdown chart).
  const sfVendor = getStatsSiteFilter(rbac, 2, 'se');
  const vendorR = await db.query(`
    SELECT COALESCE(kh.site_name, 'Unassigned') AS site, se.vendor, COUNT(*)::int AS c
    FROM syslog_entries se
    LEFT JOIN known_hosts kh ON kh.ip_address = se.source_ip
    WHERE se.received_at > $1
    ${sfVendor.clause}
    GROUP BY COALESCE(kh.site_name, 'Unassigned'), se.vendor
  `, [since, ...sfVendor.params]);

  // Top devices by log volume across the whole (site-scoped) estate, limit 15.
  const sfDev = getStatsSiteFilter(rbac, 3, 'se');
  const devR = await db.query(`
    SELECT COALESCE(kh.hostname, host(se.source_ip)) AS host,
           COALESCE(kh.site_name, 'Unassigned') AS site,
           COALESCE(kh.vendor, MAX(se.vendor)) AS vendor,
           COUNT(*)::int AS log_count
    FROM syslog_entries se
    LEFT JOIN known_hosts kh ON kh.ip_address = se.source_ip
    WHERE se.received_at > $1
    ${sfDev.clause}
    GROUP BY se.source_ip, kh.hostname, kh.site_name, kh.vendor
    ORDER BY log_count DESC
    LIMIT $2
  `, [since, 15, ...sfDev.params]);

  // Active (unacknowledged) alerts by site — current-state count, not
  // windowed by `hours` (an "active alert" doesn't stop being active just
  // because the report window is short). Relay-based site scoping, same
  // attribution as /api/stats/mitre-coverage's alert branch (ae.source_host
  // -> known_hosts.hostname -> site). No time predicate, so the filter's
  // first placeholder starts at $1.
  const sfAlert = getAlertSiteFilter(rbac, 1, 'ae');
  const alertR = await db.query(`
    SELECT COALESCE(kh.site_name, 'Unassigned') AS site, COUNT(*)::int AS active_alerts
    FROM alert_events ae
    LEFT JOIN known_hosts kh ON kh.hostname = ae.source_host
    WHERE ae.acknowledged = FALSE
    ${sfAlert.clause}
    GROUP BY COALESCE(kh.site_name, 'Unassigned')
  `, sfAlert.params);

  const alertMap = {};
  alertR.rows.forEach(r => { alertMap[r.site] = r.active_alerts; });

  const vendorTopMap = {};
  const vendorTotals = {};
  vendorR.rows.forEach(r => {
    const vendor = r.vendor || 'unknown';
    const c = parseInt(r.c) || 0;
    const cur = vendorTopMap[r.site];
    if (!cur || c > cur.count) vendorTopMap[r.site] = { vendor, count: c };
    vendorTotals[vendor] = (vendorTotals[vendor] || 0) + c;
  });

  const rows = siteR.rows.map(r => ({
    site: r.site,
    log_count: parseInt(r.log_count) || 0,
    device_count: parseInt(r.device_count) || 0,
    top_vendor: (vendorTopMap[r.site] && vendorTopMap[r.site].vendor) || '—',
    active_alerts: alertMap[r.site] || 0,
  }));

  const totalLogs = rows.reduce((a, b) => a + b.log_count, 0);
  const totalAlerts = rows.reduce((a, b) => a + b.active_alerts, 0);
  const busiest = rows[0]; // siteR is already ORDER BY log_count DESC

  const vendorEntries = Object.entries(vendorTotals).sort((a, b) => b[1] - a[1]).slice(0, 10);

  return {
    columns: [
      { key: 'site', label: 'Site', align: 'left' },
      { key: 'log_count', label: 'Log Volume', align: 'right' },
      { key: 'device_count', label: 'Devices', align: 'right' },
      { key: 'top_vendor', label: 'Top Vendor', align: 'left' },
      { key: 'active_alerts', label: 'Active Alerts', align: 'right' },
    ],
    rows,
    summary: [
      { label: 'Sites', value: rows.length },
      { label: 'Total Log Volume', value: totalLogs.toLocaleString() },
      { label: 'Active Alerts', value: totalAlerts, color: totalAlerts > 0 ? RED : GREEN },
      { label: 'Busiest Site', value: busiest ? `${busiest.site} (${busiest.log_count.toLocaleString()})` : '—' },
    ],
    charts: [
      {
        type: 'bar',
        title: 'Top Devices by Log Volume',
        x: devR.rows.map(r => r.host),
        series: [{ label: 'Logs', points: devR.rows.map(r => parseInt(r.log_count) || 0), color: RED }],
        yFormat: 'number',
      },
      {
        type: 'bar',
        title: 'Vendor Breakdown',
        x: vendorEntries.map(e => e[0]),
        series: [{ label: 'Logs', points: vendorEntries.map(e => e[1]), color: NAVY }],
        yFormat: 'number',
      },
    ],
  };
}

// ── mitre-coverage ──────────────────────────────────────────
// Technique-level coverage (events + alert-derived counts), ordered by total
// activity descending — i.e. "top techniques over the period" IS the row
// order. Query ported verbatim from /api/stats/mitre-coverage. Tactic
// grouping (the matrix layout) is left to the frontend's existing MITRE
// catalog (frontend/src/components/mitre.tsx), matching how the live
// dashboard's ATT&CK Coverage view already works — the backend never invents
// its own tactic taxonomy.
async function reportMitreCoverage(db, q, rbac) {
  const hours = safeHours(q.hours);
  // Explicit cutoff rather than NOW() - make_interval: syslog_entries has 56
  // daily partitions, and only a real parameter value lets the planner prune
  // at plan time (~566ms planning -> 2.5ms, measured 2026-08-06).
  const since = new Date(Date.now() - hours * 3600 * 1000);

  const sfEvents = getSiteFilter(rbac, 2, 'se');
  const sfAlerts = getAlertSiteFilter(rbac, 2 + sfEvents.params.length, 'ae');

  const { rows: raw } = await db.query(`
    WITH event_tech AS (
      -- se.structured_data ? 'mitre' (perf pass, 2026-07) — same GIN
      -- existence-check fix as /api/stats/mitre-coverage (kept in lockstep,
      -- this is a verbatim port). Lets the planner use idx_syslog_structured
      -- instead of a full sequential scan; measured ~30x on the live endpoint.
      SELECT t.technique AS technique, COUNT(*)::bigint AS events
      FROM syslog_entries se,
           LATERAL jsonb_array_elements_text(
             CASE WHEN jsonb_typeof(se.structured_data->'mitre') = 'array'
                  THEN se.structured_data->'mitre' ELSE '[]'::jsonb END
           ) AS t(technique)
      WHERE se.received_at > $1
        AND se.structured_data ? 'mitre'
      ${sfEvents.clause}
      GROUP BY t.technique
    ),
    alert_tech AS (
      SELECT tech AS technique, COUNT(*)::bigint AS alerts
      FROM alert_events ae
      JOIN alert_rules ar ON ar.id = ae.rule_id,
           LATERAL unnest(ar.mitre_techniques) AS tech
      WHERE ae.fired_at > $1
        AND ar.mitre_techniques IS NOT NULL
      ${sfAlerts.clause}
      GROUP BY tech
    )
    SELECT COALESCE(e.technique, a.technique) AS technique,
           COALESCE(e.events, 0)::bigint AS events,
           COALESCE(a.alerts, 0)::bigint AS alerts,
           (COALESCE(e.events, 0) + COALESCE(a.alerts, 0))::bigint AS count
    FROM event_tech e
    FULL OUTER JOIN alert_tech a ON a.technique = e.technique
    ORDER BY count DESC
  `, [since, ...sfEvents.params, ...sfAlerts.params]);

  const rows = raw.map(r => ({
    technique: r.technique,
    events: parseInt(r.events) || 0,
    alerts: parseInt(r.alerts) || 0,
    count: parseInt(r.count) || 0,
  }));

  const totalEvents = rows.reduce((a, b) => a + b.events, 0);
  const totalAlerts = rows.reduce((a, b) => a + b.alerts, 0);
  const topTechnique = rows[0] ? `${rows[0].technique} (${rows[0].count})` : '—';
  const top10 = rows.slice(0, 10);

  return {
    columns: [
      { key: 'technique', label: 'Technique', align: 'left' },
      { key: 'events', label: 'Events', align: 'right' },
      { key: 'alerts', label: 'Alerts', align: 'right' },
      { key: 'count', label: 'Total', align: 'right' },
    ],
    rows,
    summary: [
      { label: 'Techniques Observed', value: rows.length },
      { label: 'Total Events', value: totalEvents.toLocaleString() },
      { label: 'Alert-Derived', value: totalAlerts, color: totalAlerts > 0 ? RED : GREEN },
      { label: 'Top Technique', value: topTechnique },
    ],
    charts: [
      {
        type: 'bar',
        title: 'Top Techniques (by total activity)',
        x: top10.map(r => r.technique),
        series: [{ label: 'Total', points: top10.map(r => r.count), color: RED }],
        yFormat: 'number',
      },
    ],
  };
}

// All reports render PORTRAIT.
// ── web-usage ───────────────────────────────────────────────
// Web & user activity — the biggest blind spot in the Phase 1 catalog: `web`
// is ~47% of everything ingested and nothing surfaced it.
//
// EVERY figure here is category-scoped to category='web'. Only two rollups
// carry `category` (syslog_stats_rollup, syslog_entity_activity_rollup), so
// those are the only sources used. syslog_distinct_value_rollup's user/country/
// service dimensions are NOT category-scoped — mixing them in would report
// estate-wide numbers under a "web" heading, exactly the kind of quietly-wrong
// figure these reports exist to eliminate.
//
// Deliberately ABSENT: "top sites/domains visited". No rollup carries
// hostname/url, so it would mean scanning structured_data across the raw 57 GB
// partitioned table. A report that takes minutes is worse than one that answers
// a slightly narrower question instantly.
async function reportWebUsage(db, q, rbac) {
  const hours = safeHours(q.hours);
  const since = `hour_bucket >= date_trunc('hour', NOW() - make_interval(hours => $1))`;

  // Authoritative total + trend come from stats_rollup, which counts each log
  // ONCE. The entity rollup must never be SUMmed for a total — a single log
  // appears there under both its user and its srcip, so it double-counts.
  const sfTrend = getRollupSiteFilter(rbac, 2);
  const trendR = await db.query(`
    SELECT date_trunc('day', hour_bucket) AS d, SUM(log_count)::bigint AS n
    FROM syslog_stats_rollup
    WHERE ${since} AND category = 'web' ${sfTrend.clause}
    GROUP BY 1 ORDER BY 1
  `, [hours, ...sfTrend.params]);

  const sfTot = getRollupSiteFilter(rbac, 2);
  const totR = await db.query(`
    SELECT COALESCE(SUM(log_count), 0)::bigint AS n
    FROM syslog_stats_rollup
    WHERE ${since} AND category = 'web' ${sfTot.clause}
  `, [hours, ...sfTot.params]);

  const sfUser = getRollupSiteFilter(rbac, 2);
  const userR = await db.query(`
    SELECT entity_value AS name, SUM(log_count)::bigint AS n, MAX(last_seen) AS last_seen
    FROM syslog_entity_activity_rollup
    WHERE ${since} AND entity_type = 'user' AND category = 'web' ${sfUser.clause}
    GROUP BY 1 ORDER BY 2 DESC LIMIT 50
  `, [hours, ...sfUser.params]);

  const sfHost = getRollupSiteFilter(rbac, 2);
  const hostR = await db.query(`
    SELECT entity_value AS name, SUM(log_count)::bigint AS n
    FROM syslog_entity_activity_rollup
    WHERE ${since} AND entity_type = 'srcip' AND category = 'web' ${sfHost.clause}
    GROUP BY 1 ORDER BY 2 DESC LIMIT 10
  `, [hours, ...sfHost.params]);

  const sfCnt = getRollupSiteFilter(rbac, 2);
  const cntR = await db.query(`
    SELECT COUNT(DISTINCT entity_value) FILTER (WHERE entity_type = 'user')::int  AS users,
           COUNT(DISTINCT entity_value) FILTER (WHERE entity_type = 'srcip')::int AS hosts
    FROM syslog_entity_activity_rollup
    WHERE ${since} AND category = 'web' ${sfCnt.clause}
  `, [hours, ...sfCnt.params]);

  const totalWeb = parseInt(totR.rows[0] && totR.rows[0].n) || 0;
  const counts = cntR.rows[0] || { users: 0, hosts: 0 };

  const rows = userR.rows.map(r => {
    const n = parseInt(r.n) || 0;
    return {
      user: r.name || 'unattributed',
      log_count: n,
      // Share of the authoritative category total, not of the top-50 subtotal —
      // otherwise the column would sum to 100% while covering only part of it.
      share: totalWeb > 0 ? `${(n / totalWeb * 100).toFixed(1)}%` : '0%',
      last_seen: r.last_seen ? new Date(r.last_seen).toISOString().replace('T', ' ').slice(0, 16) : '-',
    };
  });

  const busiest = rows[0];
  return {
    columns: [
      { key: 'user', label: 'User', align: 'left' },
      { key: 'log_count', label: 'Web Events', align: 'right' },
      { key: 'share', label: 'Share', align: 'right' },
      { key: 'last_seen', label: 'Last Seen', align: 'left' },
    ],
    rows,
    summary: [
      { label: 'Web Events', value: totalWeb.toLocaleString() },
      { label: 'Distinct Users', value: counts.users || 0 },
      { label: 'Distinct Hosts', value: counts.hosts || 0 },
      { label: 'Busiest User', value: busiest ? `${busiest.user} (${busiest.log_count.toLocaleString()})` : '-' },
    ],
    charts: [
      {
        type: 'line',
        title: 'Web Activity Trend (daily)',
        x: trendR.rows.map(r => new Date(r.d).toISOString().slice(0, 10)),
        series: [{ label: 'Web events', points: trendR.rows.map(r => parseInt(r.n) || 0), color: RED }],
        yFormat: 'number',
      },
      {
        type: 'bar',
        title: 'Top Hosts by Web Activity',
        x: hostR.rows.map(r => r.name),
        series: [{ label: 'Web events', points: hostR.rows.map(r => parseInt(r.n) || 0), color: NAVY }],
        yFormat: 'number',
      },
    ],
  };
}

// ── blocked-threat ──────────────────────────────────────────
// Blocked & threat activity — the closest thing to a real security report the
// current log feed supports, built ONLY on signals verified to carry volume
// against 30 days of live data:
//   event_class='blocked'         14,865   syslog_dest_event_rollup
//   known-bad IP hits              7,502   syslog_known_bad_hit_rollup
//   SSL Alert / Exit / IPSec err  ~171k    syslog_security_event_rollup
//
// Deliberately NOT built on authentication or denied-traffic events: the
// firewall sends allowed-traffic, web and VPN session logs only, so
// category='authentication' is 39 logs in 30 days. A report keyed on those
// would render permanently empty and read as a broken product rather than a
// logging-scope decision. Revisit if the firewall's logging scope widens.
async function reportBlockedThreat(db, q, rbac) {
  const hours = safeHours(q.hours);
  const since = `hour_bucket >= date_trunc('hour', NOW() - make_interval(hours => $1))`;

  const sfDest = getRollupSiteFilter(rbac, 2);
  const destR = await db.query(`
    SELECT dstip, COALESCE(service, 'unknown') AS service, SUM(log_count)::bigint AS n
    FROM syslog_dest_event_rollup
    WHERE ${since} AND event_class = 'blocked' ${sfDest.clause}
    GROUP BY 1, 2 ORDER BY 3 DESC LIMIT 50
  `, [hours, ...sfDest.params]);

  const sfTrend = getRollupSiteFilter(rbac, 2);
  const trendR = await db.query(`
    SELECT date_trunc('day', hour_bucket) AS d, SUM(log_count)::bigint AS n
    FROM syslog_dest_event_rollup
    WHERE ${since} AND event_class = 'blocked' ${sfTrend.clause}
    GROUP BY 1 ORDER BY 1
  `, [hours, ...sfTrend.params]);

  // Grand total for the window, independent of the top-50 row cap, so the tile
  // and the table can never quietly disagree about what "blocked" means.
  const sfBlkTot = getRollupSiteFilter(rbac, 2);
  const blkTotR = await db.query(`
    SELECT COALESCE(SUM(log_count), 0)::bigint AS n, COUNT(DISTINCT dstip)::int AS dests
    FROM syslog_dest_event_rollup
    WHERE ${since} AND event_class = 'blocked' ${sfBlkTot.clause}
  `, [hours, ...sfBlkTot.params]);

  const sfBad = getRollupSiteFilter(rbac, 2);
  const badR = await db.query(`
    SELECT ip_address, SUM(hit_count)::bigint AS n
    FROM syslog_known_bad_hit_rollup
    WHERE ${since} ${sfBad.clause}
    GROUP BY 1 ORDER BY 2 DESC LIMIT 10
  `, [hours, ...sfBad.params]);

  const sfBadTot = getRollupSiteFilter(rbac, 2);
  const badTotR = await db.query(`
    SELECT COALESCE(SUM(hit_count), 0)::bigint AS n, COUNT(DISTINCT ip_address)::int AS ips
    FROM syslog_known_bad_hit_rollup
    WHERE ${since} ${sfBadTot.clause}
  `, [hours, ...sfBadTot.params]);

  const sfSsl = getRollupSiteFilter(rbac, 2);
  const sslR = await db.query(`
    SELECT COALESCE(SUM(log_count), 0)::bigint AS n
    FROM syslog_security_event_rollup
    WHERE ${since} AND event_type IN ('SSL Alert', 'SSL Exit Error', 'IPSec Phase 1 Error') ${sfSsl.clause}
  `, [hours, ...sfSsl.params]);

  const blkTot = blkTotR.rows[0] || { n: 0, dests: 0 };
  const badTot = badTotR.rows[0] || { n: 0, ips: 0 };
  const blockedTotal = parseInt(blkTot.n) || 0;
  const badHits = parseInt(badTot.n) || 0;
  const sslTotal = parseInt(sslR.rows[0] && sslR.rows[0].n) || 0;

  const rows = destR.rows.map(r => ({
    dstip: r.dstip || 'unknown',
    service: r.service,
    log_count: parseInt(r.n) || 0,
  }));

  return {
    columns: [
      { key: 'dstip', label: 'Blocked Destination', align: 'left' },
      { key: 'service', label: 'Service', align: 'left' },
      { key: 'log_count', label: 'Events', align: 'right' },
    ],
    rows,
    summary: [
      { label: 'Blocked Events', value: blockedTotal.toLocaleString(), color: blockedTotal > 0 ? YELLOW : GREEN },
      { label: 'Blocked Destinations', value: blkTot.dests || 0 },
      { label: 'Known-Bad IP Hits', value: badHits.toLocaleString(), color: badHits > 0 ? RED : GREEN },
      { label: 'TLS / IPSec Errors', value: sslTotal.toLocaleString() },
    ],
    charts: [
      {
        type: 'bar',
        title: 'Blocked Activity Trend (daily)',
        x: trendR.rows.map(r => new Date(r.d).toISOString().slice(0, 10)),
        series: [{ label: 'Blocked', points: trendR.rows.map(r => parseInt(r.n) || 0), color: YELLOW }],
        yFormat: 'number',
      },
      {
        type: 'bar',
        title: 'Top Known-Bad IPs Contacted',
        x: badR.rows.map(r => r.ip_address),
        series: [{ label: 'Hits', points: badR.rows.map(r => parseInt(r.n) || 0), color: RED }],
        yFormat: 'number',
      },
    ],
  };
}

const REPORTS = {
  'security-summary': { title: 'Security Summary Report', gather: reportSecuritySummary },
  'site-activity':    { title: 'Site Activity Report', gather: reportSiteActivity },
  'mitre-coverage':   { title: 'MITRE ATT&CK Coverage Report', gather: reportMitreCoverage },
  'web-usage':        { title: 'Web & User Activity Report', gather: reportWebUsage },
  'blocked-threat':   { title: 'Blocked & Threat Activity Report', gather: reportBlockedThreat },
};

// ════════════════════════════════════════════════════════════
// CSV RENDERER
// ════════════════════════════════════════════════════════════
function toCsv(columns, rows) {
  const esc = escapeCsvCell;
  const header = columns.map(c => esc(c.label)).join(',');
  const body = rows.map(r => columns.map(c => esc(r[c.key])).join(',')).join('\n');
  return `${header}\n${body}\n`;
}

// ════════════════════════════════════════════════════════════
// PDF RENDERER
// ════════════════════════════════════════════════════════════
function drawCover(doc, opts, layout) {
  const { title, company, generatedBy, dateRange, summary, rows, generatedAt } = opts;
  const { pageW, left, contentW } = layout;

  doc.rect(0, 0, pageW, 150).fill(NAVY);
  doc.rect(0, 150, pageW, 6).fill(RED);
  doc.roundedRect(left, 44, 64, 64, 10).fill(RED);
  doc.fillColor('#fff').fontSize(30).font('Helvetica-Bold').text('L', left, 60, { width: 64, align: 'center' });
  doc.fillColor('#fff').fontSize(22).font('Helvetica-Bold').text('LogVault', left + 80, 56);
  doc.fillColor('#cbd5e1').fontSize(11).font('Helvetica').text('Syslog & Log Analysis', left + 80, 86);

  doc.fillColor(NAVY).fontSize(28).font('Helvetica-Bold').text(title, left, 196, { width: contentW });
  doc.moveTo(left, 238).lineTo(left + 120, 238).lineWidth(3).stroke(RED);

  const meta = [
    ['Company', company],
    ['Generated', generatedAt],
    ['Generated by', generatedBy || 'system'],
    ['Date range', dateRange || 'All time'],
    ['Records', String(rows.length)],
  ];
  let my = 262;
  doc.fontSize(11);
  meta.forEach(([k, v]) => {
    doc.fillColor(MUTED).font('Helvetica-Bold').text(k, left, my, { width: 120, continued: false });
    doc.fillColor('#0f172a').font('Helvetica').text(v, left + 130, my, { width: contentW - 130 });
    my += 22;
  });

  if (summary && summary.length) {
    my += 10;
    doc.fillColor(NAVY).fontSize(13).font('Helvetica-Bold').text('Summary', left, my);
    my += 22;
    let cx = left;
    const chipW = Math.min(150, (contentW - 30) / Math.max(summary.length, 1));
    summary.forEach(s => {
      doc.roundedRect(cx, my, chipW - 10, 52, 8).fillAndStroke(LIGHT, BORDER);
      doc.fillColor(s.color || NAVY).fontSize(18).font('Helvetica-Bold').text(String(s.value), cx + 10, my + 8, { width: chipW - 26 });
      doc.fillColor(MUTED).fontSize(8).font('Helvetica').text(s.label, cx + 10, my + 32, { width: chipW - 26 });
      cx += chipW;
    });
  }
}

function drawCharts(doc, opts, layout) {
  const { charts } = opts;
  const { left, contentW, pageH } = layout;
  if (Array.isArray(charts) && charts.length) {
    doc.addPage();
    let cy = doc.page.margins.top;
    const chartH = 150;
    const titleH = 18;
    for (const chart of charts) {
      if (cy + titleH + chartH > pageH - doc.page.margins.bottom) {
        doc.addPage();
        cy = doc.page.margins.top;
      }
      doc.fillColor(NAVY).fontSize(11).font('Helvetica-Bold')
        .text(chart.title || 'Trend', left, cy, { width: contentW });
      cy += titleH;
      drawChart(doc, left, cy, contentW, chartH, chart);
      cy += chartH + 24;
    }
  }
}

function drawTable(doc, opts, layout) {
  const { columns, rows } = opts;
  const { left, contentW, pageH } = layout;
  doc.addPage();
  const rowH = 18;
  const headerH = 22;
  const pad = 5;
  const totalW = columns.reduce((a, c) => a + (c.width || 90), 0);
  const scale = contentW / totalW;
  const colX = [];
  let acc = left;
  columns.forEach(c => { colX.push(acc); acc += (c.width || 90) * scale; });
  const colW = (c) => (c.width || 90) * scale;

  function drawHeader() {
    const y = doc.y;
    doc.rect(left, y, contentW, headerH).fill(NAVY);
    doc.fillColor('#fff').fontSize(8).font('Helvetica-Bold');
    columns.forEach((c, i) => {
      doc.text(c.label, colX[i] + 4, y + 7, { width: colW(c) - 8, align: c.align || 'left', ellipsis: true, lineBreak: false });
    });
    doc.y = y + headerH;
  }

  drawHeader();
  rows.forEach((r, idx) => {
    doc.font('Helvetica').fontSize(8);
    let rh = rowH;
    columns.forEach((c) => {
      const txt = String(r[c.key] == null ? '' : r[c.key]);
      const th = doc.heightOfString(pdfSafe(txt), { width: colW(c) - 8 }) + pad * 2;
      if (th > rh) rh = th;
    });
    if (doc.y + rh > pageH - doc.page.margins.bottom) {
      doc.addPage();
      drawHeader();
      doc.font('Helvetica').fontSize(8);
    }
    const y = doc.y;
    if (idx % 2 === 1) doc.rect(left, y, contentW, rh).fill(LIGHT);
    columns.forEach((c, i) => {
      const color = typeof c.color === 'function' ? (c.color(r) || '#1e293b') : '#1e293b';
      doc.fillColor(color).font('Helvetica').fontSize(8)
        .text(String(r[c.key] == null ? '' : r[c.key]), colX[i] + 4, y + pad, { width: colW(c) - 8, align: c.align || 'left' });
    });
    doc.y = y + rh;
  });

  if (rows.length === 0) {
    doc.fillColor(MUTED).fontSize(11).font('Helvetica-Oblique').text('No data matched the selected filters.', left, doc.y + 16, { width: contentW, align: 'center' });
  }
}

function stampHeadersFooters(doc, { title, company, generatedAt }) {
  const pageW = doc.page.width;
  const pageH = doc.page.height;
  const left = doc.page.margins.left;
  const right = pageW - doc.page.margins.right;
  const contentW = right - left;
  const range = doc.bufferedPageRange();
  const stampH = 12;
  for (let i = range.start; i < range.start + range.count; i++) {
    doc.switchToPage(i);
    if (i > range.start) {
      doc.fillColor(MUTED).fontSize(8).font('Helvetica')
        .text(`${title}`, left, 18, { width: contentW / 2, align: 'left', lineBreak: false, height: stampH });
      doc.text(company, left + contentW / 2, 18, { width: contentW / 2, align: 'right', lineBreak: false, height: stampH });
      doc.moveTo(left, 30).lineTo(right, 30).lineWidth(0.5).strokeColor(BORDER).stroke();
    }
    doc.fillColor(MUTED).fontSize(8).font('Helvetica')
      .text(`Generated ${generatedAt}`, left, pageH - 26, { width: contentW / 2, align: 'left', lineBreak: false, height: stampH });
    doc.text(`Page ${i - range.start + 1} of ${range.count}`, left + contentW / 2, pageH - 26, { width: contentW / 2, align: 'right', lineBreak: false, height: stampH });
  }
}

function buildPdfDoc(opts) {
  const { title, company } = opts;
  const doc = installPdfSafeText(new PDFDocument({ size: 'A4', layout: 'portrait', margin: 36, bufferPages: true }));

  const pageW = doc.page.width;
  const pageH = doc.page.height;
  const left = doc.page.margins.left;
  const right = pageW - doc.page.margins.right;
  const contentW = right - left;
  const generatedAt = new Date().toLocaleString('en-GB', { hour12: false });
  const layout = { pageW, pageH, left, right, contentW };
  const o = { ...opts, generatedAt };

  drawCover(doc, o, layout);
  drawCharts(doc, o, layout);
  drawTable(doc, o, layout);
  stampHeadersFooters(doc, { title, company, generatedAt });

  return doc;
}

function renderPdf(res, opts) {
  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader('Content-Disposition', `attachment; filename="${opts.filename}"`);
  const doc = buildPdfDoc(opts);
  doc.pipe(res);
  doc.end();
}

// ════════════════════════════════════════════════════════════
// ROUTER
// ════════════════════════════════════════════════════════════
function createReportsRouter(db) {
  const router = express.Router();

  // List available reports (for the UI cards)
  router.get('/', (_req, res) => {
    res.json({ data: Object.entries(REPORTS).map(([key, r]) => ({ key, title: r.title })) });
  });

  router.get('/:type', async (req, res) => {
    const def = REPORTS[req.params.type];
    if (!def) return res.status(404).json({ error: 'Unknown report type' });

    const format = String(req.query.format || 'json').toLowerCase();

    try {
      if (!['json', 'csv', 'pdf'].includes(format)) {
        throw new BadRequestError('invalid format');
      }
      const hours = safeHours(req.query.hours);
      const { columns, rows, summary, charts } = await def.gather(db, req.query, req.rbac);
      const safeCols = columns.map(c => ({ key: c.key, label: c.label, align: c.align || 'left' }));
      const dateRange = `Last ${hours} hour${hours === 1 ? '' : 's'}`;

      // Best-effort audit of every report generation. A logging failure must
      // NEVER break the actual export, so this is wrapped + swallowed.
      const logRun = async (fmt) => {
        try {
          await db.query(
            `INSERT INTO report_run_history (report_type, format, params, row_count, status, trigger_type, generated_by)
             VALUES ($1, $2, $3::jsonb, $4, 'success', 'manual', $5)`,
            [req.params.type, fmt, JSON.stringify(req.query), rows.length,
             req.rbac && req.rbac.userId ? String(req.rbac.userId) : 'system']);
        } catch (e) {
          console.error('[Reports] run-history log failed:', e.message);
        }
      };

      if (format === 'csv') {
        await logRun('csv');
        res.setHeader('Content-Type', 'text/csv');
        res.setHeader('Content-Disposition', `attachment; filename="${req.params.type}-${Date.now()}.csv"`);
        return res.send(toCsv(columns, rows));
      }
      if (format === 'pdf') {
        const company = await companyName(db);
        const actor = req.rbac && req.rbac.userId ? String(req.rbac.userId) : 'system';
        await logRun('pdf');
        return renderPdf(res, {
          title: def.title, company, generatedBy: actor, dateRange,
          columns, rows, summary, charts,
          filename: `${req.params.type}-${Date.now()}.pdf`,
        });
      }
      // json (default)
      await logRun('json');
      res.json({ title: def.title, columns: safeCols, rows, summary, charts });
    } catch (err) {
      if (err instanceof BadRequestError) return res.status(400).json({ error: err.message });
      console.error(`[Reports] ${req.params.type} error:`, err.message);
      if (res.headersSent) { try { res.end(); } catch { /* stream already gone */ } return; }
      res.status(500).json({ error: 'Report generation failed' });
    }
  });

  return router;
}

module.exports = { createReportsRouter, REPORTS };

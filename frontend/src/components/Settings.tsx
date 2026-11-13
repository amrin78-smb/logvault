'use client';
import { useEffect, useState, useRef } from 'react';
import { useToast } from '@/components/Toast';
import { getHubUrl } from '@/lib/publicUrl';
import { PageHeader } from './ui';

interface Settings {
  dns_server:         string;
  dns_lookup_enabled: string;
  // READ-ONLY here. The mail SERVER is owned by the NetVault hub (suite SMTP
  // centralization, net-vault/docs/nocvault-smtp-centralization-plan.md §3), so
  // these two are kept only to NAME a legacy local transport that is still
  // carrying mail — never to edit it. smtp_user/smtp_pass are deliberately not
  // in this shape at all: nothing on this page may read or write them.
  smtp_host:          string;
  smtp_port:          string;
  smtp_from:          string;
  smtp_enabled:       string;
  email_notify_enabled:      string;
  email_notify_severities:   string;
  email_notify_categories:   string;
  email_notify_vendors:      string;
  email_notify_min_risk:     string;
  email_notify_digest_mode:  string;
  email_notify_digest_hour:  string;
  email_notify_recipients:   string;
  email_notify_cooldown_mins: string;
  abuseipdb_api_key:         string;
}

// Returned alongside `data` by GET /api/settings: which mail transport is
// actually in force, plus the four facts the panel below states about it.
//
// ⛔ Everything except `source` is withheld from anyone who is not a
// super_admin, and it is withheld as a SET — present or absent together. Treat
// it that way: a half-read of this object would print some facts beside silently
// missing ones. There is deliberately no password here and nothing derived from
// one (collector/emailer.js :: getSmtpStatus).
interface SmtpStatus {
  source: 'hub' | 'local';
  host?:  string;
  port?:  number;
  secure?: boolean;
  username?: string;
  allow_self_signed?: boolean;
}

const CARD  = { background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 'var(--radius)', padding: 16, marginBottom: 20, boxShadow: 'var(--shadow-sm)' };
// A handful of fields shouldn't sit inside a panel stretched to the full page
// width — it reads as a mostly-empty container. Caps a panel to a sane form
// width; matches SETTINGS_ROW's own cap below so every panel in this file
// shares one left-aligned column instead of some being capped and others not.
const PANEL_NARROW = { ...CARD, maxWidth: 860 };
const LABEL = { fontSize: 'var(--text-base)', fontWeight: 500, color: 'var(--text-secondary)', marginBottom: 6, display: 'block' as const };
const INPUT = { width: '100%', padding: '9px 12px', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border)',
  background: 'var(--bg-input)', color: 'var(--text-primary)', fontSize: 'var(--text-md)', outline: 'none',
  boxSizing: 'border-box' as const };
// Short/medium fixed-width variants of INPUT for fields whose values are inherently short
// (port numbers, IPs, hour-of-day, masked passwords) -- prevents them from stretching to
// fill an ad hoc grid cell (a bare port or hour field, previously unbounded, filled a 1fr column).
const INPUT_SM = { padding: '9px 12px', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border)',
  background: 'var(--bg-input)', color: 'var(--text-primary)', fontSize: 'var(--text-md)', outline: 'none',
  boxSizing: 'border-box' as const, maxWidth: 140 };
const INPUT_MD = { ...INPUT_SM, maxWidth: 220 };
const SECTION_HEADER = { fontSize: 'var(--text-base)', fontWeight: 600, color: 'var(--text-secondary)', textTransform: 'uppercase' as const, letterSpacing: '0.04em', marginBottom: 16 };
// A settings panel paired with a short "what this actually does" explainer,
// for the handful of sections whose behavior isn't obvious from the form
// alone. The aside sticks just below the fixed 72px header while its (often
// taller) neighboring panel scrolls.
const SETTINGS_ROW = { display: 'grid', gridTemplateColumns: 'minmax(0,1fr) 300px', gap: 20, alignItems: 'start' as const, maxWidth: 1180 };
const INFO_CARD = { background: 'var(--tint-info)', border: '1px solid var(--border)', borderRadius: 'var(--radius)',
  padding: '16px 18px', position: 'sticky' as const, top: 72 };
const INFO_CARD_TITLE = { margin: '0 0 12px', fontSize: 'var(--text-base)', fontWeight: 700, color: 'var(--tint-info-fg)' };
const INFO_CARD_DT = { fontSize: 'var(--text-sm)', fontWeight: 700, color: 'var(--text-primary)', marginTop: 12 };
const INFO_CARD_DD = { margin: '3px 0 0', fontSize: 'var(--text-sm)', color: 'var(--text-secondary)', lineHeight: 1.5 };

// Parse a JSON-array string (stored in app_settings) into a string[]. Tolerant
// of malformed/empty values — always returns an array.
function parseArr(json: string): string[] {
  try { const v = JSON.parse(json || '[]'); return Array.isArray(v) ? v.map(String) : []; }
  catch { return []; }
}

// Parse a comma-separated recipients string into trimmed, non-empty entries.
function parseEmails(csv: string): string[] {
  return (csv || '').split(',').map(s => s.trim()).filter(Boolean);
}

const SEVERITY_OPTS: { value: string; label: string; color: string }[] = [
  { value: '0', label: 'Emergency (0)', color: '#dc2626' },
  { value: '1', label: 'Alert (1)',     color: '#dc2626' },
  { value: '2', label: 'Critical (2)',  color: '#dc2626' },
  { value: '3', label: 'Error (3)',     color: '#ea580c' },
  { value: '4', label: 'Warning (4)',   color: '#d97706' },
  { value: '5', label: 'Notice (5)',    color: '#2563eb' },
  { value: '6', label: 'Info (6)',      color: '#16a34a' },
  { value: '7', label: 'Debug (7)',     color: '#6b7280' },
];

const CATEGORY_OPTS: { value: string; label: string }[] = [
  { value: 'authentication', label: 'Authentication' },
  { value: 'vpn',           label: 'VPN' },
  { value: 'security',      label: 'Security' },
  { value: 'firewall',      label: 'Firewall' },
  { value: 'interface',     label: 'Interface' },
  { value: 'routing',       label: 'Routing' },
  { value: 'configuration', label: 'Configuration' },
  { value: 'wireless',      label: 'Wireless' },
  { value: 'system',        label: 'System' },
  { value: 'dns',           label: 'DNS' },
  { value: 'web',           label: 'Web' },
  { value: 'dlp',           label: 'DLP' },
  { value: 'email',         label: 'Email' },
  { value: 'network',       label: 'Network' },
];

const VENDOR_OPTS: { value: string; label: string }[] = [
  { value: 'fortinet',   label: 'Fortinet' },
  { value: 'cisco',      label: 'Cisco' },
  { value: 'paloalto',   label: 'Palo Alto' },
  { value: 'aruba',      label: 'Aruba' },
  { value: 'sangfor',    label: 'Sangfor' },
  { value: 'forcepoint', label: 'Forcepoint' },
  { value: 'checkpoint', label: 'Check Point' },
  { value: 'juniper',    label: 'Juniper' },
  { value: 'windows',    label: 'Windows' },
  { value: 'sonicwall',  label: 'SonicWall' },
  { value: 'generic',    label: 'Generic' },
];

const COOLDOWN_OPTS: { value: string; label: string }[] = [
  { value: '5',    label: '5 minutes' },
  { value: '15',   label: '15 minutes' },
  { value: '30',   label: '30 minutes' },
  { value: '60',   label: '1 hour' },
  { value: '120',  label: '2 hours' },
  { value: '240',  label: '4 hours' },
  { value: '480',  label: '8 hours' },
  { value: '1440', label: '24 hours' },
];

// Background/foreground tint + label for the minimum-risk-score badge based on the threshold.
function riskBadge(n: number): { bg: string; fg: string; label: string } {
  if (n <= 30)  return { bg: 'var(--tint-success)', fg: 'var(--tint-success-fg)', label: 'Low+' };
  if (n <= 60)  return { bg: 'var(--tint-info)',     fg: 'var(--tint-info-fg)',    label: 'Medium+' };
  if (n <= 80)  return { bg: 'var(--tint-warn)',     fg: 'var(--tint-warn-fg)',    label: 'High+' };
  return { bg: 'var(--tint-danger)', fg: 'var(--tint-danger-fg)', label: 'Critical only' };
}

interface AlertRule { id: number; name: string; description: string; notify_email: string; is_enabled: boolean; }

interface UpdateStatus {
  current_version?:  string;
  latest_version?:   string;
  current_commit?:   string;
  latest_commit?:    string;
  up_to_date?:       boolean;
  update_available?: boolean;
  release_notes?:    string[];
  release_date?:     string;
  error?:            string;
}

// Shape of GET /api/system/last-update-status (Update-LogVault.ps1's
// Write-StatusJson output) — the ACTUAL outcome of an update run, distinct
// from the version-check shape above. Matches UpdateFailureBanner.tsx's own
// interface of the same underlying data.
interface UpdateRunStatus {
  exists?:            boolean;
  success?:           boolean;
  stage?:             string | null;
  errorCode?:         number;
  errorMessage?:      string | null;
  rolledBack?:        boolean;
  healthCheckPassed?: boolean;
  timestamp?:         string;
}

const UPDATE_TIMEOUT_MS = 10 * 60 * 1000; // 10 minutes — covers slow npm install + Next.js build before services are back
// After the API is confirmed stably back up, wait this long before reloading so
// the Next.js frontend (which starts AFTER the API) has time to finish booting —
// otherwise the reload lands on "page cannot be reached" for 20-30 seconds.
const RELOAD_COUNTDOWN_SECONDS = 15;

const MONTHS = ['January', 'February', 'March', 'April', 'May', 'June',
  'July', 'August', 'September', 'October', 'November', 'December'];
// Format an ISO date "2026-06-08" → "June 8, 2026" (no timezone shifting).
function fmtReleaseDate(d?: string): string {
  if (!d) return '';
  const [y, m, day] = d.split('-').map(Number);
  if (!y || !m || !day) return d;
  return `${MONTHS[m - 1]} ${day}, ${y}`;
}
// Full-screen overlay shown during an update; polls /api/health for recovery.
// The API must be seen DOWN before an UP response counts as recovery, so we
// never declare "complete" against the still-running pre-restart service.
// Once the health poll confirms SOMETHING is stably back up, this does NOT
// assume that means "the update succeeded" — a health-poll recovery looks
// IDENTICAL whether the update actually succeeded, or it failed and the
// script's own Invoke-Rollback silently put the OLD version back (the API on
// port 3005 answers /api/health either way). So before declaring success it
// also checks /api/system/last-update-status (the same structured result
// UpdateFailureBanner reads) for the ACTUAL outcome of this run, and shows a
// distinct state for each of the three real outcomes: succeeded, failed-but-
// rolled-back (still running, but on the OLD version — needs attention), or
// rollback-also-failed (the most urgent state — no auto-reload, since the app
// may genuinely be down/unstable and a reload could just spin forever).
// Defined at module level (never inside another component).
function UpdateOverlay() {
  const [phase, setPhase] = useState<
    'starting' | 'down' | 'checking_result' | 'success' | 'rolled_back' | 'rollback_failed' | 'timeout'
  >('starting');
  const [countdown, setCountdown] = useState(RELOAD_COUNTDOWN_SECONDS);
  const [resultInfo, setResultInfo] = useState<UpdateRunStatus | null>(null);
  const wentDown = useRef(false);
  const consecutiveUp = useRef(0);

  useEffect(() => {
    let active   = true;
    const startedAt = Date.now();
    let pollId:   ReturnType<typeof setInterval> | null = null;

    const stopPolling = () => { if (pollId !== null) { clearInterval(pollId); pollId = null; } };

    // Once the health poll confirms recovery, consult the real outcome from
    // logs/last-update-status.json (written by Update-LogVault.ps1's
    // Write-StatusJson) rather than trusting the health-poll transition alone.
    // Retries briefly in case the script is still finishing its own writes;
    // if the outcome can't be confirmed at all, falls back to declaring
    // success rather than blocking the user forever — the health poll above
    // already proved SOMETHING is up and stably responding.
    const checkOutcome = async () => {
      if (!active) return;
      setPhase('checking_result');
      for (let attempt = 0; attempt < 5; attempt++) {
        if (!active) return;
        try {
          const res  = await fetch('/api/system/last-update-status', { cache: 'no-store' });
          const data: UpdateRunStatus = await res.json();
          // Only trust a status file whose timestamp is AFTER this update run
          // started — otherwise this could be reading a stale result left
          // over from a previous update.
          if (data?.exists && data?.timestamp && new Date(data.timestamp).getTime() > startedAt) {
            if (!active) return;
            if (data.success === true) {
              setPhase('success');
            } else if (data.rolledBack === true) {
              setResultInfo(data);
              setPhase('rolled_back');
            } else {
              setResultInfo(data);
              setPhase('rollback_failed');
            }
            return;
          }
        } catch {
          // fall through and retry
        }
        await new Promise(r => setTimeout(r, 1500));
      }
      if (active) setPhase('success');
    };

    const tick = async () => {
      if (!active) return;
      if (Date.now() - startedAt > UPDATE_TIMEOUT_MS) {
        stopPolling();
        if (active) setPhase('timeout');
        return;
      }

      // Per-poll timeout via AbortController, kept under the 2s poll interval so
      // a hung connection during the restart resolves as "down" promptly.
      const ctrl    = new AbortController();
      const abortId = setTimeout(() => ctrl.abort(), 1800);
      let ok = false;
      try {
        const res = await fetch('/api/health', { cache: 'no-store', signal: ctrl.signal });
        ok = res.ok; // non-200 counts as down
      } catch {
        ok = false;
      } finally {
        clearTimeout(abortId);
      }
      if (!active) return;

      if (!ok) {
        // Fetch failed or non-200 → API is down (restarting). Reset the
        // consecutive-success counter: during startup the API can answer one
        // probe then drop again, so any failure restarts the stability window.
        consecutiveUp.current = 0;
        wentDown.current = true;
        setPhase('down');
        return;
      }

      // Healthy response. Only a recovery if we previously saw it go down.
      if (wentDown.current) {
        // Require 3 consecutive healthy probes (≈6s at the 2s cadence) before
        // declaring the API stably back up. A single success after going down
        // isn't enough — services may respond once then briefly drop again
        // mid-startup, which would trigger a premature reload.
        consecutiveUp.current += 1;
        if (consecutiveUp.current >= 3) {
          stopPolling();
          checkOutcome();
        }
      }
      // else: still the pre-restart API — keep waiting for it to go down.
    };

    pollId = setInterval(tick, 2000); // poll every 2 seconds
    tick(); // immediate first poll

    return () => {
      active = false;
      stopPolling();
    };
  }, []);

  // Once the outcome is confirmed as a genuine success OR a failed-but-
  // rolled-back run (both leave a running app it's safe to reload into),
  // count down before reloading so the Next.js frontend has time to finish
  // starting. "rollback_failed" deliberately does NOT auto-reload — the app
  // may be down/unstable, and a countdown-driven reload there would just
  // mislead the admin into thinking it's routine.
  useEffect(() => {
    if (phase !== 'success' && phase !== 'rolled_back') return;
    if (countdown <= 0) { window.location.href = '/?updated=true'; return; }
    const id = setTimeout(() => setCountdown(c => c - 1), 1000);
    return () => clearTimeout(id);
  }, [phase, countdown]);

  let heading = 'Updating LogVault...';
  let statusLine = 'Starting update...';
  if (phase === 'down') {
    statusLine = 'Services restarting...';
  } else if (phase === 'checking_result') {
    statusLine = 'Services are back online. Verifying the update outcome...';
  } else if (phase === 'success') {
    heading = 'Update Complete';
    statusLine = `✓ Update completed successfully. Reloading in ${countdown} second${countdown === 1 ? '' : 's'}...`;
  } else if (phase === 'rolled_back') {
    heading = 'Update Failed — Rolled Back';
    statusLine = `The update failed and was automatically rolled back — LogVault is back on the previous version. Reloading in ${countdown} second${countdown === 1 ? '' : 's'}...`;
  } else if (phase === 'rollback_failed') {
    heading = 'Update Failed — Rollback Also Failed';
    statusLine = 'LogVault may be DOWN or unstable — the automatic rollback also failed. MANUAL INTERVENTION REQUIRED — check the server / update logs.';
  } else if (phase === 'timeout') {
    statusLine = 'Update is taking longer than expected. Try refreshing the page manually.';
  }

  const spinning = phase === 'starting' || phase === 'down' || phase === 'checking_result';
  const showCountdownNumber = phase === 'success' || phase === 'rolled_back';

  return (
    <div style={{ position: 'fixed', inset: 0, zIndex: 9999, background: 'rgba(0,0,0,0.5)',
      display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 16 }}>
      <style>{'@keyframes lv-spin { to { transform: rotate(360deg); } }'}</style>
      <div style={{ background: 'var(--bg-card)', borderRadius: 'var(--radius)', boxShadow: 'var(--shadow-md)',
        padding: 40, maxWidth: 480, width: '100%', textAlign: 'center' }}>
        {spinning && (
          <div style={{ fontSize: 44, lineHeight: 1, display: 'inline-block',
            color: 'var(--primary)', animation: 'lv-spin 1s linear infinite' }}>⟳</div>
        )}
        {phase === 'success' && <div style={{ fontSize: 44, lineHeight: 1 }}>✓</div>}
        {phase === 'rolled_back' && <div style={{ fontSize: 44, lineHeight: 1, color: '#d97706' }}>⚠</div>}
        {phase === 'rollback_failed' && <div style={{ fontSize: 44, lineHeight: 1, color: '#dc2626' }}>⛔</div>}
        {phase === 'timeout' && <div style={{ fontSize: 44, lineHeight: 1 }}>⚠</div>}
        <div style={{ fontSize: 'var(--text-lg)', fontWeight: 700, marginTop: 14, color: 'var(--text-primary)' }}>{heading}</div>
        {spinning && (
          <p style={{ fontSize: 'var(--text-base)', color: 'var(--text-muted)', marginTop: 6 }}>
            Pulling latest code and restarting services. Do not close this window.
          </p>
        )}
        <p style={{ fontWeight: 600, margin: '14px 0', color: phase === 'rollback_failed' ? '#dc2626' : 'var(--text-primary)' }}>{statusLine}</p>
        {(phase === 'rolled_back' || phase === 'rollback_failed') && resultInfo?.errorMessage && (
          <p style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', wordBreak: 'break-word' }}>
            {resultInfo.stage ? `Failed at ${resultInfo.stage}: ` : ''}{resultInfo.errorMessage}
          </p>
        )}
        {showCountdownNumber && (
          <div style={{ fontSize: 40, fontWeight: 800, lineHeight: 1, margin: '4px 0 10px', color: 'var(--primary)' }}>
            {countdown}
          </div>
        )}
        {spinning && (
          <p style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)' }}>(This usually takes 1-3 minutes)</p>
        )}
        <button onClick={showCountdownNumber ? () => { window.location.href = '/?updated=true'; } : () => window.location.reload()}
          style={{ marginTop: 10, padding: '9px 22px', borderRadius: 'var(--radius-sm)', border: 'none',
            background: phase === 'rollback_failed' ? '#dc2626' : 'var(--primary)', color: '#fff',
            fontSize: 'var(--text-base)', fontWeight: 600, cursor: 'pointer' }}>
          {phase === 'rollback_failed' ? 'Reload Anyway' : 'Reload Now'}
        </button>
      </div>
    </div>
  );
}

// ── Effective mail transport (read-only) ─────────────────────
//
// The mail SERVER is owned by the NetVault hub for the whole suite
// (net-vault/docs/nocvault-smtp-centralization-plan.md §3). LogVault used to
// offer a full editable SMTP Host / Port / Username / Password form here; after
// Phase 2 nothing on this page owns a transport, and leaving the form up made
// three apps each look like they needed their own mail server filled in.
//
// It is replaced by a STATEMENT, not by silence. An admin still has to be able
// to answer "which server is actually carrying my alerts" without a DB query,
// and there are three different answers:
//
//   hub      — the hub has an enabled transport and it is in force.
//   fallback — no transport is coming from the hub, but this install still has a
//              legacy app_settings row with a host in it, and the send path is
//              STILL USING IT. ⛔ Never hide this one: it is live config.
//   none     — nothing from the hub and no local row. No alert email can be
//              sent, and it cannot be fixed from this page.
//
// ⛔ ONE SHAPE FOR ALL THREE SATELLITES. The titles, the four facts and the body
// copy below are shared verbatim with DDIVault and SpanVault — the canonical one is
// ddivault/frontend/src/components/SmtpSettings.tsx. Only the app name is
// adapted. The facts are there because prose cannot carry four of them without
// becoming a paragraph, and because an operator needs all four: which server,
// which connection mode, whether the relay is authenticated, and whether the
// certificate is actually checked. Two differently-worded statements of one fact
// read as two different facts, which is exactly what three hand-written panels
// produced; do not re-word one app's copy on its own.
//
// ⛔ THE SETTINGS RAIL ALREADY SAYS MAIL IS MANAGED IN NETVAULT. This panel says
// WHICH SERVER IS CARRYING YOUR MAIL RIGHT NOW. Do not restate ownership here in
// a louder voice — that duplicate-voice problem was fixed once already (2.41.1).
//
// ⛔ THE COPY SAYS WHAT IS TRUE, NOT WHY. The legacy and none states say "No
// suite mail server is reaching LogVault" — NOT "NetVault has no suite mail
// server switched on", which an earlier draft of the shared spec asserted.
// collector/suiteSmtp.js resolves to 'local' for FOUR different reasons: the hub
// genuinely has none enabled, the hub DB is unreachable, the hub predates
// smtp_config, or its password will not decrypt. This page cannot tell them
// apart, so naming one of them would be a guess printed as a fact — and the
// three wrong ones all describe a hub that is fine and a link that is broken,
// which sends an admin to the wrong screen.
// The wording is still identical in all three apps: one state, one sentence.
// The warn-once [SuiteSMTP] line in the collector log is what distinguishes the
// four causes, and that is the right place for it.
//
// (`status` is null only when the whole GET /api/settings failed, in which case
// no setting on this page loaded either.)

// Calm informational panel — tokenized so it flips with the theme.
const NOTE: React.CSSProperties = {
  background:   'var(--tint-info)',
  color:        'var(--tint-info-fg)',
  border:       '1px solid var(--border)',
  borderRadius: 'var(--radius-sm)',
  padding:      '14px 16px',
  marginBottom: 18,
  fontSize:     'var(--text-base)',
  lineHeight:   1.55,
};

// The same panel on the warn tint — used where the effective transport is a
// state an administrator should act on (a legacy local row, or nothing at all).
const NOTE_WARN: React.CSSProperties = { ...NOTE, background: 'var(--tint-warn)', color: 'var(--tint-warn-fg)' };

const NOTE_TITLE: React.CSSProperties = { fontWeight: 700, marginBottom: 6, fontSize: 'var(--text-md)' };

// Read-only fact grid inside a transport panel: label on the left, value right.
const FACTS: React.CSSProperties = {
  display: 'grid',
  gridTemplateColumns: 'max-content 1fr',
  columnGap: 14,
  rowGap: 6,
  margin: '12px 0',
  fontSize: 'var(--text-base)',
};

const FACT_LABEL: React.CSSProperties = {
  // --text-secondary, not --text-muted: measured 4.37:1 on the light --tint-info
  // wash, just under the 4.5:1 floor. 13px/600 is not WCAG large text, so the
  // exemption does not apply. Changed in all three apps at once - one app
  // quietly altering a shared token is how the divergence started.
  color: 'var(--text-secondary)', fontWeight: 600, whiteSpace: 'nowrap',
};

const FACT_VALUE: React.CSSProperties = {
  color: 'var(--text-primary)', fontFamily: 'var(--font-mono)', wordBreak: 'break-all',
};

// ⛔ The link INHERITS the panel's own foreground token and is distinguished by
// weight + underline, never by hue. A link colour is chosen against the page
// background; these panels sit on the info/warn washes, and a colour picked for
// one background is not legible on another — the same trap as --canvas-light,
// from the other direction. Measured against this stylesheet in dark mode:
// var(--primary) on the warn tint is 2.66:1 and var(--blue) 3.03:1, both under
// the 4.5:1 body-text floor; inheriting gives 8.89:1 on info and 10.86:1 on warn
// (6.16 / 4.84 in light). The obvious future "fix" is to reach for a brand
// colour again — don't.
const HUB_LINK: React.CSSProperties = {
  color: 'inherit', fontWeight: 600, textDecoration: 'underline',
};

// One read-only fact row.
// ⛔ Module scope, like everything else here — a component declared inside
// another component is a brand-new type on every render, so React remounts its
// whole subtree (and anything focused inside it loses focus).
function Fact({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <>
      <div style={FACT_LABEL}>{label}</div>
      <div style={FACT_VALUE}>{children}</div>
    </>
  );
}

// Certificate-checking wording, shared by both configured states so they cannot
// drift apart. `allowSelfSigned === true` is the ONE rule buildTransport applies
// (collector/emailer.js).
function certText(allowSelfSigned: boolean): string {
  return allowSelfSigned
    ? 'Not enforced — any certificate is accepted, including an expired or impersonated one'
    : 'Enforced';
}

function SmtpTransportNotice({ status, localHost }: {
  status:    SmtpStatus | null;
  localHost: string;
}) {
  // Always derive the hub origin from the browser's current hostname — never a
  // hardcoded host and never the install-time env bake-in (lib/publicUrl.ts).
  const hubLink = getHubUrl() + '/settings?tab=notifications';
  const link = (
    <a href={hubLink} target="_blank" rel="noopener noreferrer" style={HUB_LINK}>
      NetVault → Settings → Notifications
    </a>
  );

  const fromHub  = status?.source === 'hub';
  // The hub's answer wins whenever the API resolved to it; otherwise a non-empty
  // local host is the live fallback. `localHost` rather than `status.host`
  // because a non-super_admin is given `{ source }` alone — it must still be
  // told that a legacy server is carrying its mail.
  const hasLocal = !!localHost.trim();

  // The four facts, or null when the API withheld them (not a super_admin).
  // Withheld is NOT unknown: the panel drops the grid rather than printing four
  // placeholder rows for a reader who is not allowed to see any of them.
  // ⛔ The `{' '}` before each {facts} below is load-bearing: JSX strips the
  // whitespace between a text line and an expression container, so with the grid
  // absent the two sentences would run together as "suite.Change".
  const facts = status && status.host ? (
    <div style={FACTS}>
      <Fact label="Server">{status.host}:{status.port}</Fact>
      <Fact label="Connection">{status.secure ? 'TLS / SSL' : 'STARTTLS or plain'}</Fact>
      <Fact label="Username">{status.username || '(none — unauthenticated)'}</Fact>
      <Fact label="Certificate checking">{certText(!!status.allow_self_signed)}</Fact>
    </div>
  ) : null;

  if (fromHub) {
    return (
      <div style={NOTE}>
        <div style={NOTE_TITLE}>Sending through the NocVault suite mail server</div>
        Alerts and digests are delivered through the mail server configured once for the
        whole NocVault suite.{' '}
        {facts}
        Change the server in {link}. LogVault keeps its own sender identity and its own
        delivery switch, below.
      </div>
    );
  }

  if (hasLocal) {
    return (
      <div style={NOTE_WARN}>
        <div style={NOTE_TITLE}>Sending through a mail server stored in LogVault</div>
        No suite mail server is reaching LogVault, so it is falling back to the
        server saved in its own settings by an earlier release.{' '}
        {facts}
        These values are <strong>no longer editable here</strong> — a mail server is now
        configured for the whole suite in {link}. This one keeps working until one is set
        up there, which then takes over.
      </div>
    );
  }

  return (
    <div style={NOTE_WARN}>
      <div style={NOTE_TITLE}>No mail server configured</div>
      No suite mail server is reaching LogVault, and LogVault has none of its own. Until
      one is configured, alerts and digests <strong>will not be delivered</strong> and Send
      Test Email will fail.
      <div style={{ marginTop: 10 }}>
        Set one up in {link}. LogVault cannot be pointed at a mail server from this page.
      </div>
    </div>
  );
}

export default function Settings() {
  const { toast } = useToast();
  const [settings, setSettings]   = useState<Settings>({
    dns_server: '', dns_lookup_enabled: 'true',
    smtp_host: '', smtp_port: '587',
    smtp_from: '', smtp_enabled: 'false',
    email_notify_enabled: 'true',
    email_notify_severities: '["0","1","2","3"]',
    email_notify_categories: '[]',
    email_notify_vendors: '[]',
    email_notify_min_risk: '40',
    email_notify_digest_mode: 'instant',
    email_notify_digest_hour: '8',
    email_notify_recipients: '',
    email_notify_cooldown_mins: '30',
    abuseipdb_api_key: '',
  });
  // Count of known-bad IPs from threat intel (shown in the Threat Intelligence section).
  const [knownBadCount, setKnownBadCount] = useState<number | null>(null);
  const [saving,   setSaving]     = useState(false);
  const [activeTab, setActiveTab] = useState<'email' | 'system' | 'updates' | 'about'>('system');
  const [testTo,   setTestTo]     = useState('');
  const [testing,  setTesting]    = useState(false);
  // Which SMTP transport is actually in force. 'hub' means the NetVault hub
  // supplies host/port/credentials; 'local' means it does not, and LogVault is
  // either falling back to a legacy row in its own app_settings or has no
  // transport at all. Set for BOTH sources — the page has to be able to tell
  // "the hub owns it" from "nobody owns it", and a null status would read as
  // the second. host/port are present for a super_admin only (the API withholds
  // them otherwise), so render them conditionally, not unconditionally.
  const [smtpStatus, setSmtpStatus] = useState<SmtpStatus | null>(null);

  // ── Per-rule alert recipients ──────────────────────────────
  const [rules, setRules] = useState<AlertRule[]>([]);
  const [ruleEmails, setRuleEmails] = useState<Record<number, string>>({});
  const [savingRule, setSavingRule] = useState<number | null>(null);
  const rulesLoaded = useRef(false);

  // Toggle a value in one of the JSON-array string fields (severities/categories/vendors).
  const toggleInArr = (field: keyof Settings, value: string) => {
    setSettings(s => {
      const arr = parseArr(s[field] as string);
      const next = arr.includes(value) ? arr.filter(x => x !== value) : [...arr, value];
      return { ...s, [field]: JSON.stringify(next) };
    });
  };

  // Remove an email from the comma-separated global recipients string.
  const removeRecipient = (email: string) => {
    setSettings(s => ({
      ...s,
      email_notify_recipients: parseEmails(s.email_notify_recipients).filter(e => e !== email).join(', '),
    }));
  };

  const saveRuleEmail = async (id: number) => {
    setSavingRule(id);
    try {
      const r = await fetch(`/api/alert-rules/${id}/notify`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ notify_email: ruleEmails[id] || '' }),
      });
      if (r.ok) {
        toast('Rule recipient saved', 'success');
        setRules(rs => rs.map(x => x.id === id ? { ...x, notify_email: ruleEmails[id] || '' } : x));
      } else { toast('Failed to save rule recipient', 'error'); }
    } catch { toast('Failed to save rule recipient', 'error'); }
    setSavingRule(null);
  };

  // ── Updates tab state ──────────────────────────────────────
  const [updateStatus,     setUpdateStatus]     = useState<UpdateStatus | null>(null);
  const [checkingUpdate,   setCheckingUpdate]   = useState(false);
  const [updating,         setUpdating]         = useState(false);
  const [showUpdateOverlay, setShowUpdateOverlay] = useState(false);
  const [showConfirmModal,  setShowConfirmModal]  = useState(false);
  const [updateBlocked,    setUpdateBlocked]    = useState<string | null>(null);
  // Whether updateBlocked's message is specifically a license block (shows the
  // "Manage License" link) vs. any other reason an update couldn't start
  // (e.g. a concurrent update already running) — previously the render always
  // showed a hardcoded "License expired" message regardless of what
  // updateBlocked actually contained.
  const [updateBlockedIsLicense, setUpdateBlockedIsLicense] = useState(false);
  const [appVersion,       setAppVersion]       = useState<string>('');
  const [updateAvail,      setUpdateAvail]      = useState(false);

  // Current running version (from /api/health) + a lightweight update-available
  // check that drives the red dot on the Updates tab label.
  useEffect(() => {
    fetch('/api/health').then(r => r.json()).then(d => { if (d?.version) setAppVersion(d.version); }).catch(() => {});
    fetch('/api/system/update-available').then(r => r.json()).then(d => setUpdateAvail(!!d?.available)).catch(() => {});
  }, []);

  // Deep-link from the update-notifier banner: open the Updates sub-tab.
  useEffect(() => {
    try {
      const t = sessionStorage.getItem('logvault-settings-tab');
      if (t === 'updates' || t === 'system' || t === 'email' || t === 'about') {
        setActiveTab(t);
        sessionStorage.removeItem('logvault-settings-tab');
      }
    } catch { /* ignore */ }
  }, []);

  const checkUpdate = async () => {
    setCheckingUpdate(true);
    try {
      const r = await fetch('/api/system/update-status');
      const d = await r.json();
      setUpdateStatus(d);
    } catch {
      setUpdateStatus({ error: 'Could not check for updates', up_to_date: true });
    }
    setCheckingUpdate(false);
  };

  // Load update status when the Updates tab is opened.
  useEffect(() => {
    if (activeTab === 'updates' && !updateStatus && !checkingUpdate) checkUpdate();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeTab]);

  const startUpdate = async () => {
    setShowConfirmModal(false);
    setUpdateBlocked(null);
    setUpdateBlockedIsLicense(false);
    setUpdating(true);
    setShowUpdateOverlay(true);
    try {
      const r = await fetch('/api/system/update', { method: 'POST' });
      // License gate: a 402 means the update was refused — don't show the overlay.
      if (r.status === 402) {
        let msg = 'License validation failed.';
        try { const d = await r.json(); if (d?.error) msg = d.error; } catch { /* keep default */ }
        setShowUpdateOverlay(false);
        setUpdating(false);
        setUpdateBlockedIsLicense(true);
        setUpdateBlocked(msg);
        return;
      }
      // Any other non-OK response (e.g. 400/500, or 409 when an update is
      // already running — see the concurrency guard in api/server.js) means
      // the update never started — surface the server's error instead of
      // leaving the overlay spinning forever.
      if (!r.ok) {
        let msg = 'Failed to start update. Please try again or update manually.';
        try { const d = await r.json(); if (d?.error) msg = d.error; } catch { /* keep default */ }
        setShowUpdateOverlay(false);
        setUpdating(false);
        setUpdateBlockedIsLicense(false);
        setUpdateBlocked(msg);
        return;
      }
    } catch {
      // The response may be cut off by a fast restart — the overlay's health
      // polling detects recovery regardless, so we still show it.
    }
  };

  useEffect(() => {
    fetch('/api/settings')
      .then(r => r.json())
      .then(d => {
        if (d.data) {
          // Strip the hub-owned credentials before they reach form state. The
          // API still returns them to a super_admin (collector/suiteSmtp.js
          // reads them as the fallback), but this page no longer edits or
          // posts them, so holding them in a React state object that gets
          // JSON.stringify'd back to POST /api/settings would be pure risk.
          const data: Record<string, string> = { ...d.data };
          delete data.smtp_user;
          delete data.smtp_pass;
          setSettings(s => ({ ...s, ...data }));
        }
        if (d.smtp) setSmtpStatus(d.smtp);
      }).catch(() => {});
  }, []);

  // Threat-intel enrichment stats — count of known-bad external IPs detected.
  useEffect(() => {
    fetch('/api/threats/known-bad')
      .then(r => r.json())
      // The endpoint returns { data: [...] } — read the array off .data, not the
      // envelope itself (the bare-array check always saw 0).
      .then((d: { data?: unknown[] }) => setKnownBadCount(Array.isArray(d?.data) ? d.data.length : 0))
      .catch(() => setKnownBadCount(null));
  }, []);

  // Load alert rules once when the Email tab is first opened.
  useEffect(() => {
    if (activeTab !== 'email' || rulesLoaded.current) return;
    rulesLoaded.current = true;
    fetch('/api/alert-rules')
      .then(r => r.json())
      .then(d => {
        if (d.data) {
          setRules(d.data);
          setRuleEmails(Object.fromEntries((d.data as AlertRule[]).map(r => [r.id, r.notify_email || ''])));
        }
      })
      .catch(() => {});
  }, [activeTab]);

  const save = async () => {
    setSaving(true);
    try {
      const r = await fetch('/api/settings', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(settings),
      });
      if (r.ok) {
        toast('Settings saved — refresh to see changes', 'success');
      } else {
        toast('Failed to save settings', 'error');
      }
    } catch {
      toast('Failed to save settings', 'error');
    }
    setSaving(false);
  };

  const sendTest = async () => {
    if (!testTo.trim()) { toast('Enter a recipient address', 'error'); return; }
    setTesting(true);
    try {
      const r = await fetch('/api/settings/test-email', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        // ONLY the recipient. POST /api/settings/test-email treats a supplied
        // `smtp_host` as an override of the saved config — that existed so the
        // page could test SMTP fields the admin had typed but not yet saved.
        // There are no such fields any more, so sending anything else here
        // could only test a server that is not the live one. The API resolves
        // the effective transport (hub, or the local fallback) itself, which is
        // exactly what this button is meant to exercise.
        //
        // Consequence worth knowing: an UNSAVED From address is not used by the
        // test — save first, then test.
        body: JSON.stringify({ to: testTo.trim() }),
      });
      if (r.ok) {
        toast(`Test email sent to ${testTo.trim()}`, 'success');
      } else {
        const d = await r.json().catch(() => ({}));
        toast(d.error || 'Failed to send test email', 'error');
      }
    } catch {
      toast('Failed to send test email', 'error');
    }
    setTesting(false);
  };

  const TAB_LABEL: Record<string, string> = {
    system:  'General',
    email:   'Email Alerts',
    updates: 'Updates',
    about:   'About',
  };

  // Grouped settings sub-navigation (NocVault suite-standard chrome — the same
  // .settings-layout rail netvault/ddivault/spanvault use).
  //
  // Two groups for four tabs, and the split is conceptual rather than a
  // halving: SYSTEM holds the tabs that change how this installation BEHAVES
  // (what the collector enriches, who gets told when an alert fires), SOFTWARE
  // holds the two that only describe the product itself — which build is
  // running and whether a newer one exists. Nothing under SOFTWARE configures
  // LogVault, and nothing under SYSTEM is a fact about the build.
  //
  // There is deliberately no role filter here: LogVault gates Settings as a
  // WHOLE in page.tsx (`tab === 'settings' && isAdmin`) and has no per-tab role
  // gate, so there is none to carry over and no group can ever come out empty.
  // If a per-tab gate is ever added it must go on the content block AND here
  // AND the sessionStorage deep-link handler above — a nav filter alone only
  // hides the button.
  const GROUPS: ReadonlyArray<readonly [string, readonly string[]]> = [
    ['System',   ['system', 'email']],
    ['Software', ['updates', 'about']],
  ];

  const hasUpdateError = !!updateStatus?.error;
  const upToDate       = !hasUpdateError && !!updateStatus?.up_to_date;
  const updatesAvailable = !hasUpdateError && !!updateStatus?.update_available;

  return (
    <div style={{ width: '100%' }}>
      <PageHeader title="Settings" subtitle="System configuration and email alerts" />

      <div className="settings-layout">
        <nav className="settings-nav" aria-label="Settings sections">
          {/* Standing hub pointer. LogVault has no user management, no SSO
              config, no licence screen and — since 2.41.0 — no mail server
              field. All four genuinely live on the hub, so without this line an
              admin hunting one of them reads its absence as "LogVault is
              missing it" rather than "it is next door". Quiet chrome on
              purpose: this is a signpost, not a warning. */}
          <div className="settings-nav-hub">
            Users, sign-on, licence and mail are managed in{' '}
            <a href={getHubUrl()}>NetVault →</a>
          </div>

          {GROUPS.map(([group, tabs]) => (
            <div className="settings-nav-group" key={group}>
              <div className="settings-nav-label">{group}</div>
              {tabs.map(t => (
                <button key={t} type="button"
                  className="settings-nav-item"
                  aria-current={activeTab === t ? 'page' : undefined}
                  onClick={() => setActiveTab(t as any)}>
                  <span style={{ flex: 1, minWidth: 0 }}>{TAB_LABEL[t]}</span>
                  {t === 'updates' && updateAvail && (
                    <span title="Update available" aria-label="Update available"
                      style={{ display: 'inline-block', width: 7, height: 7,
                        // intentional: 50% keeps the 7x7 update-available status dot a circle
                        borderRadius: '50%',
                        background: 'var(--red)', flexShrink: 0 }} />
                  )}
                </button>
              ))}
            </div>
          ))}
        </nav>

        <div className="settings-panel">

      {activeTab === 'system' && (
        <>
          {/* DNS Settings */}
          <div style={PANEL_NARROW}>
            <div style={SECTION_HEADER}>DNS Lookup</div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 14 }}>
              <input type="checkbox"
                checked={settings.dns_lookup_enabled !== 'false'}
                onChange={e => setSettings(s => ({ ...s, dns_lookup_enabled: e.target.checked ? 'true' : 'false' }))}
                style={{ cursor: 'pointer', width: 16, height: 16 }} />
              <div>
                <div style={{ fontSize: 'var(--text-base)', color: 'var(--text-primary)', fontWeight: 500 }}>
                  Enable reverse DNS lookup
                </div>
                <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginTop: 2 }}>
                  Automatically resolve IP addresses to hostnames for unknown devices
                </div>
              </div>
            </div>
            <div>
              <label style={LABEL}>
                DNS Server IP
                <span style={{ fontWeight: 400, color: 'var(--text-muted)', marginLeft: 6 }}>
                  (optional — leave blank to use system default)
                </span>
              </label>
              <input style={{ ...INPUT_MD, width: 220 }}
                value={settings.dns_server}
                onChange={e => setSettings(s => ({ ...s, dns_server: e.target.value }))}
                placeholder="e.g. 192.168.1.1 or 8.8.8.8" />
              <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginTop: 6 }}>
                Used for reverse lookups of IPs appearing in logs — both internal devices and external IPs.
                Settings are applied automatically within 5 minutes — no restart needed.
              </div>
            </div>
          </div>

          {/* Threat Intelligence */}
          <div style={PANEL_NARROW}>
            <div style={SECTION_HEADER}>Threat Intelligence</div>
            <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginBottom: 16 }}>
              GeoIP data uses ip-api.com (free, no key needed). AbuseIPDB requires a free API key for threat scoring.
            </div>

            <div style={{ maxWidth: 420, marginBottom: 4 }}>
              <label style={LABEL}>AbuseIPDB API Key</label>
              <input style={INPUT} type="password" value={settings.abuseipdb_api_key}
                onChange={e => setSettings(s => ({ ...s, abuseipdb_api_key: e.target.value }))}
                placeholder="••••••••••••••••" autoComplete="off" />
              <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginTop: 6 }}>
                Get a free key at abuseipdb.com (1,000 checks/day free).
              </div>
            </div>

            {/* Enrichment stats */}
            <div style={{ display: 'inline-flex', alignItems: 'center', gap: 8, marginTop: 16,
              background: knownBadCount && knownBadCount > 0 ? 'var(--tint-danger)' : 'var(--surface-subtle)',
              border: '1px solid var(--border)', borderRadius: 'var(--radius)', padding: '8px 14px' }}>
              <span style={{ fontSize: 'var(--text-lg)', fontWeight: 700,
                color: knownBadCount && knownBadCount > 0 ? 'var(--tint-danger-fg)' : 'var(--text-primary)' }}>
                {knownBadCount === null ? '—' : knownBadCount.toLocaleString()}
              </span>
              <span style={{ fontSize: 'var(--text-sm)', color: 'var(--text-secondary)' }}>
                known-bad IP{knownBadCount === 1 ? '' : 's'} detected
              </span>
            </div>
          </div>

          {/* Save */}
          <button onClick={save} disabled={saving}
            style={{ padding: '10px 28px', borderRadius: 'var(--radius-sm)', border: 'none', cursor: 'pointer',
              fontSize: 'var(--text-base)', fontWeight: 600, background: 'var(--primary)', color: '#fff',
              opacity: saving ? 0.7 : 1, transition: 'all 0.15s' }}>
            {saving ? 'Saving...' : 'Save Settings'}
          </button>
        </>
      )}

      {activeTab === 'email' && (
        <>
          {/* SECTION 1 — Mail transport (read-only) + the From identity */}
          <div style={PANEL_NARROW}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16 }}>
              <div style={{ ...SECTION_HEADER, marginBottom: 0 }}>Mail Delivery</div>
              <label style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer' }}>
                <input type="checkbox"
                  checked={settings.smtp_enabled === 'true'}
                  onChange={e => setSettings(s => ({ ...s, smtp_enabled: e.target.checked ? 'true' : 'false' }))}
                  style={{ cursor: 'pointer', width: 16, height: 16 }} />
                <span style={{ fontSize: 'var(--text-sm)', fontWeight: 600, color: 'var(--text-secondary)' }}>
                  {settings.smtp_enabled === 'true' ? 'Enabled' : 'Disabled'}
                </span>
              </label>
            </div>
            <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginBottom: 18 }}>
              This switch is LogVault's own: it decides whether LogVault sends alert email at all,
              whichever mail server is carrying it. Emails are only sent for rules that match the
              filters below.
            </div>

            <SmtpTransportNotice
              status={smtpStatus}
              localHost={settings.smtp_host} />

            <div style={{ marginBottom: 4 }}>
              <label style={LABEL}>From Address</label>
              <input style={INPUT} value={settings.smtp_from}
                onChange={e => setSettings(s => ({ ...s, smtp_from: e.target.value }))}
                placeholder="LogVault Alerts <alerts@example.com>" />
            </div>

            <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginTop: 12 }}>
              The From address is deliberately per-app — it is what makes an alert read as LogVault
              in a recipient's inbox. Left blank, the mail server's own From address is used.
            </div>
            <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginTop: 6 }}>
              Settings applied automatically within 5 minutes — no restart needed.
            </div>
          </div>

          {/* SECTION 2 — Global Recipients */}
          <div style={PANEL_NARROW}>
            <div style={SECTION_HEADER}>Global Alert Recipients</div>
            <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginBottom: 14 }}>
              These addresses receive all alerts that match the filters below. Individual alert rules can also have their own recipients.
            </div>
            <input style={INPUT}
              value={settings.email_notify_recipients}
              onChange={e => setSettings(s => ({ ...s, email_notify_recipients: e.target.value }))}
              placeholder="security@company.com, admin@company.com" />
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, marginTop: 12 }}>
              {parseEmails(settings.email_notify_recipients).map(email => (
                <span key={email}
                  style={{ display: 'inline-flex', alignItems: 'center', gap: 6, background: 'var(--bg-hover)',
                    border: '1px solid var(--border)', borderRadius: 'var(--radius-pill)', padding: '4px 10px',
                    fontSize: 'var(--text-sm)', color: 'var(--text-primary)' }}>
                  {email}
                  <button onClick={() => removeRecipient(email)}
                    style={{ border: 'none', background: 'transparent', cursor: 'pointer',
                      color: 'var(--text-muted)', fontSize: 'var(--text-md)', lineHeight: 1, padding: 0 }}>
                    ×
                  </button>
                </span>
              ))}
            </div>
          </div>

          {/* SECTION 3 + 4 — Notification Filters & Delivery Mode, paired with an explainer */}
          <div style={SETTINGS_ROW}>
          <div>
          <div style={CARD}>
            <div style={SECTION_HEADER}>When to Send Alerts</div>
            <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginBottom: 16 }}>
              Only send emails when ALL selected conditions match
            </div>

            <label style={{ display: 'flex', alignItems: 'center', gap: 10, cursor: 'pointer', marginBottom: 20 }}>
              <input type="checkbox"
                checked={settings.email_notify_enabled === 'true'}
                onChange={e => setSettings(s => ({ ...s, email_notify_enabled: e.target.checked ? 'true' : 'false' }))}
                style={{ cursor: 'pointer', width: 16, height: 16 }} />
              <span style={{ fontSize: 'var(--text-base)', color: 'var(--text-primary)', fontWeight: 500 }}>
                Email notifications enabled
              </span>
            </label>

            {/* 3a Severity */}
            <div style={{ marginBottom: 22 }}>
              <label style={LABEL}>Severity levels</label>
              <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginBottom: 10 }}>
                Send email for these severity levels
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 8 }}>
                {SEVERITY_OPTS.map(o => (
                  <label key={o.value} style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer' }}>
                    <input type="checkbox"
                      checked={parseArr(settings.email_notify_severities).includes(o.value)}
                      onChange={() => toggleInArr('email_notify_severities', o.value)}
                      style={{ cursor: 'pointer', width: 15, height: 15 }} />
                    {/* intentional: 50% keeps the 8x8 severity swatch a circle */}
                    <span style={{ width: 8, height: 8, borderRadius: '50%', background: o.color, display: 'inline-block' }} />
                    <span style={{ fontSize: 'var(--text-sm)', color: 'var(--text-primary)' }}>{o.label}</span>
                  </label>
                ))}
              </div>
            </div>

            {/* 3b Categories */}
            <div style={{ marginBottom: 22 }}>
              <label style={LABEL}>Event categories</label>
              <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginBottom: 10 }}>
                Only send for these categories (leave all unchecked to receive all categories)
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 8 }}>
                {CATEGORY_OPTS.map(o => (
                  <label key={o.value} style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer' }}>
                    <input type="checkbox"
                      checked={parseArr(settings.email_notify_categories).includes(o.value)}
                      onChange={() => toggleInArr('email_notify_categories', o.value)}
                      style={{ cursor: 'pointer', width: 15, height: 15 }} />
                    <span style={{ fontSize: 'var(--text-sm)', color: 'var(--text-primary)' }}>{o.label}</span>
                  </label>
                ))}
              </div>
            </div>

            {/* 3c Vendors */}
            <div style={{ marginBottom: 22 }}>
              <label style={LABEL}>Vendors</label>
              <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginBottom: 10 }}>
                Only send for logs from these vendors (leave all unchecked to receive from all vendors)
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 8 }}>
                {VENDOR_OPTS.map(o => (
                  <label key={o.value} style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer' }}>
                    <input type="checkbox"
                      checked={parseArr(settings.email_notify_vendors).includes(o.value)}
                      onChange={() => toggleInArr('email_notify_vendors', o.value)}
                      style={{ cursor: 'pointer', width: 15, height: 15 }} />
                    <span style={{ fontSize: 'var(--text-sm)', color: 'var(--text-primary)' }}>{o.label}</span>
                  </label>
                ))}
              </div>
            </div>

            {/* 3d Minimum risk score */}
            <div style={{ marginBottom: 22 }}>
              <label style={LABEL}>Minimum risk score</label>
              <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginBottom: 10 }}>
                Only send emails for logs with risk score at or above this value (0 = send all)
              </div>
              {(() => {
                const v = parseInt(settings.email_notify_min_risk || '0') || 0;
                const b = riskBadge(v);
                return (
                  <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
                    <input type="range" min={0} max={100} step={5}
                      value={v}
                      onChange={e => setSettings(s => ({ ...s, email_notify_min_risk: String(e.target.value) }))}
                      style={{ flex: 1, maxWidth: 320, cursor: 'pointer' }} />
                    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6, padding: '4px 10px',
                      borderRadius: 'var(--radius-pill)', background: b.bg, color: b.fg, fontSize: 'var(--text-sm)', fontWeight: 600 }}>
                      {v} · {b.label}
                    </span>
                  </div>
                );
              })()}
            </div>

            {/* 3e Cooldown */}
            <div>
              <label style={LABEL}>Cooldown between alerts</label>
              <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginBottom: 10 }}>
                Minimum time between emails for the same alert rule (prevents email flooding)
              </div>
              <select
                value={settings.email_notify_cooldown_mins}
                onChange={e => setSettings(s => ({ ...s, email_notify_cooldown_mins: e.target.value }))}
                style={{ ...INPUT_MD, width: 220, cursor: 'pointer' }}>
                {COOLDOWN_OPTS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
              </select>
            </div>
          </div>

          {/* SECTION 4 — Delivery Mode */}
          <div style={CARD}>
            <div style={SECTION_HEADER}>Delivery mode</div>
            <label style={{ display: 'flex', alignItems: 'flex-start', gap: 10, cursor: 'pointer', marginBottom: 14 }}>
              <input type="radio" name="delivery" value="instant"
                checked={settings.email_notify_digest_mode === 'instant'}
                onChange={() => setSettings(s => ({ ...s, email_notify_digest_mode: 'instant' }))}
                style={{ cursor: 'pointer', marginTop: 2, width: 15, height: 15 }} />
              <span style={{ fontSize: 'var(--text-base)', color: 'var(--text-primary)' }}>
                <span style={{ fontWeight: 600 }}>Instant</span> — Send email immediately when alert fires
              </span>
            </label>
            <label style={{ display: 'flex', alignItems: 'flex-start', gap: 10, cursor: 'pointer', marginBottom: 14 }}>
              <input type="radio" name="delivery" value="digest"
                checked={settings.email_notify_digest_mode === 'digest'}
                onChange={() => setSettings(s => ({ ...s, email_notify_digest_mode: 'digest' }))}
                style={{ cursor: 'pointer', marginTop: 2, width: 15, height: 15 }} />
              <span style={{ fontSize: 'var(--text-base)', color: 'var(--text-primary)' }}>
                <span style={{ fontWeight: 600 }}>Daily Digest</span> — Collect alerts and send one summary email
              </span>
            </label>

            {settings.email_notify_digest_mode === 'digest' && (
              <div style={{ marginLeft: 25 }}>
                <label style={LABEL}>Send digest at</label>
                <select
                  value={settings.email_notify_digest_hour}
                  onChange={e => setSettings(s => ({ ...s, email_notify_digest_hour: e.target.value }))}
                  style={{ ...INPUT_SM, width: 140, cursor: 'pointer' }}>
                  {Array.from({ length: 24 }, (_, h) => (
                    <option key={h} value={String(h)}>{String(h).padStart(2, '0')}:00</option>
                  ))}
                </select>
                <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginTop: 8 }}>
                  Sends a summary of all alerts from the past 24 hours at the selected time
                </div>
              </div>
            )}
          </div>
          </div>
          <div style={INFO_CARD}>
            <div style={INFO_CARD_TITLE}>How delivery works</div>
            <div style={INFO_CARD_DT}>Cooldown</div>
            <div style={INFO_CARD_DD}>Tracked per alert rule in memory, not the database. Resets on every collector restart, so a restart can allow one extra email inside the cooldown window.</div>
            <div style={INFO_CARD_DT}>Daily Digest</div>
            <div style={INFO_CARD_DD}>Not implemented yet — every eligible alert is still sent instantly regardless of this selection.</div>
            <div style={INFO_CARD_DT}>Recipients</div>
            <div style={INFO_CARD_DD}>Global and per-rule recipients are combined and deduplicated automatically — a rule&apos;s override adds to the global list, it doesn&apos;t replace it.</div>
          </div>
          </div>

          {/* Shared Save (SMTP + recipients + filters + delivery) */}
          <button onClick={save} disabled={saving}
            style={{ padding: '10px 28px', borderRadius: 'var(--radius-sm)', border: 'none', cursor: 'pointer',
              fontSize: 'var(--text-base)', fontWeight: 600, background: 'var(--primary)', color: '#fff',
              opacity: saving ? 0.7 : 1, transition: 'all 0.15s', marginBottom: 16 }}>
            {saving ? 'Saving...' : 'Save Settings'}
          </button>

          {/* SECTION 5 — Per-Rule Recipients */}
          <div style={PANEL_NARROW}>
            <div style={SECTION_HEADER}>Per-Rule Recipients</div>
            <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginBottom: 16 }}>
              Override recipients for specific alert rules. These are in addition to global recipients.
            </div>
            {rules.length === 0 ? (
              <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)' }}>No alert rules configured.</div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
                {rules.map(rule => {
                  const val = ruleEmails[rule.id] || '';
                  const showHint = !rule.notify_email && !val;
                  return (
                    <div key={rule.id} style={{ display: 'flex', alignItems: 'flex-end', gap: 12,
                      paddingBottom: 14, borderBottom: '1px solid var(--border-light)' }}>
                      <div style={{ flex: 1, minWidth: 0 }}>
                        <div style={{ fontSize: 'var(--text-base)', fontWeight: 600, color: 'var(--text-primary)' }}>{rule.name}</div>
                        {rule.description && (
                          <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginTop: 2 }}>{rule.description}</div>
                        )}
                        <input style={{ ...INPUT, marginTop: 8 }}
                          value={val}
                          onChange={e => setRuleEmails(m => ({ ...m, [rule.id]: e.target.value }))}
                          placeholder="optional override" />
                        {showHint && (
                          <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginTop: 4 }}>No custom recipient</div>
                        )}
                      </div>
                      <button onClick={() => saveRuleEmail(rule.id)} disabled={savingRule === rule.id}
                        style={{ padding: '9px 18px', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border)', cursor: 'pointer',
                          fontSize: 'var(--text-sm)', fontWeight: 600, background: 'var(--bg-input)', color: 'var(--text-primary)',
                          opacity: savingRule === rule.id ? 0.7 : 1, whiteSpace: 'nowrap' }}>
                        {savingRule === rule.id ? 'Saving...' : 'Save'}
                      </button>
                    </div>
                  );
                })}
              </div>
            )}
          </div>

          {/* SECTION 6 — Test & Preview */}
          <div style={PANEL_NARROW}>
            <div style={{ ...SECTION_HEADER, marginBottom: 6 }}>Send Test Email</div>
            <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginBottom: 14 }}>
              Sends a test message over the mail server currently in use, shown at the top of
              this tab. It uses the SAVED From address — save first if you have just changed it.
            </div>
            <div style={{ display: 'flex', alignItems: 'flex-end', gap: 12 }}>
              <div style={{ flex: 1, maxWidth: 360 }}>
                <label style={LABEL}>Recipient Address</label>
                <input style={INPUT} type="email" value={testTo}
                  onChange={e => setTestTo(e.target.value)}
                  placeholder="you@example.com" />
              </div>
              <button onClick={sendTest} disabled={testing}
                style={{ padding: '9px 20px', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border)', cursor: 'pointer',
                  fontSize: 'var(--text-sm)', fontWeight: 600, background: 'var(--bg-input)', color: 'var(--text-primary)',
                  opacity: testing ? 0.7 : 1, whiteSpace: 'nowrap' }}>
                {testing ? 'Sending...' : 'Send Test'}
              </button>
            </div>
            {parseEmails(settings.email_notify_recipients).length > 0 ? (
              <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginTop: 12 }}>
                Test email will be sent to: {parseEmails(settings.email_notify_recipients).join(', ')}
              </div>
            ) : (
              <div style={{ background: 'rgba(217,119,6,0.1)', border: '1px solid rgba(217,119,6,0.3)',
                borderRadius: 'var(--radius)', padding: '10px 14px', marginTop: 12, fontSize: 'var(--text-sm)', color: '#b45309' }}>
                No global recipients configured — alerts will only go to per-rule recipients.
              </div>
            )}
          </div>
        </>
      )}

      {activeTab === 'updates' && (
        <div style={CARD}>
          <div style={SECTION_HEADER}>Software Updates</div>

          {checkingUpdate ? (
            <div style={{ fontSize: 'var(--text-base)', color: 'var(--text-muted)' }}>Checking for updates...</div>
          ) : hasUpdateError ? (
            <div>
              <div style={{ fontSize: 'var(--text-base)', color: '#d97706', fontWeight: 600, marginBottom: 14 }}>
                {updateStatus?.error}
              </div>
              <button onClick={checkUpdate}
                style={{ padding: '8px 18px', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border)',
                  background: 'var(--bg-input)', color: 'var(--text-primary)', fontSize: 'var(--text-sm)',
                  fontWeight: 600, cursor: 'pointer' }}>
                Re-check
              </button>
            </div>
          ) : upToDate ? (
            <div>
              <div style={{ fontSize: 'var(--text-md)', fontWeight: 700, color: '#16a34a', marginBottom: 8 }}>
                ✓ LogVault is up to date
              </div>
              {updateStatus?.current_version && (
                <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)', marginBottom: 16 }}>
                  Current version: <code style={{ fontFamily: 'var(--font-mono)' }}>v{updateStatus.current_version}</code>
                </div>
              )}
              <button onClick={checkUpdate}
                style={{ padding: '8px 18px', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border)',
                  background: 'var(--bg-input)', color: 'var(--text-primary)', fontSize: 'var(--text-sm)',
                  fontWeight: 600, cursor: 'pointer' }}>
                Re-check
              </button>
            </div>
          ) : updatesAvailable ? (
            <div>
              <div style={{ fontSize: 'var(--text-md)', fontWeight: 700, color: 'var(--text-primary)', marginBottom: 6 }}>
                {updateStatus?.current_version === updateStatus?.latest_version
                  ? <>🔄 Patches available since <code style={{ fontFamily: 'var(--font-mono)' }}>v{updateStatus?.current_version}</code></>
                  : <>🔄 Update available: <code style={{ fontFamily: 'var(--font-mono)' }}>v{updateStatus?.current_version}</code>
                    {' → '}
                    <code style={{ fontFamily: 'var(--font-mono)' }}>v{updateStatus?.latest_version}</code></>}
              </div>
              {(updateStatus?.current_commit || updateStatus?.latest_commit) && (
                <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)', marginBottom: 14 }}>
                  Current: v{updateStatus?.current_version}
                  {updateStatus?.current_commit && <> (<code style={{ fontFamily: 'var(--font-mono)' }}>{updateStatus.current_commit}</code>)</>}
                  {'  →  '}
                  Latest: v{updateStatus?.latest_version}
                  {updateStatus?.latest_commit && <> (<code style={{ fontFamily: 'var(--font-mono)' }}>{updateStatus.latest_commit}</code>)</>}
                </div>
              )}

              {updateStatus?.release_notes && updateStatus.release_notes.length > 0 && (
                <div style={{ marginBottom: 16 }}>
                  <div style={{ fontSize: 'var(--text-sm)', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: 6 }}>
                    What&apos;s new{updateStatus?.latest_version ? ` in v${updateStatus.latest_version}` : ''}
                  </div>
                  <ul style={{ margin: 0, paddingLeft: 20, fontSize: 'var(--text-sm)', lineHeight: 1.6,
                    color: 'var(--text-primary)' }}>
                    {updateStatus.release_notes.map((note, i) => (
                      <li key={i}>{note}</li>
                    ))}
                  </ul>
                  {updateStatus?.release_date && (
                    <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginTop: 8 }}>
                      Released: {fmtReleaseDate(updateStatus.release_date)}
                    </div>
                  )}
                </div>
              )}

              <div style={{ background: 'rgba(217,119,6,0.1)', border: '1px solid rgba(217,119,6,0.3)',
                borderRadius: 'var(--radius)', padding: '10px 14px', marginBottom: 16, fontSize: 'var(--text-sm)', color: '#b45309' }}>
                ⚠ Services will restart during the update — you may lose connection for 30–60 seconds.
              </div>

              <div style={{ display: 'flex', gap: 10 }}>
                <button onClick={() => setShowConfirmModal(true)} disabled={updating}
                  style={{ padding: '9px 22px', borderRadius: 'var(--radius-sm)', border: 'none',
                    cursor: updating ? 'default' : 'pointer', opacity: updating ? 0.6 : 1,
                    fontSize: 'var(--text-base)', fontWeight: 600, background: 'var(--primary)', color: '#fff' }}>
                  Update Now
                </button>
                <button onClick={checkUpdate}
                  style={{ padding: '9px 18px', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border)',
                    background: 'var(--bg-input)', color: 'var(--text-primary)', fontSize: 'var(--text-base)',
                    fontWeight: 600, cursor: 'pointer' }}>
                  Re-check
                </button>
              </div>

              {updateBlocked && (
                <div style={{ marginTop: 12, fontSize: 'var(--text-base)', color: 'var(--primary)' }}>
                  ⚠ {updateBlocked}
                  {updateBlockedIsLicense && (
                    <>
                      {' '}
                      <a
                        href={getHubUrl() + '/settings/license'}
                        style={{ color: 'var(--primary)', fontWeight: 600, textDecoration: 'underline' }}
                      >
                        Manage License →
                      </a>
                    </>
                  )}
                </div>
              )}
            </div>
          ) : (
            <button onClick={checkUpdate}
              style={{ padding: '8px 18px', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border)',
                background: 'var(--bg-input)', color: 'var(--text-primary)', fontSize: 'var(--text-sm)',
                fontWeight: 600, cursor: 'pointer' }}>
              Check for Updates
            </button>
          )}
        </div>
      )}

      {/* Confirmation modal (inline) */}
      {showConfirmModal && (
        <div onMouseDown={() => setShowConfirmModal(false)}
          style={{ position: 'fixed', inset: 0, zIndex: 9998, background: 'rgba(0,0,0,0.5)',
            display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 16 }}>
          <div onMouseDown={e => e.stopPropagation()}
            style={{ background: 'var(--bg-card)', borderRadius: 'var(--radius)', width: '100%', maxWidth: 460,
              overflow: 'hidden', boxShadow: '0 4px 16px rgba(0,0,0,0.12)' }}>
            <div style={{ background: '#1a2744', color: '#fff', padding: '14px 20px', fontSize: 'var(--text-md)', fontWeight: 700 }}>
              Start Update?
            </div>
            <div style={{ padding: 20 }}>
              <div style={{ fontSize: 'var(--text-base)', color: 'var(--text-secondary)', lineHeight: 1.5, marginBottom: 20 }}>
                Services will restart and you&apos;ll lose connection for 30–60 seconds. The page reloads automatically when the update completes.
              </div>
              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 10 }}>
                <button onClick={() => setShowConfirmModal(false)}
                  style={{ padding: '9px 18px', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border)',
                    background: 'var(--bg-input)', color: 'var(--text-primary)', fontSize: 'var(--text-base)',
                    fontWeight: 600, cursor: 'pointer' }}>
                  Cancel
                </button>
                <button onClick={startUpdate}
                  style={{ padding: '9px 22px', borderRadius: 'var(--radius-sm)', border: 'none', cursor: 'pointer',
                    fontSize: 'var(--text-base)', fontWeight: 600, background: 'var(--primary)', color: '#fff' }}>
                  Start Update
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Full-screen update overlay */}
      {showUpdateOverlay && <UpdateOverlay />}

      {activeTab === 'about' && (
        <div style={CARD}>
          <div style={{ ...SECTION_HEADER, marginBottom: 20 }}>About</div>
          {[
            { label: 'Product',    value: 'LogVault — Syslog & Log Analyzer' },
            { label: 'Family',     value: 'NocVault Network Intelligence Suite' },
            { label: 'Version',    value: `v${appVersion || '1.0.0'}` },
            { label: 'App Port',   value: '3004' },
            { label: 'API Port',   value: '3005 (internal)' },
            { label: 'Collector',  value: 'UDP/TCP 514 · 1514' },
            { label: 'Database',   value: 'PostgreSQL 16' },
            { label: 'Runtime',    value: 'Node.js 20 · Next.js 16' },
          ].map(({ label, value }) => (
            <div key={label} style={{ display: 'flex', padding: '10px 0',
              borderBottom: '1px solid var(--border-light)' }}>
              <span style={{ width: 140, fontSize: 'var(--text-sm)', color: 'var(--text-muted)', fontWeight: 500 }}>{label}</span>
              <span style={{ fontSize: 'var(--text-sm)', color: 'var(--text-primary)', fontFamily: label.includes('Port') || label === 'Collector' || label === 'Database' || label === 'Runtime' ? 'var(--font-mono)' : 'inherit' }}>{value}</span>
            </div>
          ))}
          <div style={{ marginTop: 18, fontSize: 'var(--text-sm)', color: 'var(--text-muted)', lineHeight: 1.7 }}>
            <div style={{ fontWeight: 700, color: 'var(--text-primary)' }}>LogVault v{appVersion || '1.0.0'}</div>
            <div>Part of the NocVault Network Intelligence Suite</div>
            <div>© 2026 NocVault</div>
          </div>
        </div>
      )}
        </div>
      </div>
    </div>
  );
}

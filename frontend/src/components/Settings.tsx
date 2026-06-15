'use client';
import { useEffect, useState, useRef } from 'react';
import { useToast } from '@/components/Toast';
import { PageHeader } from './ui';

interface Settings {
  dns_server:         string;
  dns_lookup_enabled: string;
  smtp_host:          string;
  smtp_port:          string;
  smtp_user:          string;
  smtp_pass:          string;
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
}

const CARD  = { background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 12, padding: 20, marginBottom: 20, boxShadow: 'var(--shadow-sm)' };
const LABEL = { fontSize: 13, fontWeight: 500, color: 'var(--text-secondary)', marginBottom: 6, display: 'block' as const };
const INPUT = { width: '100%', padding: '9px 12px', borderRadius: 8, border: '1px solid var(--border)',
  background: 'var(--input-bg)', color: 'var(--text-primary)', fontSize: 13.5, outline: 'none',
  boxSizing: 'border-box' as const };
const SECTION_HEADER = { fontSize: 13, fontWeight: 600, color: 'var(--text-secondary)', textTransform: 'uppercase' as const, letterSpacing: '0.04em', marginBottom: 16 };

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

// Color + label for the minimum-risk-score badge based on the threshold.
function riskBadge(n: number): { color: string; label: string } {
  if (n <= 30)  return { color: '#16a34a', label: 'Low+' };
  if (n <= 60)  return { color: '#d97706', label: 'Medium+' };
  if (n <= 80)  return { color: '#ea580c', label: 'High+' };
  return { color: '#dc2626', label: 'Critical only' };
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
// Defined at module level (never inside another component).
function UpdateOverlay() {
  const [phase, setPhase] = useState<'starting' | 'down' | 'back_up' | 'timeout'>('starting');
  const [countdown, setCountdown] = useState(RELOAD_COUNTDOWN_SECONDS);
  const wentDown = useRef(false);
  const consecutiveUp = useRef(0);

  useEffect(() => {
    let active   = true;
    const startedAt = Date.now();
    let pollId:   ReturnType<typeof setInterval> | null = null;

    const stopPolling = () => { if (pollId !== null) { clearInterval(pollId); pollId = null; } };

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
          setPhase('back_up');
          stopPolling();
          // The reload itself is driven by the countdown effect below — the API
          // is up, but Next.js needs a little longer before it can serve pages.
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

  // Once the API is confirmed stably back up, count down (15…14…13…) before
  // reloading so the Next.js frontend has time to finish starting after the API.
  useEffect(() => {
    if (phase !== 'back_up') return;
    if (countdown <= 0) { window.location.href = '/?updated=true'; return; }
    const id = setTimeout(() => setCountdown(c => c - 1), 1000);
    return () => clearTimeout(id);
  }, [phase, countdown]);

  let statusLine = 'Starting update...';
  if (phase === 'down')          statusLine = 'Services restarting...';
  else if (phase === 'back_up')  statusLine = `✓ Services are back online. Reloading in ${countdown} second${countdown === 1 ? '' : 's'}...`;
  else if (phase === 'timeout')  statusLine = 'Update is taking longer than expected. Try reloading manually.';

  return (
    <div style={{ position: 'fixed', inset: 0, zIndex: 9999, background: 'rgba(0,0,0,0.5)',
      display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 16 }}>
      <style>{'@keyframes lv-spin { to { transform: rotate(360deg); } }'}</style>
      <div style={{ background: 'var(--bg-card)', borderRadius: 12, boxShadow: 'var(--shadow-md)',
        padding: 40, maxWidth: 480, width: '100%', textAlign: 'center' }}>
        {phase !== 'back_up' && phase !== 'timeout' && (
          <div style={{ fontSize: 44, lineHeight: 1, display: 'inline-block',
            color: 'var(--primary)', animation: 'lv-spin 1s linear infinite' }}>⟳</div>
        )}
        {phase === 'back_up' && <div style={{ fontSize: 44, lineHeight: 1 }}>✓</div>}
        {phase === 'timeout' && <div style={{ fontSize: 44, lineHeight: 1 }}>⚠</div>}
        <div style={{ fontSize: 18, fontWeight: 700, marginTop: 14, color: 'var(--text-primary)' }}>Updating LogVault...</div>
        <p style={{ fontSize: 13, color: 'var(--text-muted)', marginTop: 6 }}>
          Pulling latest code and restarting services. Do not close this window.
        </p>
        <p style={{ fontWeight: 600, margin: '14px 0', color: 'var(--text-primary)' }}>{statusLine}</p>
        {phase === 'back_up' && (
          <div style={{ fontSize: 40, fontWeight: 800, lineHeight: 1, margin: '4px 0 10px', color: 'var(--primary)' }}>
            {countdown}
          </div>
        )}
        {phase !== 'back_up' && (
          <p style={{ fontSize: 12, color: 'var(--text-muted)' }}>(This usually takes 1-3 minutes)</p>
        )}
        <button onClick={phase === 'back_up' ? () => { window.location.href = '/?updated=true'; } : () => window.location.reload()}
          style={{ marginTop: 10, padding: '9px 22px', borderRadius: 8, border: 'none',
            background: 'var(--primary)', color: '#fff', fontSize: 13, fontWeight: 600, cursor: 'pointer' }}>
          Reload Now
        </button>
      </div>
    </div>
  );
}

export default function Settings() {
  const { toast } = useToast();
  const [settings, setSettings]   = useState<Settings>({
    dns_server: '', dns_lookup_enabled: 'true',
    smtp_host: '', smtp_port: '587', smtp_user: '', smtp_pass: '',
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
  });
  const [saving,   setSaving]     = useState(false);
  const [activeTab, setActiveTab] = useState<'email' | 'system' | 'updates' | 'about'>('email');
  const [testTo,   setTestTo]     = useState('');
  const [testing,  setTesting]    = useState(false);

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
          setSettings(s => ({ ...s, ...d.data }));
        }
      }).catch(() => {});
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
        body: JSON.stringify({
          to:        testTo.trim(),
          smtp_host: settings.smtp_host,
          smtp_port: settings.smtp_port,
          smtp_user: settings.smtp_user,
          smtp_pass: settings.smtp_pass,
          smtp_from: settings.smtp_from,
        }),
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

  const TABS = [{ id: 'email', label: 'Email Alerts' }, { id: 'system', label: 'System' }, { id: 'updates', label: 'Updates' }, { id: 'about', label: 'About' }];

  const hasUpdateError = !!updateStatus?.error;
  const upToDate       = !hasUpdateError && !!updateStatus?.up_to_date;
  const updatesAvailable = !hasUpdateError && !!updateStatus?.update_available;

  return (
    <div style={{ width: '100%' }}>
      <PageHeader title="Settings" subtitle="System configuration and email alerts" />

      {/* Tab bar */}
      <div style={{ display: 'flex', gap: 4, borderBottom: '1px solid var(--border)', marginBottom: 20, flexWrap: 'wrap' }}>
        {TABS.map(t => (
          <button key={t.id} onClick={() => setActiveTab(t.id as any)}
            style={{ padding: '10px 18px', fontSize: 14, background: 'none', border: 'none',
              borderBottom: '2px solid transparent', marginBottom: -1, cursor: 'pointer',
              color: activeTab === t.id ? 'var(--primary)' : 'var(--text-muted)',
              fontWeight: activeTab === t.id ? 600 : 500,
              borderBottomColor: activeTab === t.id ? 'var(--primary)' : 'transparent' }}>
            {t.label}
            {t.id === 'updates' && updateAvail && (
              <span title="Update available"
                style={{ display: 'inline-block', width: 7, height: 7, borderRadius: '50%',
                  background: '#dc2626', marginLeft: 6, verticalAlign: 'middle' }} />
            )}
          </button>
        ))}
      </div>

      {activeTab === 'system' && (
        <>
          {/* DNS Settings */}
          <div style={CARD}>
            <div style={SECTION_HEADER}>DNS Lookup</div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 14 }}>
              <input type="checkbox"
                checked={settings.dns_lookup_enabled !== 'false'}
                onChange={e => setSettings(s => ({ ...s, dns_lookup_enabled: e.target.checked ? 'true' : 'false' }))}
                style={{ cursor: 'pointer', width: 16, height: 16 }} />
              <div>
                <div style={{ fontSize: 13, color: 'var(--text-primary)', fontWeight: 500 }}>
                  Enable reverse DNS lookup
                </div>
                <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>
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
              <input style={{ ...INPUT, maxWidth: 260 }}
                value={settings.dns_server}
                onChange={e => setSettings(s => ({ ...s, dns_server: e.target.value }))}
                placeholder="e.g. 192.168.1.1 or 8.8.8.8" />
              <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 6 }}>
                Used for reverse lookups of IPs appearing in logs — both internal devices and external IPs.
                Settings are applied automatically within 5 minutes — no restart needed.
              </div>
            </div>
          </div>

          {/* Save */}
          <button onClick={save} disabled={saving}
            style={{ padding: '10px 28px', borderRadius: 8, border: 'none', cursor: 'pointer',
              fontSize: 13, fontWeight: 600, background: 'var(--primary)', color: '#fff',
              opacity: saving ? 0.7 : 1, transition: 'all 0.15s' }}>
            {saving ? 'Saving...' : 'Save Settings'}
          </button>
        </>
      )}

      {activeTab === 'email' && (
        <>
          {/* SMTP Settings */}
          <div style={CARD}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16 }}>
              <div style={{ ...SECTION_HEADER, marginBottom: 0 }}>SMTP Server</div>
              <label style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer' }}>
                <input type="checkbox"
                  checked={settings.smtp_enabled === 'true'}
                  onChange={e => setSettings(s => ({ ...s, smtp_enabled: e.target.checked ? 'true' : 'false' }))}
                  style={{ cursor: 'pointer', width: 16, height: 16 }} />
                <span style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-secondary)' }}>
                  {settings.smtp_enabled === 'true' ? 'Enabled' : 'Disabled'}
                </span>
              </label>
            </div>
            <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 18 }}>
              Configure an SMTP server to send email notifications when alert rules fire.
              Emails are only sent for rules that have a notification address set.
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: 16, marginBottom: 16 }}>
              <div>
                <label style={LABEL}>SMTP Host</label>
                <input style={INPUT} value={settings.smtp_host}
                  onChange={e => setSettings(s => ({ ...s, smtp_host: e.target.value }))}
                  placeholder="e.g. smtp.gmail.com" />
              </div>
              <div>
                <label style={LABEL}>Port</label>
                <input style={INPUT} value={settings.smtp_port}
                  onChange={e => setSettings(s => ({ ...s, smtp_port: e.target.value }))}
                  placeholder="587" />
              </div>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 16 }}>
              <div>
                <label style={LABEL}>Username</label>
                <input style={INPUT} value={settings.smtp_user}
                  onChange={e => setSettings(s => ({ ...s, smtp_user: e.target.value }))}
                  placeholder="user@example.com" autoComplete="off" />
              </div>
              <div>
                <label style={LABEL}>Password</label>
                <input style={INPUT} type="password" value={settings.smtp_pass}
                  onChange={e => setSettings(s => ({ ...s, smtp_pass: e.target.value }))}
                  placeholder="••••••••" autoComplete="new-password" />
              </div>
            </div>

            <div style={{ marginBottom: 4 }}>
              <label style={LABEL}>From Address</label>
              <input style={INPUT} value={settings.smtp_from}
                onChange={e => setSettings(s => ({ ...s, smtp_from: e.target.value }))}
                placeholder="LogVault Alerts <alerts@example.com>" />
            </div>

            <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 12 }}>
              Common SMTP servers — Gmail: smtp.gmail.com:587 · Office365: smtp.office365.com:587 · Port 465 uses implicit TLS.
            </div>
            <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 6 }}>
              Settings applied automatically within 5 minutes — no restart needed.
            </div>
          </div>

          {/* SECTION 2 — Global Recipients */}
          <div style={CARD}>
            <div style={SECTION_HEADER}>Global Alert Recipients</div>
            <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 14 }}>
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
                    border: '1px solid var(--border)', borderRadius: 14, padding: '4px 10px',
                    fontSize: 12, color: 'var(--text-primary)' }}>
                  {email}
                  <button onClick={() => removeRecipient(email)}
                    style={{ border: 'none', background: 'transparent', cursor: 'pointer',
                      color: 'var(--text-muted)', fontSize: 14, lineHeight: 1, padding: 0 }}>
                    ×
                  </button>
                </span>
              ))}
            </div>
          </div>

          {/* SECTION 3 — Notification Filters */}
          <div style={CARD}>
            <div style={SECTION_HEADER}>When to Send Alerts</div>
            <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 16 }}>
              Only send emails when ALL selected conditions match
            </div>

            <label style={{ display: 'flex', alignItems: 'center', gap: 10, cursor: 'pointer', marginBottom: 20 }}>
              <input type="checkbox"
                checked={settings.email_notify_enabled === 'true'}
                onChange={e => setSettings(s => ({ ...s, email_notify_enabled: e.target.checked ? 'true' : 'false' }))}
                style={{ cursor: 'pointer', width: 16, height: 16 }} />
              <span style={{ fontSize: 13, color: 'var(--text-primary)', fontWeight: 500 }}>
                Email notifications enabled
              </span>
            </label>

            {/* 3a Severity */}
            <div style={{ marginBottom: 22 }}>
              <label style={LABEL}>Severity levels</label>
              <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 10 }}>
                Send email for these severity levels
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 8 }}>
                {SEVERITY_OPTS.map(o => (
                  <label key={o.value} style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer' }}>
                    <input type="checkbox"
                      checked={parseArr(settings.email_notify_severities).includes(o.value)}
                      onChange={() => toggleInArr('email_notify_severities', o.value)}
                      style={{ cursor: 'pointer', width: 15, height: 15 }} />
                    <span style={{ width: 8, height: 8, borderRadius: '50%', background: o.color, display: 'inline-block' }} />
                    <span style={{ fontSize: 12.5, color: 'var(--text-primary)' }}>{o.label}</span>
                  </label>
                ))}
              </div>
            </div>

            {/* 3b Categories */}
            <div style={{ marginBottom: 22 }}>
              <label style={LABEL}>Event categories</label>
              <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 10 }}>
                Only send for these categories (leave all unchecked to receive all categories)
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 8 }}>
                {CATEGORY_OPTS.map(o => (
                  <label key={o.value} style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer' }}>
                    <input type="checkbox"
                      checked={parseArr(settings.email_notify_categories).includes(o.value)}
                      onChange={() => toggleInArr('email_notify_categories', o.value)}
                      style={{ cursor: 'pointer', width: 15, height: 15 }} />
                    <span style={{ fontSize: 12.5, color: 'var(--text-primary)' }}>{o.label}</span>
                  </label>
                ))}
              </div>
            </div>

            {/* 3c Vendors */}
            <div style={{ marginBottom: 22 }}>
              <label style={LABEL}>Vendors</label>
              <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 10 }}>
                Only send for logs from these vendors (leave all unchecked to receive from all vendors)
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 8 }}>
                {VENDOR_OPTS.map(o => (
                  <label key={o.value} style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer' }}>
                    <input type="checkbox"
                      checked={parseArr(settings.email_notify_vendors).includes(o.value)}
                      onChange={() => toggleInArr('email_notify_vendors', o.value)}
                      style={{ cursor: 'pointer', width: 15, height: 15 }} />
                    <span style={{ fontSize: 12.5, color: 'var(--text-primary)' }}>{o.label}</span>
                  </label>
                ))}
              </div>
            </div>

            {/* 3d Minimum risk score */}
            <div style={{ marginBottom: 22 }}>
              <label style={LABEL}>Minimum risk score</label>
              <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 10 }}>
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
                      borderRadius: 14, background: b.color, color: '#fff', fontSize: 12, fontWeight: 600 }}>
                      {v} · {b.label}
                    </span>
                  </div>
                );
              })()}
            </div>

            {/* 3e Cooldown */}
            <div>
              <label style={LABEL}>Cooldown between alerts</label>
              <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 10 }}>
                Minimum time between emails for the same alert rule (prevents email flooding)
              </div>
              <select
                value={settings.email_notify_cooldown_mins}
                onChange={e => setSettings(s => ({ ...s, email_notify_cooldown_mins: e.target.value }))}
                style={{ ...INPUT, maxWidth: 260, cursor: 'pointer' }}>
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
              <span style={{ fontSize: 13, color: 'var(--text-primary)' }}>
                <span style={{ fontWeight: 600 }}>Instant</span> — Send email immediately when alert fires
              </span>
            </label>
            <label style={{ display: 'flex', alignItems: 'flex-start', gap: 10, cursor: 'pointer', marginBottom: 14 }}>
              <input type="radio" name="delivery" value="digest"
                checked={settings.email_notify_digest_mode === 'digest'}
                onChange={() => setSettings(s => ({ ...s, email_notify_digest_mode: 'digest' }))}
                style={{ cursor: 'pointer', marginTop: 2, width: 15, height: 15 }} />
              <span style={{ fontSize: 13, color: 'var(--text-primary)' }}>
                <span style={{ fontWeight: 600 }}>Daily Digest</span> — Collect alerts and send one summary email
              </span>
            </label>

            {settings.email_notify_digest_mode === 'digest' && (
              <div style={{ marginLeft: 25 }}>
                <label style={LABEL}>Send digest at</label>
                <select
                  value={settings.email_notify_digest_hour}
                  onChange={e => setSettings(s => ({ ...s, email_notify_digest_hour: e.target.value }))}
                  style={{ ...INPUT, maxWidth: 160, cursor: 'pointer' }}>
                  {Array.from({ length: 24 }, (_, h) => (
                    <option key={h} value={String(h)}>{String(h).padStart(2, '0')}:00</option>
                  ))}
                </select>
                <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 8 }}>
                  Sends a summary of all alerts from the past 24 hours at the selected time
                </div>
              </div>
            )}
          </div>

          {/* Shared Save (SMTP + recipients + filters + delivery) */}
          <button onClick={save} disabled={saving}
            style={{ padding: '10px 28px', borderRadius: 8, border: 'none', cursor: 'pointer',
              fontSize: 13, fontWeight: 600, background: 'var(--primary)', color: '#fff',
              opacity: saving ? 0.7 : 1, transition: 'all 0.15s', marginBottom: 16 }}>
            {saving ? 'Saving...' : 'Save Settings'}
          </button>

          {/* SECTION 5 — Per-Rule Recipients */}
          <div style={CARD}>
            <div style={SECTION_HEADER}>Per-Rule Recipients</div>
            <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 16 }}>
              Override recipients for specific alert rules. These are in addition to global recipients.
            </div>
            {rules.length === 0 ? (
              <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>No alert rules configured.</div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
                {rules.map(rule => {
                  const val = ruleEmails[rule.id] || '';
                  const showHint = !rule.notify_email && !val;
                  return (
                    <div key={rule.id} style={{ display: 'flex', alignItems: 'flex-end', gap: 12,
                      paddingBottom: 14, borderBottom: '1px solid var(--border-light)' }}>
                      <div style={{ flex: 1, minWidth: 0 }}>
                        <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-primary)' }}>{rule.name}</div>
                        {rule.description && (
                          <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>{rule.description}</div>
                        )}
                        <input style={{ ...INPUT, marginTop: 8 }}
                          value={val}
                          onChange={e => setRuleEmails(m => ({ ...m, [rule.id]: e.target.value }))}
                          placeholder="optional override" />
                        {showHint && (
                          <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 4 }}>No custom recipient</div>
                        )}
                      </div>
                      <button onClick={() => saveRuleEmail(rule.id)} disabled={savingRule === rule.id}
                        style={{ padding: '9px 18px', borderRadius: 7, border: '1px solid var(--border)', cursor: 'pointer',
                          fontSize: 12, fontWeight: 600, background: 'var(--input-bg)', color: 'var(--text-primary)',
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
          <div style={CARD}>
            <div style={{ ...SECTION_HEADER, marginBottom: 6 }}>Send Test Email</div>
            <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 14 }}>
              Sends a test message using the settings above (without saving them first).
            </div>
            <div style={{ display: 'flex', alignItems: 'flex-end', gap: 12 }}>
              <div style={{ flex: 1, maxWidth: 360 }}>
                <label style={LABEL}>Recipient Address</label>
                <input style={INPUT} type="email" value={testTo}
                  onChange={e => setTestTo(e.target.value)}
                  placeholder="you@example.com" />
              </div>
              <button onClick={sendTest} disabled={testing}
                style={{ padding: '9px 20px', borderRadius: 7, border: '1px solid var(--border)', cursor: 'pointer',
                  fontSize: 12, fontWeight: 600, background: 'var(--input-bg)', color: 'var(--text-primary)',
                  opacity: testing ? 0.7 : 1, whiteSpace: 'nowrap' }}>
                {testing ? 'Sending...' : 'Send Test'}
              </button>
            </div>
            {parseEmails(settings.email_notify_recipients).length > 0 ? (
              <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 12 }}>
                Test email will be sent to: {parseEmails(settings.email_notify_recipients).join(', ')}
              </div>
            ) : (
              <div style={{ background: 'rgba(217,119,6,0.1)', border: '1px solid rgba(217,119,6,0.3)',
                borderRadius: 8, padding: '10px 14px', marginTop: 12, fontSize: 12.5, color: '#b45309' }}>
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
            <div style={{ fontSize: 13, color: 'var(--text-muted)' }}>Checking for updates...</div>
          ) : hasUpdateError ? (
            <div>
              <div style={{ fontSize: 13, color: '#d97706', fontWeight: 600, marginBottom: 14 }}>
                {updateStatus?.error}
              </div>
              <button onClick={checkUpdate}
                style={{ padding: '8px 18px', borderRadius: 7, border: '1px solid var(--border)',
                  background: 'var(--input-bg)', color: 'var(--text-primary)', fontSize: 12,
                  fontWeight: 600, cursor: 'pointer' }}>
                Re-check
              </button>
            </div>
          ) : upToDate ? (
            <div>
              <div style={{ fontSize: 15, fontWeight: 700, color: '#16a34a', marginBottom: 8 }}>
                ✓ LogVault is up to date
              </div>
              {updateStatus?.current_version && (
                <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 16 }}>
                  Current version: <code style={{ fontFamily: 'JetBrains Mono, monospace' }}>v{updateStatus.current_version}</code>
                </div>
              )}
              <button onClick={checkUpdate}
                style={{ padding: '8px 18px', borderRadius: 7, border: '1px solid var(--border)',
                  background: 'var(--input-bg)', color: 'var(--text-primary)', fontSize: 12,
                  fontWeight: 600, cursor: 'pointer' }}>
                Re-check
              </button>
            </div>
          ) : updatesAvailable ? (
            <div>
              <div style={{ fontSize: 15, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 6 }}>
                {updateStatus?.current_version === updateStatus?.latest_version
                  ? <>🔄 Patches available since <code style={{ fontFamily: 'JetBrains Mono, monospace' }}>v{updateStatus?.current_version}</code></>
                  : <>🔄 Update available: <code style={{ fontFamily: 'JetBrains Mono, monospace' }}>v{updateStatus?.current_version}</code>
                    {' → '}
                    <code style={{ fontFamily: 'JetBrains Mono, monospace' }}>v{updateStatus?.latest_version}</code></>}
              </div>
              {(updateStatus?.current_commit || updateStatus?.latest_commit) && (
                <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 14 }}>
                  Current: v{updateStatus?.current_version}
                  {updateStatus?.current_commit && <> (<code style={{ fontFamily: 'JetBrains Mono, monospace' }}>{updateStatus.current_commit}</code>)</>}
                  {'  →  '}
                  Latest: v{updateStatus?.latest_version}
                  {updateStatus?.latest_commit && <> (<code style={{ fontFamily: 'JetBrains Mono, monospace' }}>{updateStatus.latest_commit}</code>)</>}
                </div>
              )}

              {updateStatus?.release_notes && updateStatus.release_notes.length > 0 && (
                <div style={{ marginBottom: 16 }}>
                  <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-secondary)', marginBottom: 6 }}>
                    What&apos;s new{updateStatus?.latest_version ? ` in v${updateStatus.latest_version}` : ''}
                  </div>
                  <ul style={{ margin: 0, paddingLeft: 20, fontSize: 12.5, lineHeight: 1.6,
                    color: 'var(--text-primary)' }}>
                    {updateStatus.release_notes.map((note, i) => (
                      <li key={i}>{note}</li>
                    ))}
                  </ul>
                  {updateStatus?.release_date && (
                    <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 8 }}>
                      Released: {fmtReleaseDate(updateStatus.release_date)}
                    </div>
                  )}
                </div>
              )}

              <div style={{ background: 'rgba(217,119,6,0.1)', border: '1px solid rgba(217,119,6,0.3)',
                borderRadius: 8, padding: '10px 14px', marginBottom: 16, fontSize: 12.5, color: '#b45309' }}>
                ⚠ Services will restart during update. You may lose connection briefly (30-60 seconds).
              </div>

              <div style={{ display: 'flex', gap: 10 }}>
                <button onClick={() => setShowConfirmModal(true)} disabled={updating}
                  style={{ padding: '9px 22px', borderRadius: 8, border: 'none',
                    cursor: updating ? 'default' : 'pointer', opacity: updating ? 0.6 : 1,
                    fontSize: 13, fontWeight: 600, background: '#C8102E', color: '#fff' }}>
                  Update Now
                </button>
                <button onClick={checkUpdate}
                  style={{ padding: '9px 18px', borderRadius: 8, border: '1px solid var(--border)',
                    background: 'var(--input-bg)', color: 'var(--text-primary)', fontSize: 13,
                    fontWeight: 600, cursor: 'pointer' }}>
                  Re-check
                </button>
              </div>

              {updateBlocked && (
                <div style={{ marginTop: 12, fontSize: 13, color: 'var(--primary)' }}>
                  Updates disabled: {updateBlocked}{' '}
                  <a
                    href={(process.env.NEXT_PUBLIC_NOCVAULT_HUB_URL || '') + '/settings/license'}
                    style={{ color: 'var(--primary)', fontWeight: 600, textDecoration: 'underline' }}
                  >
                    Renew License
                  </a>
                </div>
              )}
            </div>
          ) : (
            <button onClick={checkUpdate}
              style={{ padding: '8px 18px', borderRadius: 7, border: '1px solid var(--border)',
                background: 'var(--input-bg)', color: 'var(--text-primary)', fontSize: 12,
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
            style={{ background: 'var(--bg-card)', borderRadius: 12, width: '100%', maxWidth: 460,
              overflow: 'hidden', boxShadow: '0 10px 40px rgba(0,0,0,0.3)' }}>
            <div style={{ background: '#1a2744', color: '#fff', padding: '14px 20px', fontSize: 15, fontWeight: 700 }}>
              Start Update?
            </div>
            <div style={{ padding: 20 }}>
              <div style={{ fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.5, marginBottom: 20 }}>
                Start update? Services will restart and you will lose connection for 30-60 seconds.
              </div>
              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 10 }}>
                <button onClick={() => setShowConfirmModal(false)}
                  style={{ padding: '9px 18px', borderRadius: 8, border: '1px solid var(--border)',
                    background: 'var(--input-bg)', color: 'var(--text-primary)', fontSize: 13,
                    fontWeight: 600, cursor: 'pointer' }}>
                  Cancel
                </button>
                <button onClick={startUpdate}
                  style={{ padding: '9px 22px', borderRadius: 8, border: 'none', cursor: 'pointer',
                    fontSize: 13, fontWeight: 600, background: '#C8102E', color: '#fff' }}>
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
          <div style={{ ...SECTION_HEADER, marginBottom: 20 }}>About LogVault</div>
          {[
            { label: 'Product',    value: 'LogVault — Syslog & Log Analyzer' },
            { label: 'Family',     value: 'NocVault Network Intelligence Suite' },
            { label: 'Version',    value: `v${appVersion || '1.0.0'}` },
            { label: 'API Port',   value: '3005 (internal)' },
            { label: 'App Port',   value: '3004' },
            { label: 'Collector',  value: 'UDP/TCP 514 · 1514' },
            { label: 'Database',   value: 'PostgreSQL 16' },
            { label: 'Runtime',    value: 'Node.js 20 · Next.js 16' },
          ].map(({ label, value }) => (
            <div key={label} style={{ display: 'flex', padding: '10px 0',
              borderBottom: '1px solid var(--border-light)' }}>
              <span style={{ width: 140, fontSize: 12, color: 'var(--text-muted)', fontWeight: 500 }}>{label}</span>
              <span style={{ fontSize: 12, color: 'var(--text-primary)', fontFamily: label.includes('Port') || label === 'Collector' || label === 'Database' || label === 'Runtime' ? 'JetBrains Mono, monospace' : 'inherit' }}>{value}</span>
            </div>
          ))}
          <div style={{ marginTop: 18, fontSize: 12, color: 'var(--text-muted)', lineHeight: 1.7 }}>
            <div style={{ fontWeight: 700, color: 'var(--text-primary)' }}>LogVault v{appVersion || '1.0.0'}</div>
            <div>Part of the NocVault Intelligence Suite</div>
            <div>© 2026 NocVault</div>
          </div>
        </div>
      )}
    </div>
  );
}

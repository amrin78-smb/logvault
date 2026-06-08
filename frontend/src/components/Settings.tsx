'use client';
import { useEffect, useState, useRef } from 'react';
import { useToast } from '@/components/Toast';
import { PageHeader } from './ui';

interface Settings {
  app_name:           string;
  app_subtitle:       string;
  primary_color:      string;
  sidebar_color:      string;
  logo_url:           string;
  dns_server:         string;
  dns_lookup_enabled: string;
  smtp_host:          string;
  smtp_port:          string;
  smtp_user:          string;
  smtp_pass:          string;
  smtp_from:          string;
  smtp_enabled:       string;
}

const CARD  = { background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 10, padding: 24, marginBottom: 16 };
const LABEL = { fontSize: 12, fontWeight: 600, color: 'var(--text-secondary)', marginBottom: 6, display: 'block' as const };
const INPUT = { width: '100%', padding: '9px 12px', borderRadius: 7, border: '1px solid var(--border)',
  background: 'var(--input-bg)', color: 'var(--text-primary)', fontSize: 13, outline: 'none',
  boxSizing: 'border-box' as const };

interface UpdateStatus {
  current_version?: string;
  latest_version?:  string;
  commits_behind?:  number;
  up_to_date?:      boolean;
  changes?:         string[];
  error?:           string;
}

const UPDATE_TIMEOUT_MS = 3 * 60 * 1000; // 3 minutes

// Strip the leading short-hash from a "abc1234 subject" change line.
function changeSubject(line: string): string {
  const m = line.match(/^([0-9a-f]{7,40})\s+(.*)$/i);
  return m ? m[2] : line;
}

// Full-screen overlay shown during an update; polls /api/health for recovery.
// The API must be seen DOWN before an UP response counts as recovery, so we
// never declare "complete" against the still-running pre-restart service.
// Defined at module level (never inside another component).
function UpdateOverlay() {
  const [phase, setPhase] = useState<'starting' | 'down' | 'back_up' | 'timeout'>('starting');
  const wentDown = useRef(false);

  useEffect(() => {
    let active   = true;
    const startedAt = Date.now();
    let pollId:   ReturnType<typeof setInterval> | null = null;
    let reloadId: ReturnType<typeof setTimeout> | null = null;

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
        // Fetch failed or non-200 → API is down (restarting).
        wentDown.current = true;
        setPhase('down');
        return;
      }

      // Healthy response. Only a recovery if we previously saw it go down.
      if (wentDown.current) {
        setPhase('back_up');
        stopPolling();
        reloadId = setTimeout(() => { window.location.href = '/?updated=true'; }, 2000);
      }
      // else: still the pre-restart API — keep waiting for it to go down.
    };

    pollId = setInterval(tick, 2000); // poll every 2 seconds
    tick(); // immediate first poll

    return () => {
      active = false;
      stopPolling();
      if (reloadId !== null) clearTimeout(reloadId);
    };
  }, []);

  let statusLine = 'Starting update...';
  if (phase === 'down')          statusLine = 'Services restarting...';
  else if (phase === 'back_up')  statusLine = '✓ Update complete! Redirecting...';
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
        <p style={{ fontSize: 12, color: 'var(--text-muted)' }}>(This usually takes 30-60 seconds)</p>
        <button onClick={() => window.location.reload()}
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
  const fileRef   = useRef<HTMLInputElement>(null);
  const [settings, setSettings]   = useState<Settings>({
    app_name: 'LogVault', app_subtitle: 'Syslog & Log Analysis',
    primary_color: '#2563eb', sidebar_color: '#0f1b2d', logo_url: '',
    dns_server: '', dns_lookup_enabled: 'true',
    smtp_host: '', smtp_port: '587', smtp_user: '', smtp_pass: '',
    smtp_from: '', smtp_enabled: 'false',
  });
  const [preview,  setPreview]    = useState<string>('');
  const [saving,   setSaving]     = useState(false);
  const [activeTab, setActiveTab] = useState<'branding' | 'email' | 'updates' | 'about'>('branding');
  const [testTo,   setTestTo]     = useState('');
  const [testing,  setTesting]    = useState(false);

  // ── Updates tab state ──────────────────────────────────────
  const [updateStatus,     setUpdateStatus]     = useState<UpdateStatus | null>(null);
  const [checkingUpdate,   setCheckingUpdate]   = useState(false);
  const [updating,         setUpdating]         = useState(false);
  const [showUpdateOverlay, setShowUpdateOverlay] = useState(false);
  const [showConfirmModal,  setShowConfirmModal]  = useState(false);

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
    setUpdating(true);
    setShowUpdateOverlay(true);
    try {
      await fetch('/api/system/update', { method: 'POST' });
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
          setPreview(d.data.logo_url || '');
        }
      }).catch(() => {});
  }, []);

  const handleLogoFile = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    if (file.size > 512000) { toast('Logo must be under 500KB', 'error'); return; }
    const reader = new FileReader();
    reader.onload = ev => {
      const data = ev.target?.result as string;
      setPreview(data);
      setSettings(s => ({ ...s, logo_url: data }));
    };
    reader.readAsDataURL(file);
  };

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

  const TABS = [{ id: 'branding', label: 'Branding' }, { id: 'email', label: 'Email Alerts' }, { id: 'updates', label: 'Updates' }, { id: 'about', label: 'About' }];

  const commitsBehind = updateStatus?.commits_behind ?? 0;
  const hasUpdateError = !!updateStatus?.error;
  const upToDate       = !hasUpdateError && !!updateStatus?.up_to_date;
  const updatesAvailable = !hasUpdateError && !upToDate && commitsBehind > 0;

  return (
    <div style={{ maxWidth: 800 }}>
      <PageHeader title="Settings" subtitle="Branding, DNS lookup and SMTP email configuration" />

      {/* Tab bar */}
      <div style={{ display: 'flex', gap: 4, marginBottom: 20, background: 'var(--bg-card)',
        border: '1px solid var(--border)', borderRadius: 10, padding: 6, width: 'fit-content' }}>
        {TABS.map(t => (
          <button key={t.id} onClick={() => setActiveTab(t.id as any)}
            style={{ padding: '6px 18px', borderRadius: 6, border: 'none', cursor: 'pointer',
              fontSize: 12, fontWeight: activeTab === t.id ? 600 : 400,
              background: activeTab === t.id ? '#1a202c' : 'transparent',
              color: activeTab === t.id ? '#fff' : 'var(--text-muted)' }}>
            {t.label}
          </button>
        ))}
      </div>

      {activeTab === 'branding' && (
        <>
          {/* Preview */}
          <div style={CARD}>
            <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-primary)', marginBottom: 14, textTransform: 'uppercase', letterSpacing: '0.5px' }}>PREVIEW</div>
            <div style={{ background: settings.sidebar_color, borderRadius: 8, padding: '12px 16px',
              display: 'inline-flex', alignItems: 'center', gap: 10, minWidth: 260 }}>
              {preview ? (
                <img src={preview} alt="Logo" style={{ height: 36, width: 'auto', objectFit: 'contain' }} />
              ) : (
                <>
                  <div style={{ width: 32, height: 32, background: settings.primary_color,
                    borderRadius: 7, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                    <svg width="18" height="18" viewBox="0 0 16 16" fill="none">
                      <path d="M8 1L14 4.5V11.5L8 15L2 11.5V4.5L8 1Z" stroke="white" strokeWidth="1.3" fill="none"/>
                      <circle cx="8" cy="8" r="2" fill="white"/>
                    </svg>
                  </div>
                  <div>
                    <div style={{ fontSize: 15, fontWeight: 700, color: '#fff' }}>{settings.app_name || 'LogVault'}</div>
                    <div style={{ fontSize: 9, color: '#64748b' }}>{settings.app_subtitle || 'Syslog & Log Analysis'}</div>
                  </div>
                </>
              )}
            </div>
          </div>

          {/* App Identity */}
          <div style={CARD}>
            <div style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 16 }}>App Identity</div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 16 }}>
              <div>
                <label style={LABEL}>App Name</label>
                <input style={INPUT} value={settings.app_name}
                  onChange={e => setSettings(s => ({ ...s, app_name: e.target.value }))}
                  placeholder="e.g. LogVault" />
              </div>
              <div>
                <label style={LABEL}>Subtitle</label>
                <input style={INPUT} value={settings.app_subtitle}
                  onChange={e => setSettings(s => ({ ...s, app_subtitle: e.target.value }))}
                  placeholder="e.g. Syslog & Log Analysis" />
              </div>
            </div>

            {/* Logo upload */}
            <label style={LABEL}>Logo</label>
            <div style={{ display: 'flex', alignItems: 'flex-start', gap: 16 }}>
              {preview && (
                <div style={{ position: 'relative' }}>
                  <img src={preview} alt="Logo preview"
                    style={{ height: 48, width: 'auto', objectFit: 'contain',
                      background: settings.sidebar_color, padding: 8, borderRadius: 8 }} />
                  <button onClick={() => { setPreview(''); setSettings(s => ({ ...s, logo_url: '' })); }}
                    style={{ position: 'absolute', top: -6, right: -6, width: 18, height: 18,
                      borderRadius: '50%', border: 'none', background: '#ef4444', color: '#fff',
                      fontSize: 10, cursor: 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                    ×
                  </button>
                </div>
              )}
              <div>
                <input ref={fileRef} type="file" accept="image/png,image/jpeg,image/svg+xml,image/webp"
                  onChange={handleLogoFile} style={{ display: 'none' }} />
                <button onClick={() => fileRef.current?.click()}
                  style={{ padding: '8px 16px', borderRadius: 7, border: '1px solid var(--border)',
                    background: 'var(--input-bg)', color: 'var(--text-secondary)', fontSize: 12,
                    cursor: 'pointer', marginBottom: 6 }}>
                  Upload image
                </button>
                <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 8 }}>PNG, JPG, SVG or WebP — max 500KB</div>
                <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>Or paste a URL:</div>
                <input style={{ ...INPUT, width: 400 }} value={settings.logo_url.startsWith('data:') ? '' : settings.logo_url}
                  onChange={e => { setSettings(s => ({ ...s, logo_url: e.target.value })); setPreview(e.target.value); }}
                  placeholder="https://..." />
              </div>
            </div>
          </div>

          {/* Colors */}
          <div style={CARD}>
            <div style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 16 }}>Colors</div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
              {[
                { key: 'primary_color', label: 'Primary Color', hint: 'buttons, accents' },
                { key: 'sidebar_color', label: 'Sidebar Color', hint: 'navigation background' },
              ].map(({ key, label, hint }) => (
                <div key={key}>
                  <label style={LABEL}>{label} <span style={{ color: 'var(--text-muted)', fontWeight: 400 }}>({hint})</span></label>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                    <input type="color" value={(settings as any)[key]}
                      onChange={e => setSettings(s => ({ ...s, [key]: e.target.value }))}
                      style={{ width: 40, height: 36, borderRadius: 6, border: '1px solid var(--border)',
                        cursor: 'pointer', padding: 2, background: 'var(--input-bg)' }} />
                    <input style={{ ...INPUT, width: 140 }} value={(settings as any)[key]}
                      onChange={e => setSettings(s => ({ ...s, [key]: e.target.value }))}
                      placeholder="#000000" />
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* DNS Settings */}
          <div style={CARD}>
            <div style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 16 }}>DNS Lookup</div>
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
              fontSize: 13, fontWeight: 600, background: '#2563eb', color: '#fff',
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
              <div style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-primary)' }}>SMTP Server</div>
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

          {/* Test Email */}
          <div style={CARD}>
            <div style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 6 }}>Send Test Email</div>
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
          </div>

          {/* Save */}
          <button onClick={save} disabled={saving}
            style={{ padding: '10px 28px', borderRadius: 8, border: 'none', cursor: 'pointer',
              fontSize: 13, fontWeight: 600, background: '#2563eb', color: '#fff',
              opacity: saving ? 0.7 : 1, transition: 'all 0.15s' }}>
            {saving ? 'Saving...' : 'Save Settings'}
          </button>
        </>
      )}

      {activeTab === 'updates' && (
        <div style={CARD}>
          <div style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 16 }}>Software Updates</div>

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
                  Current version: <code style={{ fontFamily: 'JetBrains Mono, monospace' }}>{updateStatus.current_version}</code>
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
                🔄 {commitsBehind} update{commitsBehind === 1 ? '' : 's'} available
              </div>
              <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 14 }}>
                Current: <code style={{ fontFamily: 'JetBrains Mono, monospace' }}>{updateStatus?.current_version}</code>
                {'  →  '}
                Latest: <code style={{ fontFamily: 'JetBrains Mono, monospace' }}>{updateStatus?.latest_version}</code>
              </div>

              {updateStatus?.changes && updateStatus.changes.length > 0 && (
                <div style={{ marginBottom: 16 }}>
                  <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-secondary)', marginBottom: 6 }}>Changes</div>
                  <ul style={{ margin: 0, paddingLeft: 20, fontSize: 12.5, color: 'var(--text-primary)' }}>
                    {updateStatus.changes.map((c, i) => (
                      <li key={i} style={{ marginBottom: 3 }}>{changeSubject(c)}</li>
                    ))}
                  </ul>
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
          <div style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 20 }}>About LogVault</div>
          {[
            { label: 'Product',    value: 'LogVault — Syslog & Log Analyzer' },
            { label: 'Family',     value: 'NocVault Network Intelligence Suite' },
            { label: 'Version',    value: '1.0.0' },
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
        </div>
      )}
    </div>
  );
}

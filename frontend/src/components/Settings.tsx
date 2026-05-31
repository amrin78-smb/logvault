'use client';
import { useEffect, useState, useRef } from 'react';
import { useToast } from '@/components/Toast';

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
  const [activeTab, setActiveTab] = useState<'branding' | 'email' | 'about'>('branding');
  const [testTo,   setTestTo]     = useState('');
  const [testing,  setTesting]    = useState(false);

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

  const TABS = [{ id: 'branding', label: 'Branding' }, { id: 'email', label: 'Email Alerts' }, { id: 'about', label: 'About' }];

  return (
    <div style={{ maxWidth: 800 }}>
      <div style={{ fontSize: 18, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 4 }}>Settings</div>
      <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 20 }}>Manage app branding and configuration</div>

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

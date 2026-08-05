'use client';
import { useState, useRef, useEffect, useCallback } from 'react';
import { useTheme } from './ThemeContext';
import { useSession } from 'next-auth/react';
import { getHubUrl } from '@/lib/publicUrl';
import CornersToggle from './CornersToggle';

// Manual CSRF sign-out — clears the NextAuth session then returns to the hub
// login. Do NOT use the next-auth signOut helper (breaks the SSO cookie flow).
// getHubUrl() is called here (not a module-level constant) so it always
// reflects the CURRENT window.location at click time.
async function handleSignOut() {
  try {
    const csrfRes = await fetch('/api/auth/csrf');
    const { csrfToken } = await csrfRes.json();
    await fetch('/api/auth/signout', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `csrfToken=${csrfToken}&callbackUrl=/`,
    });
  } catch {}
  window.location.replace(getHubUrl() + '/login');
}

function SunIcon() {
  return (
    <svg width="18" height="18" viewBox="0 0 16 16" fill="none">
      <circle cx="8" cy="8" r="3.2" fill="currentColor" />
      <g stroke="currentColor" strokeWidth="1.4" strokeLinecap="round">
        <line x1="8" y1="0.5" x2="8" y2="2.2" /><line x1="8" y1="13.8" x2="8" y2="15.5" />
        <line x1="0.5" y1="8" x2="2.2" y2="8" /><line x1="13.8" y1="8" x2="15.5" y2="8" />
        <line x1="2.7" y1="2.7" x2="3.9" y2="3.9" /><line x1="12.1" y1="12.1" x2="13.3" y2="13.3" />
        <line x1="2.7" y1="13.3" x2="3.9" y2="12.1" /><line x1="12.1" y1="3.9" x2="13.3" y2="2.7" />
      </g>
    </svg>
  );
}
function MoonIcon() {
  return (
    <svg width="18" height="18" viewBox="0 0 16 16" fill="none">
      <path d="M13.5 8.7A5.8 5.8 0 1 1 7.3 2.5a4.6 4.6 0 0 0 6.2 6.2z" fill="currentColor" />
    </svg>
  );
}

// ── Global search ────────────────────────────────────────────
// Backed by GET /api/search. Types mirror that endpoint's response.
type HostHit  = { ip_address: string; hostname: string | null; vendor: string | null; site_name: string | null; is_known_bad: boolean | null };
type AlertHit = { id: number; fired_at: string; source_host: string | null; sample_message: string | null; rule_name: string | null; acknowledged: boolean };
type LogHit   = { id: string; received_at: string; source_host: string | null; vendor: string | null; severity: number | null; message: string };
type SearchResults = { hosts: HostHit[]; alerts: AlertHit[]; logs: LogHit[]; log_window_hours?: number; truncated?: boolean };

const EMPTY_RESULTS: SearchResults = { hosts: [], alerts: [], logs: [] };

// Jump to a tab, optionally carrying a Log Explorer filter. page.tsx's
// 'nocvault:navigate' listener applies the filter before switching tabs.
function navigateTo(tab: string, filter?: Record<string, string>) {
  window.dispatchEvent(new CustomEvent('nocvault:navigate', { detail: { tab, filter } }));
}

// Top-level, NOT nested inside Header — a component defined inside another is
// re-created every render, which remounts the input and drops focus on each
// keystroke (suite-wide rule; see CLAUDE.md "Never define components inside
// other components").
function SearchGroup({ label, count, children }: { label: string; count: number; children: React.ReactNode }) {
  if (!count) return null;
  return (
    <div style={{ padding: '4px 0' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '6px 12px 4px',
        fontSize: 'var(--text-xs)', fontWeight: 700, letterSpacing: 0.5, textTransform: 'uppercase',
        color: 'var(--text-muted)' }}>
        {label}<span style={{ opacity: 0.7, fontWeight: 600 }}>({count})</span>
      </div>
      {children}
    </div>
  );
}

function SearchRow({ dot, primary, secondary, meta, onClick }: {
  dot: string; primary: string; secondary?: string | null; meta?: string | null; onClick: () => void;
}) {
  return (
    <button
      onClick={onClick}
      style={{ display: 'flex', alignItems: 'center', gap: 8, width: '100%', padding: '7px 12px',
        background: 'none', border: 'none', cursor: 'pointer', textAlign: 'left',
        fontSize: 'var(--text-base)', color: 'var(--text-primary)' }}
      onMouseEnter={e => { (e.currentTarget as HTMLElement).style.background = 'var(--surface-subtle)'; }}
      onMouseLeave={e => { (e.currentTarget as HTMLElement).style.background = 'transparent'; }}
    >
      {/* intentional: a true circle (result-type dot), deliberately not squared. */}
      <span style={{ width: 7, height: 7, borderRadius: '50%', background: dot, flexShrink: 0 }} aria-hidden />
      <span style={{ fontWeight: 600, whiteSpace: 'nowrap' }}>{primary}</span>
      {secondary ? (
        <span style={{ color: 'var(--text-secondary)', overflow: 'hidden', textOverflow: 'ellipsis',
          whiteSpace: 'nowrap', flex: 1, minWidth: 0 }}>{secondary}</span>
      ) : <span style={{ flex: 1 }} />}
      {meta ? (
        <span style={{ color: 'var(--text-muted)', fontSize: 'var(--text-xs)', flexShrink: 0 }}>{meta}</span>
      ) : null}
    </button>
  );
}

export default function Header() {
  const { theme, toggle } = useTheme();
  // Computed per-render (cheap) so it reflects the current window.location
  // rather than a value cached at module-load time.
  const hubUrl = getHubUrl();
  const { data: session } = useSession();
  const user = session?.user as any;
  const role = (user?.role as string) || 'user';
  const roleBadge = role === 'super_admin'
    ? { label: 'Super Admin', bg: 'rgba(200,16,46,0.18)', fg: '#ef4444' }
    : role === 'admin'
    ? { label: 'Admin', bg: 'rgba(59,130,246,0.18)', fg: '#3b82f6' }
    : { label: 'User', bg: 'rgba(148,163,184,0.18)', fg: '#94a3b8' };
  const [dropdownOpen, setDropdownOpen] = useState(false);
  const [search, setSearch] = useState('');
  const [collectorOnline, setCollectorOnline] = useState(false);
  const [unacked, setUnacked] = useState(0);
  const dropdownRef = useRef<HTMLDivElement>(null);
  const searchRef = useRef<HTMLInputElement>(null);
  const [results, setResults] = useState<SearchResults>(EMPTY_RESULTS);
  const [searching, setSearching] = useState(false);
  const [searchOpen, setSearchOpen] = useState(false);
  const searchBoxRef = useRef<HTMLDivElement>(null);
  // Monotonic request id: a slow early response must never overwrite a newer one.
  const reqId = useRef(0);

  const term = search.trim();
  const totalHits = results.hosts.length + results.alerts.length + results.logs.length;

  // Debounced global search. 250ms keeps keystrokes off a 10.5M-row table; the
  // server also refuses terms shorter than 2 characters.
  useEffect(() => {
    if (term.length < 2) { setResults(EMPTY_RESULTS); setSearching(false); return; }
    setSearching(true);
    const myId = ++reqId.current;
    const t = setTimeout(async () => {
      try {
        const r = await fetch(`/api/search?q=${encodeURIComponent(term)}`);
        const d = r.ok ? await r.json() : EMPTY_RESULTS;
        if (myId === reqId.current) {
          setResults({ hosts: d.hosts ?? [], alerts: d.alerts ?? [], logs: d.logs ?? [],
            log_window_hours: d.log_window_hours, truncated: d.truncated });
        }
      } catch {
        if (myId === reqId.current) setResults(EMPTY_RESULTS);
      } finally {
        if (myId === reqId.current) setSearching(false);
      }
    }, 250);
    return () => clearTimeout(t);
  }, [term]);

  // Close the results panel on outside click or Escape.
  useEffect(() => {
    const onDown = (e: MouseEvent) => {
      if (searchBoxRef.current && !searchBoxRef.current.contains(e.target as Node)) setSearchOpen(false);
    };
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') setSearchOpen(false); };
    document.addEventListener('mousedown', onDown);
    window.addEventListener('keydown', onKey);
    return () => { document.removeEventListener('mousedown', onDown); window.removeEventListener('keydown', onKey); };
  }, []);

  // Land on Log Explorer with the term applied, and close/clear the panel.
  const goExplorer = useCallback((filter: Record<string, string>) => {
    setSearchOpen(false);
    searchRef.current?.blur();
    navigateTo('explorer', filter);
  }, []);

  // Close dropdown on outside click
  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(e.target as Node)) {
        setDropdownOpen(false);
      }
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, []);

  // "/" focuses the global search (unless already typing in a field)
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== '/') return;
      const el = document.activeElement as HTMLElement | null;
      const typing = el && (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA' || el.isContentEditable);
      if (typing) return;
      e.preventDefault();
      searchRef.current?.focus();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  // Poll collector health every 30s.
  // Cache-busting query param (perf-incident follow-up, 2026-07): a stale
  // response for this exact URL was already cached by network infra BEFORE
  // 2.22.1 added Cache-Control headers, and that entry can outlive the fix
  // indefinitely since our headers only stop NEW caching, not evict what's
  // already stored. A per-request unique URL can never hit that entry.
  const pollHealth = useCallback(async () => {
    try {
      const r = await fetch(`/api/health?_=${Date.now()}`);
      setCollectorOnline(r.ok);
    } catch { setCollectorOnline(false); }
  }, []);

  // Poll unacknowledged alert count every 30s (same cache-busting as above).
  const pollUnacked = useCallback(async () => {
    try {
      const r = await fetch(`/api/alerts/unacked-count?_=${Date.now()}`);
      if (!r.ok) return;
      const d = await r.json();
      const n = typeof d === 'number' ? d : (d.count ?? d.unacked ?? 0);
      setUnacked(Number(n) || 0);
    } catch {}
  }, []);

  useEffect(() => {
    pollHealth();
    pollUnacked();
    const id = setInterval(() => { pollHealth(); pollUnacked(); }, 30000);
    return () => clearInterval(id);
  }, [pollHealth, pollUnacked]);

  const initials = user?.name
    ? user.name.split(' ').map((n: string) => n[0]).join('').toUpperCase().slice(0, 2)
    : (user?.email?.[0] || '?').toUpperCase();

  return (
    <div style={{ height: 72, background: '#1a2744', display: 'flex', alignItems: 'center',
      padding: '0 20px', borderBottom: '1px solid #253352', flexShrink: 0, gap: 18,
      position: 'sticky', top: 0, zIndex: 200 }}>

      {/* Logo + divider + subtitle */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 16, flexShrink: 0 }}>
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 185 46" style={{ height: 44, width: 'auto' }} role="img" aria-label="LogVault">
          <rect x="2" y="6" width="3" height="34" rx="1.5" fill="#2563eb" />
          <rect x="9" y="7" width="26" height="3" rx="1.5" fill="#2563eb" />
          <rect x="9" y="15" width="18" height="3" rx="1.5" fill="#2563eb" opacity="0.7" />
          <rect x="9" y="23" width="22" height="3" rx="1.5" fill="#2563eb" opacity="0.85" />
          <rect x="9" y="31" width="14" height="3" rx="1.5" fill="#2563eb" opacity="0.6" />
          <text x="50" y="30" fontSize="26" fontWeight="700" letterSpacing="-0.3" fontFamily="'Rubik','Helvetica Neue',Helvetica,Arial,sans-serif">
            <tspan fill="#ffffff">Log</tspan>
            <tspan fill="#2563eb">Vault</tspan>
          </text>
        </svg>
        <div style={{ width: 1, height: 32, background: 'rgba(255,255,255,0.15)' }} />
        <div style={{ fontSize: 'var(--text-xs)', color: '#94a3b8', fontWeight: 600, letterSpacing: '1px' }}>
          SYSLOG ANALYZER
        </div>
      </div>

      {/* Center — global search */}
      <div style={{ flex: 1, display: 'flex', justifyContent: 'center', minWidth: 0 }}>
        <div ref={searchBoxRef} style={{ position: 'relative', width: '100%', maxWidth: 520 }}>
          <svg width="15" height="15" viewBox="0 0 16 16" fill="none"
            style={{ position: 'absolute', left: 12, top: '50%', transform: 'translateY(-50%)', color: '#64748b', pointerEvents: 'none' }}>
            <circle cx="7" cy="7" r="5" stroke="currentColor" strokeWidth="1.5" />
            <line x1="11" y1="11" x2="14.5" y2="14.5" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
          </svg>
          <input
            ref={searchRef}
            value={search}
            onChange={e => { setSearch(e.target.value); setSearchOpen(true); }}
            onFocus={() => setSearchOpen(true)}
            onKeyDown={e => {
              // Enter always works, even before results land — it hands the term
              // to Log Explorer, which runs the same query unbounded.
              if (e.key === 'Enter' && term.length >= 2) goExplorer({ q: term });
            }}
            placeholder="Search logs, hosts, alerts... (/)"
            style={{ width: '100%', height: 38, padding: '0 34px 0 34px', borderRadius: 'var(--radius-sm)',
              border: '1px solid #2d3a52', background: 'rgba(255,255,255,0.04)', color: '#f1f5f9',
              fontSize: 'var(--text-base)', outline: 'none' }}
          />
          {search && (
            <button onClick={() => { setSearch(''); searchRef.current?.focus(); }}
              aria-label="Clear search"
              style={{ position: 'absolute', right: 8, top: '50%', transform: 'translateY(-50%)',
                background: 'none', border: 'none', cursor: 'pointer', color: '#64748b', fontSize: 'var(--text-lg)',
                lineHeight: 1, padding: 4 }}>
              ×
            </button>
          )}

          {/* Results panel. Opaque --bg-card (never a translucent tint) so the
              page behind it can't bleed through — suite dark-mode rule. */}
          {searchOpen && term.length >= 2 && (
            <div style={{ position: 'absolute', top: 44, left: 0, right: 0, zIndex: 300,
              background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 'var(--radius)',
              boxShadow: '0 12px 32px rgba(0,0,0,0.28)', maxHeight: '70vh', overflowY: 'auto',
              paddingBottom: 4 }}>

              {searching && totalHits === 0 && (
                <div style={{ padding: '14px 12px', color: 'var(--text-muted)', fontSize: 'var(--text-base)' }}>
                  Searching…
                </div>
              )}

              {!searching && totalHits === 0 && (
                <div style={{ padding: '14px 12px', color: 'var(--text-muted)', fontSize: 'var(--text-base)' }}>
                  No matches for “{term}”.
                  <div style={{ marginTop: 4, fontSize: 'var(--text-sm)' }}>
                    Logs are previewed over the last {results.log_window_hours ?? 24}h — try Log Explorer for a wider range.
                  </div>
                </div>
              )}

              <SearchGroup label="Hosts" count={results.hosts.length}>
                {results.hosts.map(h => (
                  <SearchRow
                    key={h.ip_address}
                    dot={h.is_known_bad ? 'var(--red)' : 'var(--blue)'}
                    primary={h.ip_address}
                    secondary={h.hostname || h.vendor || ''}
                    meta={h.site_name || 'Unassigned'}
                    // Explorer's `host` filter matches the syslog sender AND the
                    // parsed src/dst IPs, so this finds the host's traffic too.
                    onClick={() => goExplorer({ host: h.ip_address })}
                  />
                ))}
              </SearchGroup>

              <SearchGroup label="Alerts" count={results.alerts.length}>
                {results.alerts.map(a => (
                  <SearchRow
                    key={a.id}
                    dot={a.acknowledged ? 'var(--text-muted)' : 'var(--red)'}
                    primary={a.rule_name || 'Alert'}
                    secondary={a.sample_message || ''}
                    meta={new Date(a.fired_at).toLocaleString()}
                    onClick={() => { setSearchOpen(false); navigateTo('alerts'); }}
                  />
                ))}
              </SearchGroup>

              <SearchGroup label={`Logs (last ${results.log_window_hours ?? 24}h)`} count={results.logs.length}>
                {results.logs.map(l => (
                  <SearchRow
                    key={l.id}
                    dot={(l.severity ?? 7) <= 3 ? 'var(--red)' : (l.severity ?? 7) <= 4 ? 'var(--yellow)' : 'var(--text-muted)'}
                    primary={l.source_host || l.vendor || 'log'}
                    secondary={l.message}
                    meta={new Date(l.received_at).toLocaleTimeString()}
                    onClick={() => goExplorer({ q: term })}
                  />
                ))}
              </SearchGroup>

              {/* Always offered: the panel only previews a bounded slice, so this
                  is the route to the complete, filterable result set. */}
              <button
                onClick={() => goExplorer({ q: term })}
                style={{ display: 'block', width: '100%', textAlign: 'left', padding: '9px 12px',
                  marginTop: 2, borderTop: '1px solid var(--border)', background: 'none', border: 'none',
                  borderTopStyle: 'solid', cursor: 'pointer', color: 'var(--primary)',
                  fontSize: 'var(--text-base)', fontWeight: 600 }}
                onMouseEnter={e => { (e.currentTarget as HTMLElement).style.background = 'var(--surface-subtle)'; }}
                onMouseLeave={e => { (e.currentTarget as HTMLElement).style.background = 'transparent'; }}
              >
                Search all logs for “{term}” in Log Explorer →
              </button>
            </div>
          )}
        </div>
      </div>

      {/* Right cluster */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 12, flexShrink: 0 }}>

        {/* Notifications bell */}
        <button
          aria-label="View alerts"
          onClick={() => window.dispatchEvent(new CustomEvent('nocvault:navigate', { detail: { tab: 'alerts' } }))}
          style={{ position: 'relative', display: 'flex', alignItems: 'center', justifyContent: 'center',
            width: 38, height: 38, borderRadius: 'var(--radius)', background: 'transparent', border: 'none',
            cursor: 'pointer', transition: 'background 0.15s, transform 0.1s' }}
          onMouseEnter={e => { (e.currentTarget as HTMLElement).style.background = 'rgba(255,255,255,0.1)'; }}
          onMouseLeave={e => { (e.currentTarget as HTMLElement).style.background = 'transparent'; }}
          onMouseDown={e => { (e.currentTarget as HTMLElement).style.transform = 'scale(0.95)'; }}
          onMouseUp={e => { (e.currentTarget as HTMLElement).style.transform = 'scale(1)'; }}>
          <svg width="18" height="18" viewBox="0 0 20 20" fill="none" style={{ color: '#94a3b8' }}>
            <path d="M10 2a5 5 0 0 0-5 5v3l-1.5 2.5h13L15 10V7a5 5 0 0 0-5-5z" stroke="currentColor" strokeWidth="1.4" strokeLinejoin="round" fill="none" />
            <path d="M8 15a2 2 0 0 0 4 0" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" />
          </svg>
          {unacked > 0 && (
            // pill: the old 8px was exactly half of this 16px-tall count badge (a capsule
            // when it grows to "99+"), so it belongs to --radius-pill, not --radius.
            <span style={{ position: 'absolute', top: 0, right: 0, minWidth: 16, height: 16, padding: '0 4px',
              borderRadius: 'var(--radius-pill)', background: 'var(--primary)', color: '#fff', fontSize: 'var(--text-xs)', fontWeight: 700,
              display: 'flex', alignItems: 'center', justifyContent: 'center', lineHeight: 1 }}>
              {unacked > 99 ? '99+' : unacked}
            </span>
          )}
        </button>

        {/* Dark mode toggle */}
        <button onClick={toggle} aria-label="Toggle dark mode"
          style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', width: 38, height: 38,
            borderRadius: 'var(--radius)', background: 'rgba(255,255,255,0.04)', border: '1px solid #2d3a52',
            cursor: 'pointer', color: '#94a3b8' }}>
          {theme === 'dark' ? <SunIcon /> : <MoonIcon />}
        </button>

        {/* Collector status pill */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 6,
          background: collectorOnline ? 'rgba(34,197,94,0.12)' : 'rgba(148,163,184,0.12)',
          border: `1px solid ${collectorOnline ? 'rgba(34,197,94,0.25)' : 'rgba(148,163,184,0.25)'}`,
          borderRadius: 'var(--radius-pill)', padding: '5px 12px' }}>
          {/* intentional: a true circle, not a corner radius — the status dot stays
              round in both corner styles. */}
          <div style={{ width: 7, height: 7, borderRadius: '50%',
            background: collectorOnline ? '#22c55e' : '#94a3b8',
            boxShadow: collectorOnline ? '0 0 6px #22c55e' : 'none',
            animation: collectorOnline ? 'pulse 1.6s ease-in-out infinite' : 'none' }} />
          <span style={{ fontSize: 'var(--text-xs)', color: collectorOnline ? '#22c55e' : '#94a3b8', fontWeight: 600, letterSpacing: '0.5px' }}>
            {collectorOnline ? 'COLLECTOR' : 'OFFLINE'}
          </span>
        </div>

        {/* User avatar + dropdown */}
        <div ref={dropdownRef} style={{ position: 'relative' }}>
          <button
            onClick={() => setDropdownOpen(o => !o)}
            style={{ display: 'flex', alignItems: 'center', gap: 8, background: 'none',
              border: 'none', cursor: 'pointer', padding: '4px 6px', borderRadius: 'var(--radius-sm)',
              transition: 'background 0.15s' }}
            onMouseEnter={e => { (e.currentTarget as HTMLElement).style.background = 'rgba(255,255,255,0.08)'; }}
            onMouseLeave={e => { if (!dropdownOpen) (e.currentTarget as HTMLElement).style.background = 'none'; }}>

            {/* intentional: a true circle (avatar), deliberately not squared. */}
            <div style={{ width: 34, height: 34, borderRadius: '50%', background: 'var(--primary)',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              fontSize: 'var(--text-sm)', fontWeight: 700, color: '#fff', flexShrink: 0 }}>
              {initials}
            </div>
            <div style={{ textAlign: 'left' }}>
              <div style={{ fontSize: 'var(--text-sm)', color: '#f1f5f9', fontWeight: 600, lineHeight: 1.2 }}>
                {user?.name || user?.email?.split('@')[0] || 'User'}
              </div>
              <span style={{ display: 'inline-block', fontSize: 'var(--text-xs)', fontWeight: 700,
                padding: '1px 7px', borderRadius: 'var(--radius-sm)', background: roleBadge.bg, color: roleBadge.fg,
                textTransform: 'uppercase', letterSpacing: '0.4px', marginTop: 2 }}>
                {roleBadge.label}
              </span>
            </div>
            <svg width="12" height="12" viewBox="0 0 12 12" fill="none"
              style={{ color: '#64748b', transform: dropdownOpen ? 'rotate(180deg)' : 'none', transition: 'transform 0.15s' }}>
              <path d="M2 4l4 4 4-4" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
          </button>

          {dropdownOpen && (
            <div style={{ position: 'absolute', top: 'calc(100% + 8px)', right: 0, zIndex: 1000,
              background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 'var(--radius)',
              boxShadow: '0 1px 3px rgba(0,0,0,0.06)', minWidth: 230, overflow: 'hidden',
              animation: 'fadeIn 0.15s ease' }}>

              <div style={{ padding: '14px 16px', borderBottom: '1px solid var(--border-light)' }}>
                <div style={{ fontSize: 'var(--text-base)', fontWeight: 600, color: 'var(--text-primary)' }}>
                  {user?.name || 'User'}
                </div>
                <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginTop: 2 }}>
                  {user?.email || ''}
                </div>
              </div>

              <div style={{ padding: '6px 0' }}>
                {/* NocVault Hub */}
                <a href={`${hubUrl}/launcher`}
                  style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '9px 16px',
                    textDecoration: 'none', color: 'var(--text-secondary)', fontSize: 'var(--text-base)', transition: 'background 0.1s' }}
                  onMouseEnter={e => { (e.currentTarget as HTMLElement).style.background = 'var(--bg-primary)'; }}
                  onMouseLeave={e => { (e.currentTarget as HTMLElement).style.background = 'transparent'; }}>
                  <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <path d="M3 9l9-7 9 7v11a2 2 0 01-2 2H5a2 2 0 01-2-2z" />
                    <polyline points="9 22 9 12 15 12 15 22" />
                  </svg>
                  NocVault Hub
                </a>

                {/* Dark mode toggle (mirror of header button) */}
                <button
                  onClick={() => { toggle(); setDropdownOpen(false); }}
                  style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '9px 16px',
                    width: '100%', background: 'none', border: 'none', cursor: 'pointer',
                    color: 'var(--text-secondary)', fontSize: 'var(--text-base)', textAlign: 'left', transition: 'background 0.1s' }}
                  onMouseEnter={e => { (e.currentTarget as HTMLElement).style.background = 'var(--bg-primary)'; }}
                  onMouseLeave={e => { (e.currentTarget as HTMLElement).style.background = 'transparent'; }}>
                  {theme === 'dark' ? <SunIcon /> : <MoonIcon />}
                  {theme === 'dark' ? 'Light Mode' : 'Dark Mode'}
                </button>

                {/* Corner style (rounded/square) — lives in this avatar dropdown
                    alongside the other per-user display prefs, NOT in Settings, on
                    purpose: the Settings tab is admin-only (role-gated in page.tsx),
                    but this is a per-browser display preference with no server state,
                    so every role must be able to reach it. It sits here rather than in
                    the navy top bar because a segmented control doesn't belong in the
                    bar, and the dropdown is where per-user preferences already live. */}
                <CornersToggle />

                <div style={{ height: 1, background: 'var(--border-light)', margin: '4px 0' }} />

                {/* Sign out */}
                <button
                  onClick={handleSignOut}
                  style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '9px 16px',
                    width: '100%', background: 'none', border: 'none', cursor: 'pointer',
                    color: '#dc2626', fontSize: 'var(--text-base)', textAlign: 'left', transition: 'background 0.1s' }}
                  onMouseEnter={e => { (e.currentTarget as HTMLElement).style.background = 'rgba(220,38,38,0.08)'; }}
                  onMouseLeave={e => { (e.currentTarget as HTMLElement).style.background = 'transparent'; }}>
                  <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <path d="M9 21H5a2 2 0 01-2-2V5a2 2 0 012-2h4" />
                    <polyline points="16 17 21 12 16 7" />
                    <line x1="21" y1="12" x2="9" y2="12" />
                  </svg>
                  Sign Out
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

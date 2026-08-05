'use client';

import { useEffect, useState } from 'react';

// ── Shared GeoIP / threat-intel helpers + the Known-Bad Sources widget ────────
// Owned by the frontend GeoIP/threat-intel feature. countryFlag() and the
// shared types are imported by DashboardWidgets.tsx so the talkers/blocked rows
// and this widget stay in sync.

// Map a 2-letter ISO 3166-1 alpha-2 code to its regional-indicator flag emoji.
// Guards against null / wrong-length / non-letter input (returns '' so callers
// can fall back to a globe or just omit the flag). Uppercased before mapping.
export function countryFlag(code?: string | null): string {
  if (!code || typeof code !== 'string') return '';
  const cc = code.trim().toUpperCase();
  if (!/^[A-Z]{2}$/.test(cc)) return '';
  const A = 0x1f1e6; // regional indicator 'A'
  const base = 'A'.charCodeAt(0);
  return String.fromCodePoint(A + (cc.charCodeAt(0) - base), A + (cc.charCodeAt(1) - base));
}

// Fallback glyph when no usable country code is present.
export const GLOBE = '🌐';

// Shape returned by the enriched stats endpoints (talkers / blocked rows).
export interface EnrichedFields {
  country_code?: string | null;
  country_name?: string | null;
  asn_org?:      string | null;
  abuse_score?:  number | null;
  is_known_bad?: boolean;
  is_external?:  boolean;
  threat_tags?:  string[] | null;
}

// Shape returned by GET /api/threats/known-bad.
export interface KnownBadRow extends EnrichedFields {
  ip_address:    string;
  hostname?:     string | null;
  last_enriched?: string | null;
  last_seen?:    string | null;
  total_hits?:   number | string | null;
}

const CARD = {
  background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 10,
  padding: '16px 20px', boxShadow: 'var(--shadow-sm)',
};

// A compact red "known-bad" badge with the abuse score. Used in both the
// dashboard talkers/blocked rows and the known-bad widget.
export function KnownBadBadge({ score, compact }: { score?: number | null; compact?: boolean }) {
  const hasScore = typeof score === 'number' && !isNaN(score);
  return (
    <span title={hasScore ? `AbuseIPDB confidence ${score}%` : 'Flagged as known-bad'}
      style={{ display: 'inline-flex', alignItems: 'center', gap: 4, flexShrink: 0,
        background: 'var(--tint-danger)', color: 'var(--tint-danger-fg)',
        borderRadius: 4, padding: compact ? '0 4px' : '1px 6px',
        fontSize: 'var(--text-xs)', fontWeight: 700, lineHeight: 1.5, whiteSpace: 'nowrap' }}>
      ⚠ {hasScore ? `${score}` : 'BAD'}
    </span>
  );
}

// Inline country flag + name + ASN org, for an external source-IP row.
// Renders nothing when there's no geo/asn data so internal IPs stay clean.
export function GeoInline({ row }: { row: EnrichedFields }) {
  const flag = countryFlag(row.country_code) || (row.is_external ? GLOBE : '');
  const parts: string[] = [];
  if (row.country_name) parts.push(row.country_name);
  if (row.asn_org) parts.push(row.asn_org);
  if (!flag && parts.length === 0) return null;
  return (
    <span title={parts.join(' · ')}
      style={{ display: 'inline-flex', alignItems: 'center', gap: 4, minWidth: 0,
        fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
      {flag && <span style={{ flexShrink: 0 }}>{flag}</span>}
      {parts.length > 0 && (
        <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: 130 }}>
          {parts.join(' · ')}
        </span>
      )}
    </span>
  );
}

function fmtHits(v: number | string | null | undefined): string {
  const n = typeof v === 'string' ? parseInt(v) : v;
  return typeof n === 'number' && !isNaN(n) ? n.toLocaleString() : '0';
}

function fmtRelative(iso?: string | null): string {
  if (!iso) return '—';
  const t = new Date(iso).getTime();
  if (isNaN(t)) return '—';
  const diff = Date.now() - t;
  if (diff < 0) return 'just now';
  const mins = Math.floor(diff / 60000);
  if (mins < 1)  return 'just now';
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24)  return `${hrs}h ago`;
  const days = Math.floor(hrs / 24);
  return `${days}d ago`;
}

// ── Known-Bad Sources widget ──────────────────────────────────────────────────
// Fetches GET /api/threats/known-bad and lists each flagged external source IP
// with its country, ASN, abuse score, threat tags, hits today and last-seen.
// Module-level component (never defined inside another).
export function KnownBadSources({ onNavigate }: { onNavigate?: (ip: string) => void }) {
  const [rows, setRows] = useState<KnownBadRow[]>([]);
  const [keyConfigured, setKeyConfigured] = useState(true);
  const [loaded, setLoaded] = useState(false);

  useEffect(() => {
    let active = true;
    const load = () => {
      fetch('/api/threats/known-bad')
        .then(r => r.json())
        // The endpoint returns { data: [...], keyConfigured }. The previous code
        // checked Array.isArray(d) on the envelope, so rows were ALWAYS empty even
        // when threats existed — read the array off .data.
        .then((d: { data?: KnownBadRow[]; keyConfigured?: boolean }) => {
          if (!active) return;
          setRows(Array.isArray(d?.data) ? d.data : []);
          setKeyConfigured(d?.keyConfigured !== false);
          setLoaded(true);
        })
        .catch(() => { if (active) setLoaded(true); });
    };
    load();
    const refresh = () => load();
    window.addEventListener('nocvault:refresh', refresh);
    return () => { active = false; window.removeEventListener('nocvault:refresh', refresh); };
  }, []);

  return (
    <div style={{ ...CARD, height: '100%', boxSizing: 'border-box', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexShrink: 0 }}>
        <div style={{ fontSize: 'var(--text-base)', fontWeight: 600, color: 'var(--text-primary)' }}>
          Known-Bad Sources
        </div>
        {loaded && rows.length > 0 && (
          <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4,
            background: 'var(--tint-danger)', color: 'var(--tint-danger-fg)', borderRadius: 12,
            padding: '1px 9px', fontSize: 'var(--text-xs)', fontWeight: 700 }}>
            {rows.length}
          </span>
        )}
      </div>
      <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginBottom: 10, flexShrink: 0 }}>
        External IPs flagged by threat intelligence
      </div>

      {!loaded ? (
        <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text-muted)', fontSize: 'var(--text-sm)' }}>
          Loading...
        </div>
      ) : rows.length === 0 && !keyConfigured ? (
        // No AbuseIPDB key configured — scoring is inactive. Guide the operator
        // rather than implying the network is clean.
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center',
          gap: 4, color: 'var(--text-muted)', fontSize: 'var(--text-sm)', textAlign: 'center', padding: '0 12px' }}>
          <span style={{ fontSize: 'var(--text-md)' }}>🛈</span>
          <span style={{ fontWeight: 600, color: 'var(--text-secondary)' }}>Threat scoring not configured</span>
          <span style={{ fontSize: 'var(--text-xs)' }}>Add an AbuseIPDB API key in Settings to score external IPs.</span>
        </div>
      ) : rows.length === 0 ? (
        <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center',
          color: 'var(--tint-success-fg)', fontSize: 'var(--text-sm)', fontWeight: 500, textAlign: 'center', padding: '0 12px' }}>
          ✓ No known-bad external sources detected.
        </div>
      ) : (
        <div style={{ flex: 1, minHeight: 0, overflowY: 'auto', paddingRight: 6, display: 'flex', flexDirection: 'column', gap: 8 }}>
          {rows.map((row, i) => {
            const flag = countryFlag(row.country_code) || GLOBE;
            const tags = Array.isArray(row.threat_tags) ? row.threat_tags : [];
            return (
              <div key={row.ip_address || i}
                onClick={() => onNavigate?.(row.ip_address)}
                title={`${row.ip_address}${row.hostname ? ` · ${row.hostname}` : ''}`}
                style={{ padding: '8px 10px', borderRadius: 8, background: 'var(--surface-subtle)',
                  border: '1px solid var(--border-light)', cursor: onNavigate ? 'pointer' : 'default' }}>
                {/* Row 1: IP + flag/country + abuse badge */}
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6, minWidth: 0 }}>
                    <span style={{ flexShrink: 0 }}>{flag}</span>
                    <span style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)', fontWeight: 600,
                      color: 'var(--text-primary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: 130 }}>
                      {row.ip_address}
                    </span>
                  </div>
                  <KnownBadBadge score={row.abuse_score} />
                </div>

                {/* Row 2: country + ASN org */}
                {(row.country_name || row.asn_org) && (
                  <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginTop: 3,
                    overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {[row.country_name, row.asn_org].filter(Boolean).join(' · ')}
                  </div>
                )}

                {/* Row 3: threat tags */}
                {tags.length > 0 && (
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4, marginTop: 5 }}>
                    {tags.slice(0, 4).map(tag => (
                      <span key={tag} style={{ fontSize: 'var(--text-xs)', fontWeight: 600,
                        background: 'var(--tint-warn)', color: 'var(--tint-warn-fg)',
                        borderRadius: 4, padding: '0 5px', lineHeight: 1.6 }}>
                        {tag}
                      </span>
                    ))}
                  </div>
                )}

                {/* Row 4: hits + last seen */}
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8, marginTop: 5 }}>
                  <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-secondary)' }}>
                    {fmtHits(row.total_hits)} hits today
                  </span>
                  <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
                    {fmtRelative(row.last_seen)}
                  </span>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

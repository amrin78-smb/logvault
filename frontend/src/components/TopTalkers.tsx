'use client';
import { useEffect, useState } from 'react';
import { countryFlag, KnownBadBadge } from './ThreatIntel';

const VENDOR_COLORS: Record<string, string> = {
  cisco: '#2563eb', paloalto: '#ea580c', fortinet: '#dc2626',
  aruba: '#7c3aed', sangfor: '#0891b2', generic: '#9ca3af', unknown: '#9ca3af',
  forcepoint: '#003087', checkpoint: '#E31937', juniper: '#84BD00',
  windows: '#0078D4', sonicwall: '#FF6600',
};

export default function TopTalkers({ hours, onHostClick, compact }: {
  hours: number; onHostClick?: (host: string) => void; compact?: boolean;
}) {
  const [data, setData] = useState<any[]>([]);
  useEffect(() => {
    fetch(`/api/stats/top-talkers?hours=${hours}&limit=5`)
      .then(r => r.json()).then(d => setData(d.data || [])).catch(() => {});
  }, [hours]);
  const max = data[0] ? parseInt(data[0].log_count) : 1;
  return (
    <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 8,
      padding: '16px 20px', height: '100%', boxSizing: 'border-box', display: 'flex', flexDirection: 'column', overflow: 'hidden', boxShadow: '0 1px 3px rgba(0,0,0,0.06)' }}>
      <div style={{ fontSize: 'var(--text-sm)', fontWeight: 600, color: 'var(--text-primary)', marginBottom: 1, flexShrink: 0 }}>Top Talkers</div>
      <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginBottom: 8, flexShrink: 0 }}>Most active — {hours}h</div>
      <div style={{ flex: 1, minHeight: 0, overflowY: 'auto', paddingRight: 8, display: 'flex', flexDirection: 'column', gap: 7 }}>
        {data.slice(0, 5).map((row, i) => {
          const pct = Math.round((parseInt(row.log_count) / max) * 100);
          const color = VENDOR_COLORS[row.vendor] || '#9ca3af';
          const flag = countryFlag(row.country_code);
          const geoText = [row.country_name, row.asn_org].filter(Boolean).join(' · ');
          const knownBad = !!row.is_known_bad;
          return (
            <div key={i} onClick={() => onHostClick && onHostClick(row.host)}
              style={{ cursor: onHostClick ? 'pointer' : 'default',
                borderLeft: `3px solid ${knownBad ? 'var(--primary)' : 'transparent'}`,
                paddingLeft: 7 }}>
              {/* Row 1: vendor dot + flag + host, count on the right */}
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 3, gap: 6 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 5, minWidth: 0 }}>
                  <div style={{ width: 6, height: 6, borderRadius: '50%', background: color, flexShrink: 0 }} />
                  {flag && <span style={{ flexShrink: 0, fontSize: 'var(--text-xs)' }}>{flag}</span>}
                  <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-primary)', fontFamily: 'var(--font-mono)', fontWeight: 500, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{row.host}</span>
                </div>
                <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-secondary)', fontWeight: 600, flexShrink: 0 }}>{parseInt(row.log_count).toLocaleString()}</span>
              </div>
              <div style={{ height: 4, background: 'var(--border-light)', borderRadius: 2, overflow: 'hidden' }}>
                <div style={{ height: '100%', width: `${pct}%`, background: color, borderRadius: 2 }} />
              </div>
              {/* Row 2: country · ASN org, with known-bad badge */}
              {(geoText || knownBad) && (
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 6, marginTop: 3 }}>
                  <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', minWidth: 0 }}>{geoText}</span>
                  {knownBad && <KnownBadBadge score={row.abuse_score} compact />}
                </div>
              )}
            </div>
          );
        })}
        {data.length === 0 && <div style={{ textAlign: 'center', color: 'var(--text-muted)', fontSize: 'var(--text-sm)' }}>No data</div>}
      </div>
    </div>
  );
}

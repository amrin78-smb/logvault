'use client';
import { useEffect, useState } from 'react';
import { countryFlag, KnownBadBadge } from './ThreatIntel';

// Top Destinations (outbound) — mirrors TopTalkers but on the DESTINATION IP
// (the external side of firewall logs). Surfaces outbound callouts: high-volume
// external destinations are normal egress (DNS, CDNs); a flagged/known-bad one is
// a possible C2/exfil channel. Data from GET /api/stats/top-destinations.
export default function TopDestinations({ hours, onHostClick }: {
  hours: number; onHostClick?: (host: string) => void;
}) {
  const [data, setData] = useState<any[]>([]);
  useEffect(() => {
    fetch(`/api/stats/top-destinations?hours=${hours}&limit=5`)
      .then(r => r.json()).then(d => setData(d.data || [])).catch(() => {});
  }, [hours]);
  const max = data[0] ? parseInt(data[0].log_count) : 1;
  return (
    <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 8,
      padding: '16px 20px', height: '100%', boxSizing: 'border-box', display: 'flex', flexDirection: 'column', overflow: 'hidden', boxShadow: '0 1px 3px rgba(0,0,0,0.06)' }}>
      <div style={{ fontSize: 'var(--text-sm)', fontWeight: 600, color: 'var(--text-primary)', marginBottom: 1, flexShrink: 0 }}>Top Destinations</div>
      <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginBottom: 8, flexShrink: 0 }}>Outbound callouts — {hours}h</div>
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: 7, justifyContent: 'space-evenly' }}>
        {data.slice(0, 5).map((row, i) => {
          const pct = Math.round((parseInt(row.log_count) / max) * 100);
          const flag = countryFlag(row.country_code);
          const geoText = [row.country_name, row.asn_org].filter(Boolean).join(' · ');
          const knownBad = !!row.is_known_bad;
          // External destinations are the egress signal; tint the bar by risk.
          const external = !!row.is_external;
          const barColor = knownBad ? 'var(--primary)' : external ? '#0891b2' : '#9ca3af';
          return (
            <div key={i} onClick={() => onHostClick && onHostClick(row.host)}
              style={{ cursor: onHostClick ? 'pointer' : 'default',
                borderLeft: `3px solid ${knownBad ? 'var(--primary)' : 'transparent'}`,
                paddingLeft: 7 }}>
              {/* Row 1: flag + host, count on the right */}
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 3, gap: 6 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 5, minWidth: 0 }}>
                  {flag && <span style={{ flexShrink: 0, fontSize: 'var(--text-xs)' }}>{flag}</span>}
                  <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-primary)', fontFamily: 'var(--font-mono)', fontWeight: 500, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{row.host}</span>
                </div>
                <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-secondary)', fontWeight: 600, flexShrink: 0 }}>{parseInt(row.log_count).toLocaleString()}</span>
              </div>
              <div style={{ height: 4, background: 'var(--border-light)', borderRadius: 2, overflow: 'hidden' }}>
                <div style={{ height: '100%', width: `${pct}%`, background: barColor, borderRadius: 2 }} />
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

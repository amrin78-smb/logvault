'use client';

import { useState, useEffect, useCallback, useMemo } from 'react';
import { PageHeader, EmptyState, Skeleton, Spinner } from './ui';
import { countryFlag, GLOBE } from './ThreatIntel';
import { Trend } from './Trend';
import type { ExplorerFilter } from '@/app/page';

// ════════════════════════════════════════════════════════════════════════════
// ThreatMap — Phase 3 "geo/attack map".
//
// DATA CONSTRAINT: there is NO lat/lon in the database — geo is country-level
// only. So this is a WORLD ATTACK MAP drawn with an inline SVG equirectangular
// projection: each country in the failed-auth/attack feed is plotted as a
// bubble at a BUNDLED centroid (below), sized by attack count. Countries with
// no bundled centroid still appear in the ranked list, just without a bubble.
//
// Source endpoint (already attack/failed-auth scoped):
//   GET /api/stats/geo?hours=<h>
//     → { hours, data: [{ country, country_code, count, prev_count, distinct_sources }] }
//   country_code is ISO-3166 alpha-2 uppercase (may be null when the country
//   name came from the event's srccountry with no known_hosts geo match).
//
// All helpers/subcomponents are at MODULE level (no component-in-component).
// Styling: inline styles + globals.css design tokens only (dark-mode safe).
// ════════════════════════════════════════════════════════════════════════════

interface GeoRow {
  country: string | null;
  country_code: string | null;
  count: number | string;
  prev_count: number | string;
  distinct_sources: number | string;
}

// ── Bundled centroid lookup (visual only — a few degrees off is fine) ─────────
// Keyed by ISO-3166 alpha-2 (uppercase). ~140 countries, weighted toward the
// likely-attacker set. { lat, lon, name }. Do NOT fetch these from anywhere.
const COUNTRY_CENTROIDS: Record<string, { lat: number; lon: number; name: string }> = {
  // ── North & Central America ──
  US: { lat: 39.5, lon: -98.4, name: 'United States' },
  CA: { lat: 56.1, lon: -106.3, name: 'Canada' },
  MX: { lat: 23.6, lon: -102.6, name: 'Mexico' },
  GT: { lat: 15.8, lon: -90.2, name: 'Guatemala' },
  CU: { lat: 21.5, lon: -79.5, name: 'Cuba' },
  DO: { lat: 18.7, lon: -70.2, name: 'Dominican Republic' },
  CR: { lat: 9.7, lon: -83.8, name: 'Costa Rica' },
  PA: { lat: 8.5, lon: -80.8, name: 'Panama' },
  HN: { lat: 15.2, lon: -86.2, name: 'Honduras' },
  NI: { lat: 12.9, lon: -85.2, name: 'Nicaragua' },
  SV: { lat: 13.8, lon: -88.9, name: 'El Salvador' },
  JM: { lat: 18.1, lon: -77.3, name: 'Jamaica' },
  // ── South America ──
  BR: { lat: -10.3, lon: -53.2, name: 'Brazil' },
  AR: { lat: -38.4, lon: -63.6, name: 'Argentina' },
  CL: { lat: -35.7, lon: -71.5, name: 'Chile' },
  CO: { lat: 4.6, lon: -74.3, name: 'Colombia' },
  PE: { lat: -9.2, lon: -75.0, name: 'Peru' },
  VE: { lat: 6.4, lon: -66.6, name: 'Venezuela' },
  EC: { lat: -1.8, lon: -78.2, name: 'Ecuador' },
  BO: { lat: -16.3, lon: -63.6, name: 'Bolivia' },
  PY: { lat: -23.4, lon: -58.4, name: 'Paraguay' },
  UY: { lat: -32.5, lon: -55.8, name: 'Uruguay' },
  // ── Western & Central Europe ──
  GB: { lat: 54.0, lon: -2.5, name: 'United Kingdom' },
  IE: { lat: 53.4, lon: -8.2, name: 'Ireland' },
  FR: { lat: 46.6, lon: 2.4, name: 'France' },
  DE: { lat: 51.2, lon: 10.4, name: 'Germany' },
  NL: { lat: 52.2, lon: 5.3, name: 'Netherlands' },
  BE: { lat: 50.6, lon: 4.6, name: 'Belgium' },
  LU: { lat: 49.8, lon: 6.1, name: 'Luxembourg' },
  CH: { lat: 46.8, lon: 8.2, name: 'Switzerland' },
  AT: { lat: 47.6, lon: 14.1, name: 'Austria' },
  ES: { lat: 40.2, lon: -3.7, name: 'Spain' },
  PT: { lat: 39.6, lon: -8.0, name: 'Portugal' },
  IT: { lat: 42.8, lon: 12.6, name: 'Italy' },
  MT: { lat: 35.9, lon: 14.4, name: 'Malta' },
  // ── Northern Europe ──
  DK: { lat: 56.0, lon: 9.5, name: 'Denmark' },
  SE: { lat: 62.0, lon: 15.6, name: 'Sweden' },
  NO: { lat: 64.6, lon: 12.0, name: 'Norway' },
  FI: { lat: 64.5, lon: 26.0, name: 'Finland' },
  IS: { lat: 64.9, lon: -19.0, name: 'Iceland' },
  EE: { lat: 58.6, lon: 25.0, name: 'Estonia' },
  LV: { lat: 56.9, lon: 24.9, name: 'Latvia' },
  LT: { lat: 55.2, lon: 23.9, name: 'Lithuania' },
  // ── Eastern & Southern Europe ──
  PL: { lat: 51.9, lon: 19.1, name: 'Poland' },
  CZ: { lat: 49.8, lon: 15.5, name: 'Czechia' },
  SK: { lat: 48.7, lon: 19.7, name: 'Slovakia' },
  HU: { lat: 47.2, lon: 19.5, name: 'Hungary' },
  RO: { lat: 45.9, lon: 25.0, name: 'Romania' },
  BG: { lat: 42.7, lon: 25.5, name: 'Bulgaria' },
  GR: { lat: 39.1, lon: 21.8, name: 'Greece' },
  HR: { lat: 45.1, lon: 15.2, name: 'Croatia' },
  RS: { lat: 44.0, lon: 21.0, name: 'Serbia' },
  SI: { lat: 46.1, lon: 14.8, name: 'Slovenia' },
  BA: { lat: 43.9, lon: 17.7, name: 'Bosnia & Herzegovina' },
  MK: { lat: 41.6, lon: 21.7, name: 'North Macedonia' },
  AL: { lat: 41.2, lon: 20.0, name: 'Albania' },
  ME: { lat: 42.7, lon: 19.4, name: 'Montenegro' },
  UA: { lat: 48.4, lon: 31.2, name: 'Ukraine' },
  BY: { lat: 53.7, lon: 27.9, name: 'Belarus' },
  MD: { lat: 47.4, lon: 28.4, name: 'Moldova' },
  CY: { lat: 35.1, lon: 33.4, name: 'Cyprus' },
  RU: { lat: 61.5, lon: 96.0, name: 'Russia' },
  // ── Middle East ──
  TR: { lat: 39.0, lon: 35.2, name: 'Turkey' },
  SA: { lat: 23.9, lon: 45.1, name: 'Saudi Arabia' },
  AE: { lat: 23.4, lon: 53.8, name: 'United Arab Emirates' },
  QA: { lat: 25.3, lon: 51.2, name: 'Qatar' },
  KW: { lat: 29.3, lon: 47.5, name: 'Kuwait' },
  BH: { lat: 26.0, lon: 50.5, name: 'Bahrain' },
  OM: { lat: 21.5, lon: 55.9, name: 'Oman' },
  YE: { lat: 15.6, lon: 48.0, name: 'Yemen' },
  IQ: { lat: 33.2, lon: 43.7, name: 'Iraq' },
  IR: { lat: 32.4, lon: 53.7, name: 'Iran' },
  IL: { lat: 31.5, lon: 34.9, name: 'Israel' },
  JO: { lat: 30.6, lon: 36.2, name: 'Jordan' },
  LB: { lat: 33.9, lon: 35.9, name: 'Lebanon' },
  SY: { lat: 34.8, lon: 38.0, name: 'Syria' },
  PS: { lat: 31.9, lon: 35.2, name: 'Palestine' },
  // ── North Africa ──
  EG: { lat: 26.8, lon: 30.8, name: 'Egypt' },
  LY: { lat: 26.3, lon: 17.2, name: 'Libya' },
  TN: { lat: 33.9, lon: 9.6, name: 'Tunisia' },
  DZ: { lat: 28.0, lon: 1.7, name: 'Algeria' },
  MA: { lat: 31.8, lon: -7.1, name: 'Morocco' },
  SD: { lat: 12.9, lon: 30.2, name: 'Sudan' },
  // ── Sub-Saharan Africa ──
  ZA: { lat: -30.6, lon: 22.9, name: 'South Africa' },
  NG: { lat: 9.1, lon: 8.7, name: 'Nigeria' },
  KE: { lat: 0.0, lon: 37.9, name: 'Kenya' },
  ET: { lat: 9.1, lon: 40.5, name: 'Ethiopia' },
  GH: { lat: 7.9, lon: -1.0, name: 'Ghana' },
  TZ: { lat: -6.4, lon: 34.9, name: 'Tanzania' },
  UG: { lat: 1.4, lon: 32.3, name: 'Uganda' },
  CI: { lat: 7.5, lon: -5.5, name: "Côte d'Ivoire" },
  CM: { lat: 7.4, lon: 12.4, name: 'Cameroon' },
  SN: { lat: 14.5, lon: -14.5, name: 'Senegal' },
  ZW: { lat: -19.0, lon: 29.9, name: 'Zimbabwe' },
  ZM: { lat: -13.1, lon: 27.8, name: 'Zambia' },
  AO: { lat: -11.2, lon: 17.9, name: 'Angola' },
  MZ: { lat: -18.7, lon: 35.5, name: 'Mozambique' },
  MG: { lat: -18.8, lon: 46.9, name: 'Madagascar' },
  RW: { lat: -1.9, lon: 29.9, name: 'Rwanda' },
  ML: { lat: 17.6, lon: -4.0, name: 'Mali' },
  BF: { lat: 12.2, lon: -1.6, name: 'Burkina Faso' },
  NE: { lat: 17.6, lon: 8.1, name: 'Niger' },
  TD: { lat: 15.5, lon: 18.7, name: 'Chad' },
  SO: { lat: 5.2, lon: 46.2, name: 'Somalia' },
  CD: { lat: -4.0, lon: 21.8, name: 'DR Congo' },
  // ── Central & South Asia ──
  KZ: { lat: 48.0, lon: 66.9, name: 'Kazakhstan' },
  UZ: { lat: 41.4, lon: 64.6, name: 'Uzbekistan' },
  TM: { lat: 38.9, lon: 59.6, name: 'Turkmenistan' },
  KG: { lat: 41.2, lon: 74.8, name: 'Kyrgyzstan' },
  TJ: { lat: 38.9, lon: 71.3, name: 'Tajikistan' },
  AZ: { lat: 40.1, lon: 47.6, name: 'Azerbaijan' },
  GE: { lat: 42.3, lon: 43.4, name: 'Georgia' },
  AM: { lat: 40.1, lon: 45.0, name: 'Armenia' },
  IN: { lat: 22.4, lon: 78.7, name: 'India' },
  PK: { lat: 30.4, lon: 69.3, name: 'Pakistan' },
  BD: { lat: 23.7, lon: 90.4, name: 'Bangladesh' },
  LK: { lat: 7.9, lon: 80.8, name: 'Sri Lanka' },
  NP: { lat: 28.4, lon: 84.1, name: 'Nepal' },
  AF: { lat: 33.9, lon: 67.7, name: 'Afghanistan' },
  // ── East Asia ──
  CN: { lat: 35.9, lon: 104.2, name: 'China' },
  HK: { lat: 22.3, lon: 114.2, name: 'Hong Kong' },
  TW: { lat: 23.7, lon: 121.0, name: 'Taiwan' },
  JP: { lat: 36.2, lon: 138.3, name: 'Japan' },
  KR: { lat: 36.5, lon: 127.9, name: 'South Korea' },
  KP: { lat: 40.3, lon: 127.5, name: 'North Korea' },
  MN: { lat: 46.9, lon: 103.8, name: 'Mongolia' },
  // ── Southeast Asia ──
  VN: { lat: 14.1, lon: 108.3, name: 'Vietnam' },
  TH: { lat: 15.9, lon: 101.0, name: 'Thailand' },
  ID: { lat: -2.5, lon: 118.0, name: 'Indonesia' },
  MY: { lat: 4.2, lon: 108.0, name: 'Malaysia' },
  SG: { lat: 1.35, lon: 103.8, name: 'Singapore' },
  PH: { lat: 12.9, lon: 122.0, name: 'Philippines' },
  KH: { lat: 12.6, lon: 104.9, name: 'Cambodia' },
  LA: { lat: 19.9, lon: 102.5, name: 'Laos' },
  MM: { lat: 21.9, lon: 95.9, name: 'Myanmar' },
  BN: { lat: 4.5, lon: 114.7, name: 'Brunei' },
  TL: { lat: -8.9, lon: 125.7, name: 'Timor-Leste' },
  // ── Oceania ──
  AU: { lat: -25.3, lon: 133.8, name: 'Australia' },
  NZ: { lat: -41.8, lon: 173.0, name: 'New Zealand' },
  PG: { lat: -6.3, lon: 143.9, name: 'Papua New Guinea' },
  FJ: { lat: -17.7, lon: 178.0, name: 'Fiji' },
};

// ── SVG canvas constants (equirectangular, 2:1) ───────────────────────────────
const MAP_W = 720;
const MAP_H = 360;
const MIN_R = 3;   // smallest bubble radius (SVG units)
const MAX_R = 18;  // largest bubble radius
const TOP_N = 3;   // number of top attackers that get the pulse/glow

// Equirectangular projection helpers.
function projX(lon: number): number { return ((lon + 180) / 360) * MAP_W; }
function projY(lat: number): number { return ((90 - lat) / 180) * MAP_H; }

function num(v: number | string | null | undefined): number {
  const n = typeof v === 'string' ? parseInt(v, 10) : v;
  return typeof n === 'number' && !isNaN(n) ? n : 0;
}

// ── Graticule backdrop (meridians + parallels every 30°) — module level ───────
function Graticule() {
  const meridians: number[] = [];
  for (let lon = -180; lon <= 180; lon += 30) meridians.push(lon);
  const parallels: number[] = [];
  for (let lat = -90; lat <= 90; lat += 30) parallels.push(lat);
  return (
    <g stroke="var(--border)" strokeWidth={0.5} opacity={0.5}>
      {meridians.map(lon => (
        <line key={`m${lon}`} x1={projX(lon)} y1={0} x2={projX(lon)} y2={MAP_H} />
      ))}
      {parallels.map(lat => (
        <line key={`p${lat}`} x1={0} y1={projY(lat)} x2={MAP_W} y2={projY(lat)} />
      ))}
      {/* Equator + prime meridian slightly stronger for orientation */}
      <line x1={0} y1={projY(0)} x2={MAP_W} y2={projY(0)} strokeWidth={0.8} opacity={0.9} />
    </g>
  );
}

// ── Floating tooltip content (module level) ───────────────────────────────────
function BubbleTooltip({ row, name }: { row: GeoRow; name: string }) {
  const flag = countryFlag(row.country_code) || GLOBE;
  return (
    <div style={{
      background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 8,
      boxShadow: 'var(--shadow-sm)', padding: '8px 11px', minWidth: 150, pointerEvents: 'none',
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 'var(--text-base)',
        fontWeight: 700, color: 'var(--text-primary)', marginBottom: 4 }}>
        <span>{flag}</span>
        <span>{name}</span>
      </div>
      <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-secondary)', display: 'flex',
        justifyContent: 'space-between', gap: 14 }}>
        <span>Attacks</span>
        <span style={{ fontWeight: 700, color: 'var(--tint-danger-fg)' }}>{num(row.count).toLocaleString()}</span>
      </div>
      <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-secondary)', display: 'flex',
        justifyContent: 'space-between', gap: 14 }}>
        <span>Sources</span>
        <span style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{num(row.distinct_sources).toLocaleString()}</span>
      </div>
    </div>
  );
}

// ── Ranked country list row (module level) ────────────────────────────────────
function RankRow({ row, rank, onClick }: { row: GeoRow; rank: number; onClick: () => void }) {
  const flag = countryFlag(row.country_code) || GLOBE;
  const name = row.country || (row.country_code ? row.country_code : 'Unknown');
  const count = num(row.count);
  const prev = num(row.prev_count);
  const sources = num(row.distinct_sources);
  return (
    <div
      onClick={onClick}
      title={`Open failed-auth activity from ${name} in Log Explorer`}
      style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '8px 10px',
        borderRadius: 8, background: 'var(--surface-subtle)', border: '1px solid var(--border-light)',
        cursor: 'pointer' }}
      onMouseEnter={e => { (e.currentTarget as HTMLElement).style.background = 'var(--bg-hover, var(--tint-danger))'; }}
      onMouseLeave={e => { (e.currentTarget as HTMLElement).style.background = 'var(--surface-subtle)'; }}
    >
      <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', fontWeight: 700,
        width: 18, textAlign: 'right', flexShrink: 0 }}>{rank}</span>
      <span style={{ flexShrink: 0, fontSize: 'var(--text-md)' }}>{flag}</span>
      <div style={{ minWidth: 0, flex: 1 }}>
        <div style={{ fontSize: 'var(--text-base)', fontWeight: 600, color: 'var(--text-primary)',
          overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{name}</div>
        <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
          {sources.toLocaleString()} source{sources === 1 ? '' : 's'}
        </div>
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: 2, flexShrink: 0 }}>
        <span style={{ fontSize: 'var(--text-base)', fontWeight: 700, color: 'var(--tint-danger-fg)' }}>
          {count.toLocaleString()}
        </span>
        <Trend value={count} prev={prev} />
      </div>
    </div>
  );
}

// ── Local time-range selector (module level) ──────────────────────────────────
const RANGE_PRESETS = [
  { label: '6h', value: 6 },
  { label: '24h', value: 24 },
  { label: '48h', value: 48 },
  { label: '7d', value: 168 },
  { label: '30d', value: 720 },
];
function RangeSelector({ value, onChange }: { value: number; onChange: (h: number) => void }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 3,
      background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 6, padding: '4px 6px' }}>
      <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginRight: 2 }}>Range</span>
      {RANGE_PRESETS.map(p => {
        const active = value === p.value;
        return (
          <button key={p.value} onClick={() => onChange(p.value)}
            style={{ padding: '3px 9px', borderRadius: 4, border: 'none', fontSize: 'var(--text-xs)',
              cursor: 'pointer', fontWeight: active ? 700 : 400,
              background: active ? 'var(--primary)' : 'transparent',
              color: active ? '#fff' : 'var(--text-muted)' }}>
            {p.label}
          </button>
        );
      })}
    </div>
  );
}

// ── Main component ────────────────────────────────────────────────────────────
export default function ThreatMap({ hours, openExplorer }: {
  hours: number;
  openExplorer: (filter: ExplorerFilter) => void;
}) {
  const [localHours, setLocalHours] = useState<number>(hours);
  const [rows, setRows] = useState<GeoRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [hovered, setHovered] = useState<number | null>(null);

  // Keep the local selector in sync when the app-level range changes.
  useEffect(() => { setLocalHours(hours); }, [hours]);

  const fetchGeo = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(`/api/stats/geo?hours=${localHours}`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const json = await res.json();
      setRows(Array.isArray(json?.data) ? json.data : []);
    } catch (e) {
      setError('Could not load geographic attack activity.');
      setRows([]);
    } finally {
      setLoading(false);
    }
  }, [localHours]);

  useEffect(() => { fetchGeo(); }, [fetchGeo]);

  // Refresh on the global "R" hotkey / app refresh event.
  useEffect(() => {
    const h = () => fetchGeo();
    window.addEventListener('nocvault:refresh', h);
    return () => window.removeEventListener('nocvault:refresh', h);
  }, [fetchGeo]);

  // Sorted descending by count (the API already orders, but be defensive).
  const sorted = useMemo(
    () => [...rows].sort((a, b) => num(b.count) - num(a.count)),
    [rows],
  );

  const maxCount = useMemo(
    () => sorted.reduce((m, r) => Math.max(m, num(r.count)), 0),
    [sorted],
  );

  // Plottable bubbles: rows with a bundled centroid, kept in count-desc order so
  // rank/opacity follow the ranked list. index = rank position within `sorted`.
  const bubbles = useMemo(() => {
    return sorted
      .map((row, idx) => {
        const cc = (row.country_code || '').toUpperCase();
        const centroid = COUNTRY_CENTROIDS[cc];
        if (!centroid) return null;
        const count = num(row.count);
        const frac = maxCount > 0 ? Math.sqrt(count / maxCount) : 0;
        const r = MIN_R + (MAX_R - MIN_R) * frac;
        // Top attackers most saturated; taper opacity by rank.
        const opacity = Math.max(0.32, 0.9 - idx * 0.06);
        return {
          row, idx, count,
          name: centroid.name || row.country || cc,
          cx: projX(centroid.lon),
          cy: projY(centroid.lat),
          r,
          opacity,
          top: idx < TOP_N,
        };
      })
      .filter((b): b is NonNullable<typeof b> => b !== null);
  }, [sorted, maxCount]);

  // Click behavior: the geo feed is failed-auth scoped, and the Log Explorer's
  // free-text `q` matches structured_data->>'srccountry' (verified in
  // api/server.js), so a bubble/row click drills into Explorer filtered to
  // authentication logs whose source country matches — the closest honest
  // reproduction of "failed-auth from this country" (Explorer has no country
  // filter field). No-op if we have no usable country string.
  const drillCountry = useCallback((row: GeoRow) => {
    const name = row.country || row.country_code || '';
    if (!name) return;
    openExplorer({ q: name, category: 'authentication', hours: String(localHours) });
  }, [openExplorer, localHours]);

  const hoveredBubble = hovered != null ? bubbles.find(b => b.idx === hovered) : undefined;

  return (
    <div>
      {/* pulse/glow keyframes for the top-N bubbles (tasteful, subtle) */}
      <style>{`
        @keyframes threatmap-pulse {
          0%   { r: var(--tm-r); opacity: 0.55; }
          70%  { r: calc(var(--tm-r) * 2.2); opacity: 0; }
          100% { r: calc(var(--tm-r) * 2.2); opacity: 0; }
        }
        .threatmap-pulse-ring { animation: threatmap-pulse 2.4s ease-out infinite; }
      `}</style>

      <PageHeader title="Threat Map" subtitle="Attack & failed-auth activity by source country">
        <RangeSelector value={localHours} onChange={setLocalHours} />
      </PageHeader>

      {error && (
        <div style={{ marginBottom: 16, padding: '10px 14px', borderRadius: 8,
          background: 'var(--tint-danger)', color: 'var(--tint-danger-fg)',
          border: '1px solid var(--border)', fontSize: 'var(--text-base)', fontWeight: 500,
          display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12 }}>
          <span>⚠ {error}</span>
          <button onClick={fetchGeo}
            style={{ padding: '4px 10px', borderRadius: 6, border: '1px solid var(--border)',
              background: 'var(--bg-card)', color: 'var(--text-secondary)', cursor: 'pointer',
              fontSize: 'var(--text-xs)', fontWeight: 600 }}>
            Retry
          </button>
        </div>
      )}

      {loading ? (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border)',
            borderRadius: 10, padding: 16, boxShadow: 'var(--shadow-sm)' }}>
            <Skeleton height={16} width={180} />
            <div style={{ height: 12 }} />
            <div style={{ position: 'relative', width: '100%', paddingTop: '50%' }}>
              <div style={{ position: 'absolute', inset: 0, display: 'flex', alignItems: 'center',
                justifyContent: 'center' }}>
                <Spinner size={22} />
              </div>
            </div>
          </div>
        </div>
      ) : !error && sorted.length === 0 ? (
        <EmptyState
          icon={<span style={{ fontSize: 24 }}>{GLOBE}</span>}
          title="No geographic attack activity in this window"
          message="No failed-auth or attack activity with a resolvable source country was recorded for the selected time range."
        />
      ) : (
        <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 2fr) minmax(260px, 1fr)',
          gap: 16, alignItems: 'start' }}>
          {/* ── Map panel ── */}
          <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border)',
            borderRadius: 10, padding: 16, boxShadow: 'var(--shadow-sm)', minWidth: 0 }}>
            <div style={{ display: 'flex', alignItems: 'baseline', justifyContent: 'space-between',
              gap: 10, marginBottom: 10, flexWrap: 'wrap' }}>
              <div style={{ fontSize: 'var(--text-base)', fontWeight: 600, color: 'var(--text-primary)' }}>
                World attack map
              </div>
              <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
                {bubbles.length} of {sorted.length} countries plotted · bubble size = attack volume
              </div>
            </div>

            <div style={{ position: 'relative', width: '100%' }}>
              <svg viewBox={`0 0 ${MAP_W} ${MAP_H}`} width="100%"
                style={{ display: 'block', borderRadius: 8 }}
                preserveAspectRatio="xMidYMid meet"
                role="img" aria-label="World map of attack activity by source country">
                {/* Ocean / frame field */}
                <rect x={0} y={0} width={MAP_W} height={MAP_H}
                  fill="var(--surface-subtle)" stroke="var(--border)" strokeWidth={1} rx={6} />
                <Graticule />

                {/* Country bubbles (drawn small→large so big ones sit on top) */}
                {[...bubbles].sort((a, b) => a.r - b.r).map(b => (
                  <g key={b.row.country_code || b.name}
                    style={{ cursor: 'pointer' }}
                    tabIndex={0}
                    role="button"
                    aria-label={`${b.name}: ${b.count.toLocaleString()} attacks`}
                    onMouseEnter={() => setHovered(b.idx)}
                    onMouseLeave={() => setHovered(h => (h === b.idx ? null : h))}
                    onFocus={() => setHovered(b.idx)}
                    onBlur={() => setHovered(h => (h === b.idx ? null : h))}
                    onClick={() => drillCountry(b.row)}
                    onKeyDown={e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); drillCountry(b.row); } }}
                  >
                    {b.top && (
                      <circle className="threatmap-pulse-ring" cx={b.cx} cy={b.cy}
                        style={{ '--tm-r': `${b.r}px` } as React.CSSProperties}
                        fill="var(--primary)" />
                    )}
                    <circle cx={b.cx} cy={b.cy} r={b.r}
                      fill="var(--primary)" fillOpacity={b.opacity}
                      stroke="var(--bg-card)" strokeWidth={0.7} />
                  </g>
                ))}
              </svg>

              {/* Hover/focus tooltip, positioned by the bubble's projected coords */}
              {hoveredBubble && (
                <div style={{ position: 'absolute',
                  left: `${(hoveredBubble.cx / MAP_W) * 100}%`,
                  top: `${(hoveredBubble.cy / MAP_H) * 100}%`,
                  transform: 'translate(-50%, calc(-100% - 10px))', zIndex: 10 }}>
                  <BubbleTooltip row={hoveredBubble.row} name={hoveredBubble.name} />
                </div>
              )}
            </div>
          </div>

          {/* ── Ranked list panel ── */}
          <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border)',
            borderRadius: 10, padding: 16, boxShadow: 'var(--shadow-sm)', minWidth: 0 }}>
            <div style={{ fontSize: 'var(--text-base)', fontWeight: 600, color: 'var(--text-primary)',
              marginBottom: 2 }}>
              Top source countries
            </div>
            <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginBottom: 12 }}>
              Ranked by attack count · trend vs. prior window
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              {sorted.map((row, i) => (
                <RankRow key={(row.country_code || row.country || i) + `:${i}`}
                  row={row} rank={i + 1} onClick={() => drillCountry(row)} />
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

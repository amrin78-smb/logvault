'use client';

/**
 * Canonical vendor-identity and entity-risk-band palettes for the LogVault
 * suite. Companion to severity.tsx (syslog severity), covering two OTHER
 * concerns that had drifted into independent per-file copies.
 *
 * Reconciled 2026-07 from a live design-token audit that found two
 * incompatible VENDOR_COLORS palettes (3 files agreeing on real per-vendor
 * brand colors; 2 files using a generic rainbow set whose `fortinet` value,
 * #dc2626, was byte-identical to the severity-critical red token — a real
 * collision, since Fortinet is this deployment's dominant vendor by log
 * volume) and two disagreeing riskBand/riskBadge functions (one used 4
 * distinct colors across the 4 tiers; the other rendered High and Medium as
 * the exact same color, indistinguishable except by label text).
 */

// Per-vendor identity color — real corporate brand colors where known
// (Fortinet orange-red, Cisco cyan-blue, Palo Alto orange, Aruba/HPE orange,
// Sangfor navy), NOT a role-based/severity token, so these stay literal hex
// on purpose (a vendor's brand color isn't a themed surface and shouldn't
// flip with dark mode any more than the vendor's actual logo would).
export const VENDOR_COLORS: Record<string, string> = {
  fortinet: '#ee4d2d', cisco: '#1ba0d7', paloalto: '#fa582d',
  aruba: '#f47920', sangfor: '#005bac', generic: '#6b7280', unknown: '#6b7280',
  forcepoint: '#003087', checkpoint: '#E31937', juniper: '#84BD00',
  windows: '#0078D4', sonicwall: '#FF6600',
};
export const VENDOR_FALLBACK = '#6b7280';

/** Look up a vendor's identity color, with a safe fallback. */
export function vendorColor(vendor: string | null | undefined): string {
  return VENDOR_COLORS[(vendor || '').toLowerCase()] || VENDOR_FALLBACK;
}

export interface RiskBand {
  label: string;
  bg:    string;
  fg:    string;
}

/**
 * Entity/log risk-score (0-100) → adaptive tint-token band. Full 4-color
 * gradient (danger/warn/info/success) so all 4 tiers stay visually distinct
 * — the boundaries and "Medium = info" choice come from the pre-existing
 * DashboardWidgets.tsx implementation (already used 4 distinct colors);
 * "Low = success" (green) comes from the pre-existing LogDetailPanel.tsx
 * implementation (a real green "all clear" signal reads better than neutral
 * gray at the bottom of the same gradient that starts at danger/red).
 */
export function riskBand(score: number): RiskBand {
  if (score >= 81) return { label: 'Critical', bg: 'var(--tint-danger)',  fg: 'var(--tint-danger-fg)' };
  if (score >= 61) return { label: 'High',     bg: 'var(--tint-warn)',    fg: 'var(--tint-warn-fg)' };
  if (score >= 31) return { label: 'Medium',   bg: 'var(--tint-info)',    fg: 'var(--tint-info-fg)' };
  return               { label: 'Low',      bg: 'var(--tint-success)', fg: 'var(--tint-success-fg)' };
}

/** Inline-styled risk pill, matching the suite badge idiom (see severity.tsx's SevBadge). */
export function RiskBadge({ score, suffix }: { score: number; suffix?: string }) {
  const band = riskBand(score);
  return (
    <span style={{ padding: '2px 8px', borderRadius: 'var(--radius-sm)', fontSize: 'var(--text-xs)', fontWeight: 700,
      background: band.bg, color: band.fg, whiteSpace: 'nowrap' }}>
      {band.label}{suffix ?? ''} · {score}
    </span>
  );
}

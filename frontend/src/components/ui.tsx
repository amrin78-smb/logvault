'use client';

import { useEffect, useRef, useState, useMemo } from 'react';

// ════════════════════════════════════════════════════════════
// Shared UI primitives — NocVault suite (DDIVault reference).
// All components defined at module scope (never nested).
// ════════════════════════════════════════════════════════════

// ── Utilization colour helper ─────────────────────────────────
export function pctColor(pct: number): string {
  if (pct >= 90) return 'var(--red)';
  if (pct >= 80) return 'var(--yellow)';
  return 'var(--green)';
}

// ── Skeleton block ────────────────────────────────────────────
export function Skeleton({ width = '100%', height = 14, radius = 6, style }: {
  width?: number | string;
  height?: number | string;
  radius?: number;
  style?: React.CSSProperties;
}) {
  return <span className="skeleton" style={{ width, height, borderRadius: radius, ...style }} />;
}

// ── Table skeleton ────────────────────────────────────────────
export function TableSkeleton({ rows = 6, cols = 5 }: { rows?: number; cols?: number }) {
  return (
    <div style={{ padding: '4px 0' }}>
      {Array.from({ length: rows }).map((_, r) => (
        <div key={r} style={{ display: 'flex', gap: 16, padding: '11px 14px', alignItems: 'center' }}>
          {Array.from({ length: cols }).map((_, c) => (
            <Skeleton key={c} height={12} width={c === 0 ? 120 : `${Math.max(40, 100 / cols)}%`} />
          ))}
        </div>
      ))}
    </div>
  );
}

// ── Card skeleton (KPI tiles etc.) ────────────────────────────
export function CardSkeleton({ count = 5, height = 88 }: { count?: number; height?: number }) {
  return (
    <>
      {Array.from({ length: count }).map((_, i) => (
        <div key={i} style={{
          background: 'var(--bg-card)', border: '1px solid var(--border)',
          borderRadius: 'var(--radius)', padding: 18, minHeight: height,
        }}>
          <Skeleton height={28} width="50%" />
          <div style={{ height: 8 }} />
          <Skeleton height={12} width="70%" />
        </div>
      ))}
    </>
  );
}

// ── Empty state ───────────────────────────────────────────────
export function EmptyState({ icon, title, message, actionLabel, onAction }: {
  icon?: React.ReactNode;
  title: string;
  message?: string;
  actionLabel?: string;
  onAction?: () => void;
}) {
  return (
    <div style={{
      display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center',
      padding: '52px 24px', textAlign: 'center', color: 'var(--text-muted)',
    }}>
      {icon && (
        <div style={{
          width: 56, height: 56, borderRadius: 14, marginBottom: 16,
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          background: 'var(--bg-primary)', border: '1px solid var(--border)', color: 'var(--text-muted)',
        }}>
          {icon}
        </div>
      )}
      <div style={{ fontSize: 'var(--text-md)', fontWeight: 600, color: 'var(--text-primary)' }}>{title}</div>
      {message && <div style={{ fontSize: 'var(--text-base)', marginTop: 6, maxWidth: 420 }}>{message}</div>}
      {actionLabel && onAction && (
        <button className="btn btn-primary" style={{ marginTop: 18 }} onClick={onAction}>
          {actionLabel}
        </button>
      )}
    </div>
  );
}

// ── Page header (title + subtitle + right-aligned actions) ─────
export function PageHeader({ title, subtitle, children }: {
  title: string;
  subtitle?: string;
  children?: React.ReactNode;
}) {
  return (
    <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 16, flexWrap: 'wrap', marginBottom: 16 }}>
      <div>
        <div className="page-title">{title}</div>
        {subtitle && <div className="page-subtitle">{subtitle}</div>}
      </div>
      {children && <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>{children}</div>}
    </div>
  );
}

// ── Breadcrumb ────────────────────────────────────────────────
export interface Crumb { label: string; onClick?: () => void }
export function Breadcrumb({ items }: { items: Crumb[] }) {
  return (
    <nav className="breadcrumb">
      {items.map((c, i) => {
        const last = i === items.length - 1;
        return (
          <span key={i} style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
            {i > 0 && <span className="crumb-sep">/</span>}
            {last || !c.onClick
              ? <span className="crumb-current">{c.label}</span>
              : <button onClick={c.onClick}>{c.label}</button>}
          </span>
        );
      })}
    </nav>
  );
}

// ── Inline utilization bar ────────────────────────────────────
export function UtilBar({ pct, showLabel = true, width }: { pct: number; showLabel?: boolean; width?: number }) {
  const p = isNaN(pct) ? 0 : pct;
  const color = pctColor(p);
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 8, width }}>
      <div className="util-track">
        <div className="util-fill" style={{ width: `${Math.min(100, p)}%`, background: color }} />
      </div>
      {showLabel && <span style={{ fontSize: 'var(--text-xs)', fontWeight: 600, color, minWidth: 40, textAlign: 'right' }}>{p.toFixed(1)}%</span>}
    </div>
  );
}

// ── Trend indicator (↑ ↓ →) ───────────────────────────────────
export function Trend({ delta, invert = false }: { delta: number; invert?: boolean }) {
  // invert=false: rising is "bad" (red) — e.g. utilization. invert=true: rising is "good".
  const up = delta > 0.05, down = delta < -0.05;
  const arrow = up ? '↑' : down ? '↓' : '→';
  const good = invert ? up : down;
  const bad  = invert ? down : up;
  const color = good ? 'var(--green)' : bad ? 'var(--red)' : 'var(--text-muted)';
  return (
    <span style={{ color, fontSize: 'var(--text-sm)', fontWeight: 600 }}>
      {arrow} {Math.abs(delta).toFixed(1)}
    </span>
  );
}

// ── Spinner ───────────────────────────────────────────────────
export function Spinner({ size = 14, color = 'var(--primary)' }: { size?: number; color?: string }) {
  return (
    <span style={{
      display: 'inline-block', width: size, height: size,
      border: `2px solid var(--border)`, borderTopColor: color,
      borderRadius: '50%', animation: 'spin 0.8s linear infinite',
    }} />
  );
}

// ── Hook: refresh on global "R" key (dispatched by app shell) ──
export function useRefreshKey(cb: () => void) {
  const ref = useRef(cb);
  ref.current = cb;
  useEffect(() => {
    const h = () => ref.current();
    window.addEventListener('nocvault:refresh', h);
    return () => window.removeEventListener('nocvault:refresh', h);
  }, []);
}

// ── Hook: call cb on Escape keypress (for modals) ─────────────
export function useEscape(cb: () => void) {
  const ref = useRef(cb);
  ref.current = cb;
  useEffect(() => {
    const h = (e: KeyboardEvent) => { if (e.key === 'Escape') ref.current(); };
    window.addEventListener('keydown', h);
    return () => window.removeEventListener('keydown', h);
  }, []);
}

// ── Pagination ────────────────────────────────────────────────
// Client-side paging for lists that are ALREADY bounded server-side. Every
// LogVault list endpoint caps its result set (15–500 rows), so slicing in the
// browser is enough and costs no extra round trip — the problem being solved
// here is a page that renders hundreds of rows at once and has to be scrolled,
// not an oversized payload.
//
// ⚠ The one endpoint this reasoning does NOT cover is GET /api/hosts, which has
// no LIMIT and returns every known_hosts row (38k+ live). Paging its output in
// the browser fixes the scrolling but the whole set is still transferred; that
// endpoint wants real server-side paging, tracked separately.
export const PAGE_SIZE = 25;

/**
 * Slice `items` into pages. Returns the current page's rows plus everything the
 * <Pagination> control needs.
 *
 * Resets to page 1 whenever the list identity changes (a filter/search/refresh
 * produces a new array), so you can never be stranded on a page that no longer
 * exists — e.g. sitting on page 7 and then filtering down to 12 rows.
 */
export function usePaged<T>(items: T[], pageSize: number = PAGE_SIZE) {
  const [page, setPage] = useState(1);
  const total = items.length;
  const pageCount = Math.max(1, Math.ceil(total / pageSize));

  // Keyed on LENGTH, not on `items` itself. Callers almost always build their
  // list inline (`const filtered = rows.filter(...)`), so the array identity is
  // new on every render — depending on it would fire this reset continuously and
  // pin the user to page 1, i.e. break paging entirely. Length changes on the
  // events that should reset (search, filter, refresh with different data); a
  // same-length content change safely keeps your place.
  useEffect(() => { setPage(1); }, [items.length, pageSize]);

  const safePage = Math.min(page, pageCount);
  const start = (safePage - 1) * pageSize;
  const rows = useMemo(() => items.slice(start, start + pageSize), [items, start, pageSize]);

  return { rows, page: safePage, setPage, pageCount, total, start, pageSize };
}

/**
 * Pager bar. Renders nothing when everything already fits on one page, so it can
 * be dropped under any table unconditionally without adding clutter to short lists.
 */
export function Pagination({ page, pageCount, total, start, shown, unit = 'rows', onPage }: {
  page: number; pageCount: number; total: number; start: number; shown: number;
  unit?: string; onPage: (p: number) => void;
}) {
  if (pageCount <= 1) return null;
  const btn = (disabled: boolean): React.CSSProperties => ({
    padding: '4px 10px',
    borderRadius: 6,
    border: '1px solid var(--border)',
    background: 'var(--bg-card)',
    color: disabled ? 'var(--text-muted)' : 'var(--text-primary)',
    cursor: disabled ? 'default' : 'pointer',
    fontSize: 'var(--text-base)',
    opacity: disabled ? 0.5 : 1,
  });
  return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between',
      gap: 12, padding: '10px 4px 2px', flexWrap: 'wrap' }}>
      <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-secondary)' }}>
        Showing {(start + 1).toLocaleString()}–{(start + shown).toLocaleString()} of {total.toLocaleString()} {unit}
      </div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
        <button style={btn(page <= 1)} disabled={page <= 1} onClick={() => onPage(1)} aria-label="First page">«</button>
        <button style={btn(page <= 1)} disabled={page <= 1} onClick={() => onPage(page - 1)}>Prev</button>
        <span style={{ fontSize: 'var(--text-sm)', color: 'var(--text-secondary)', padding: '0 4px' }}>
          Page {page} of {pageCount}
        </span>
        <button style={btn(page >= pageCount)} disabled={page >= pageCount} onClick={() => onPage(page + 1)}>Next</button>
        <button style={btn(page >= pageCount)} disabled={page >= pageCount} onClick={() => onPage(pageCount)} aria-label="Last page">»</button>
      </div>
    </div>
  );
}

/**
 * Drop-in replacement for a <tbody> that holds a long list.
 *
 *   <tbody>{rows.map(r => <tr .../>)}</tbody>
 *   →
 *   <PagedTableBody items={rows} unit="devices">{page => page.map(r => <tr .../>)}</PagedTableBody>
 *
 * Owning the page state INSIDE this component is deliberate: most of these
 * tables live in components with early returns (loading/empty states), so a
 * usePaged() call hoisted to the caller's top level would sit above a
 * conditional return and risk breaking the rules of hooks. Here the hook is
 * unconditionally at the top of its own component.
 *
 * The pager renders in a <tfoot> so it stays inside the <table> element (a bare
 * <div> between <tbody> and </table> is invalid HTML and browsers hoist it out,
 * which breaks the layout). It disappears entirely when everything fits on one page.
 */
export function PagedTableBody<T>({ items, unit = 'rows', pageSize = PAGE_SIZE, colSpan = 99, children }: {
  items: T[];
  unit?: string;
  pageSize?: number;
  colSpan?: number;
  children: (rows: T[]) => React.ReactNode;
}) {
  const { rows, page, setPage, pageCount, total, start } = usePaged(items, pageSize);
  return (
    <>
      <tbody>{children(rows)}</tbody>
      {pageCount > 1 && (
        <tfoot>
          <tr>
            <td colSpan={colSpan} style={{ padding: 0, borderTop: '1px solid var(--border)' }}>
              <Pagination
                page={page} pageCount={pageCount} total={total}
                start={start} shown={rows.length} unit={unit} onPage={setPage}
              />
            </td>
          </tr>
        </tfoot>
      )}
    </>
  );
}

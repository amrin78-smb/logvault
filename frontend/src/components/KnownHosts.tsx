'use client';
import { useEffect, useState } from 'react';
import { useToast } from '@/components/Toast';
import { PageHeader, TableSkeleton, EmptyState } from './ui';

interface Host {
  ip_address:       string;
  hostname:         string;
  vendor:           string;
  description:      string;
  site_name:        string;
  brand:            string;
  model:            string;
  device_status:    string;
  lifecycle_status: string;
  synced_from_nv:   boolean;
  last_synced:      string;
  last_seen:        string;
}

const EMPTY = { ip_address: '', hostname: '', vendor: 'generic', description: '' };

const INPUT = { padding: '8px 12px', borderRadius: 6, border: '1px solid var(--border)',
  background: 'var(--bg-input)', color: 'var(--text-primary)', fontSize: 'var(--text-base)',
  width: '100%', outline: 'none', boxSizing: 'border-box' as const };

const VENDOR_COLORS: Record<string, string> = {
  fortinet: '#ee4d2d', cisco: '#1ba0d7', paloalto: '#fa582d',
  aruba: '#f47920', sangfor: '#005bac', generic: '#6b7280',
  forcepoint: '#003087', checkpoint: '#E31937', juniper: '#84BD00',
  windows: '#0078D4', sonicwall: '#FF6600',
};

const STATUS_STYLE: Record<string, { bg: string; color: string }> = {
  'Active':    { bg: 'var(--tint-success)', color: 'var(--tint-success-fg)' },
  'Decommed':  { bg: 'var(--surface-subtle)', color: 'var(--text-muted)' },
  'Spare':     { bg: 'var(--tint-warn)', color: 'var(--tint-warn-fg)' },
  'Faulty':    { bg: 'var(--tint-warn)', color: 'var(--tint-warn-fg)' },
};

export default function KnownHosts() {
  const { toast } = useToast();
  const [hosts,    setHosts]    = useState<Host[]>([]);
  const [search,   setSearch]   = useState('');
  const [form,     setForm]     = useState(EMPTY);
  const [editIp,   setEditIp]   = useState<string | null>(null);
  const [error,    setError]    = useState<string | null>(null);
  const [loading,  setLoading]  = useState(false);
  const [listLoading, setListLoading] = useState(true);
  const [syncing,  setSyncing]  = useState(false);
  const [lastSync, setLastSync] = useState<string | null>(null);

  const fetchHosts = () => {
    fetch('/api/hosts').then(r => r.json()).then(d => {
      setHosts(d.data || []);
      const synced = (d.data || []).filter((h: Host) => h.last_synced);
      if (synced.length > 0) {
        setLastSync(synced[0].last_synced);
      }
    }).catch(() => {}).finally(() => setListLoading(false));
  };

  useEffect(() => { fetchHosts(); }, []);

  const save = async () => {
    if (!form.ip_address || !form.hostname) { setError('IP address and hostname are required.'); return; }
    setLoading(true); setError(null);
    try {
      await fetch('/api/hosts', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(form) });
      toast(editIp ? 'Host updated' : 'Host added', 'success');
      setForm(EMPTY); setEditIp(null); fetchHosts();
    } catch { setError('Failed to save.'); }
    setLoading(false);
  };

  const triggerSync = async () => {
    setSyncing(true);
    try {
      const r = await fetch('/api/hosts/sync-netvault', { method: 'POST' });
      const d = await r.json();
      if (d.ok) {
        toast(`Synced ${d.synced} devices from NetVault`, 'success');
        fetchHosts();
      } else {
        toast('Sync failed — check NetVault connection', 'error');
      }
    } catch { toast('Sync failed', 'error'); }
    setSyncing(false);
  };

  const [showAll, setShowAll] = useState(false);
  const LIMIT = 10;
  const filtered = search
    ? hosts.filter(h =>
        h.ip_address?.includes(search) ||
        h.hostname?.toLowerCase().includes(search.toLowerCase()) ||
        h.vendor?.toLowerCase().includes(search.toLowerCase()) ||
        h.site_name?.toLowerCase().includes(search.toLowerCase()) ||
        h.brand?.toLowerCase().includes(search.toLowerCase()))
    : hosts;
  const displayed = showAll ? filtered : filtered.slice(0, LIMIT);

  const nvSynced  = hosts.filter(h => h.synced_from_nv).length;
  const manualCount = hosts.filter(h => !h.synced_from_nv).length;

  return (
    <div>
      <PageHeader title="Known Hosts" subtitle="IP-to-hostname mapping with NetVault asset sync" />

      {/* Add / Edit form */}
      <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 8, padding: 16, marginBottom: 16, boxShadow: '0 1px 3px rgba(0,0,0,0.06)' }}>
        <div style={{ fontSize: 'var(--text-md)', fontWeight: 600, color: 'var(--text-primary)', marginBottom: 4 }}>
          {editIp ? 'Edit Host' : 'Add Known Host'}
        </div>
        <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginBottom: 16 }}>
          Register device IPs for friendly name display in logs
        </div>
        {error && (
          <div style={{ padding: '8px 12px', background: 'var(--tint-danger)', border: '1px solid var(--tint-danger)',
            borderRadius: 6, color: 'var(--tint-danger-fg)', fontSize: 'var(--text-sm)', marginBottom: 12 }}>{error}</div>
        )}
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr 1fr', gap: 12, marginBottom: 12 }}>
          <div>
            <div style={{ fontSize: 'var(--text-xs)', fontWeight: 500, color: 'var(--text-secondary)', marginBottom: 4 }}>IP Address *</div>
            <input value={form.ip_address} onChange={e => setForm(f => ({ ...f, ip_address: e.target.value }))}
              placeholder="10.1.1.1" style={INPUT} disabled={!!editIp} />
          </div>
          <div>
            <div style={{ fontSize: 'var(--text-xs)', fontWeight: 500, color: 'var(--text-secondary)', marginBottom: 4 }}>Hostname *</div>
            <input value={form.hostname} onChange={e => setForm(f => ({ ...f, hostname: e.target.value }))}
              placeholder="FG-BKK-01" style={INPUT} />
          </div>
          <div>
            <div style={{ fontSize: 'var(--text-xs)', fontWeight: 500, color: 'var(--text-secondary)', marginBottom: 4 }}>Vendor</div>
            <select value={form.vendor} onChange={e => setForm(f => ({ ...f, vendor: e.target.value }))}
              style={{ ...INPUT, cursor: 'pointer' }}>
              {['fortinet','cisco','paloalto','aruba','sangfor','generic'].map(v => (
                <option key={v} value={v}>{v.charAt(0).toUpperCase() + v.slice(1)}</option>
              ))}
            </select>
          </div>
          <div>
            <div style={{ fontSize: 'var(--text-xs)', fontWeight: 500, color: 'var(--text-secondary)', marginBottom: 4 }}>Description</div>
            <input value={form.description} onChange={e => setForm(f => ({ ...f, description: e.target.value }))}
              placeholder="Bangkok HQ Firewall" style={INPUT} />
          </div>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <button onClick={save} disabled={loading}
            style={{ padding: '8px 20px', borderRadius: 6, border: 'none', cursor: 'pointer',
              fontSize: 'var(--text-base)', fontWeight: 600, background: 'var(--primary)', color: '#fff', opacity: loading ? 0.7 : 1 }}>
            {loading ? 'Saving...' : editIp ? 'Update Host' : 'Add Host'}
          </button>
          {editIp && (
            <button onClick={() => { setForm(EMPTY); setEditIp(null); setError(null); }}
              style={{ padding: '8px 16px', borderRadius: 6, border: '1px solid var(--border)',
                cursor: 'pointer', fontSize: 'var(--text-base)', background: 'var(--bg-card)', color: 'var(--text-secondary)' }}>
              Cancel
            </button>
          )}
        </div>
      </div>

      {/* Host list */}
      <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 8, padding: 16, boxShadow: '0 1px 3px rgba(0,0,0,0.06)' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16 }}>
          <div>
            <div style={{ fontSize: 'var(--text-md)', fontWeight: 600, color: 'var(--text-primary)' }}>
              Registered Hosts
              <span style={{ marginLeft: 8, fontSize: 'var(--text-sm)', fontWeight: 400, color: 'var(--text-muted)' }}>
                {hosts.length} total · {nvSynced} from NetVault · {manualCount} manual
              </span>
            </div>
            {lastSync && (
              <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginTop: 2 }}>
                Last synced from NetVault: {new Date(lastSync).toLocaleString()}
              </div>
            )}
          </div>
          <div style={{ display: 'flex', gap: 8 }}>
            {/* Sync from NetVault button */}
            <button onClick={triggerSync} disabled={syncing}
              style={{ padding: '7px 14px', borderRadius: 6, border: '1px solid var(--tint-info)',
                cursor: 'pointer', fontSize: 'var(--text-sm)', fontWeight: 600,
                background: 'var(--tint-info)', color: 'var(--tint-info-fg)',
                display: 'flex', alignItems: 'center', gap: 6 }}>
              <svg width="12" height="12" viewBox="0 0 12 12" fill="none">
                <path d="M10 6A4 4 0 1 1 6 2" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"/>
                <polyline points="6,0 8,2 6,4" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
              </svg>
              {syncing ? 'Syncing...' : 'Sync from NetVault'}
            </button>
            <input value={search} onChange={e => setSearch(e.target.value)}
              placeholder="Search..." style={{ ...INPUT, width: 200 }} />
          </div>
        </div>

        {listLoading ? (
          <TableSkeleton rows={8} cols={5} />
        ) : filtered.length === 0 ? (
          <EmptyState title="No known hosts" message="Hosts will appear here as logs arrive or after NetVault sync." />
        ) : (
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 'var(--text-base)' }}>
            <thead>
              <tr style={{ borderBottom: '2px solid var(--border)' }}>
                {['IP Address','Hostname','Vendor','Brand / Model','Site','Status','Source','Last Seen'].map(h => (
                  <th key={h} style={{ padding: '8px 12px', textAlign: 'left', fontSize: 'var(--text-xs)',
                    fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase',
                    letterSpacing: '0.05em', whiteSpace: 'nowrap' }}>{h}</th>
                ))}
                <th style={{ padding: '8px 12px' }} />
              </tr>
            </thead>
            <tbody>
              {displayed.map((h, i) => {
                const statusStyle = STATUS_STYLE[h.device_status] || { bg: 'var(--surface-subtle)', color: 'var(--text-muted)' };
                return (
                  <tr key={h.ip_address} style={{ borderBottom: '1px solid var(--border-light)',
                    background: i % 2 === 0 ? 'transparent' : 'var(--bg-primary)' }}
                    onMouseEnter={e => { (e.currentTarget as HTMLElement).style.background = 'var(--bg-hover)'; }}
                    onMouseLeave={e => { (e.currentTarget as HTMLElement).style.background = i % 2 === 0 ? 'transparent' : 'var(--bg-primary)'; }}>
                    <td style={{ padding: '10px 12px', fontFamily: 'var(--font-mono)', fontSize: 'var(--text-sm)', color: 'var(--primary)', fontWeight: 500 }}>
                      {h.ip_address}
                    </td>
                    <td style={{ padding: '10px 12px', fontWeight: 600, color: 'var(--text-primary)' }}>
                      {h.hostname || '—'}
                    </td>
                    <td style={{ padding: '10px 12px' }}>
                      <span style={{ padding: '2px 8px', borderRadius: 4, fontSize: 'var(--text-xs)', fontWeight: 600,
                        background: `${VENDOR_COLORS[h.vendor] || '#6b7280'}18`,
                        color: VENDOR_COLORS[h.vendor] || '#6b7280', textTransform: 'capitalize' }}>
                        {h.vendor || 'generic'}
                      </span>
                    </td>
                    <td style={{ padding: '10px 12px', color: 'var(--text-secondary)', fontSize: 'var(--text-sm)' }}>
                      {h.brand && <span style={{ fontWeight: 500 }}>{h.brand}</span>}
                      {h.model && <span style={{ color: 'var(--text-muted)' }}> · {h.model}</span>}
                      {!h.brand && !h.model && '—'}
                    </td>
                    <td style={{ padding: '10px 12px', color: 'var(--text-secondary)', fontSize: 'var(--text-sm)' }}>
                      {h.site_name || h.description || '—'}
                    </td>
                    <td style={{ padding: '10px 12px' }}>
                      {h.device_status ? (
                        <span style={{ padding: '2px 8px', borderRadius: 10, fontSize: 'var(--text-xs)', fontWeight: 500,
                          background: statusStyle.bg, color: statusStyle.color }}>
                          {h.device_status}
                        </span>
                      ) : '—'}
                    </td>
                    <td style={{ padding: '10px 12px' }}>
                      {h.synced_from_nv ? (
                        <span style={{ padding: '2px 8px', borderRadius: 10, fontSize: 'var(--text-xs)',
                          background: 'var(--tint-info)', color: 'var(--tint-info-fg)', fontWeight: 500 }}>
                          NetVault
                        </span>
                      ) : (
                        <span style={{ padding: '2px 8px', borderRadius: 10, fontSize: 'var(--text-xs)',
                          background: 'var(--surface-subtle)', color: 'var(--text-muted)' }}>
                          Manual
                        </span>
                      )}
                    </td>
                    <td style={{ padding: '10px 12px', color: 'var(--text-muted)', fontSize: 'var(--text-xs)' }}>
                      {h.last_seen ? new Date(h.last_seen).toLocaleDateString() : '—'}
                    </td>
                    <td style={{ padding: '10px 12px' }}>
                      {!h.synced_from_nv && (
                        <button onClick={() => {
                          setForm({ ip_address: h.ip_address, hostname: h.hostname || '',
                            vendor: h.vendor || 'generic', description: h.description || '' });
                          setEditIp(h.ip_address); setError(null);
                        }}
                          style={{ padding: '4px 10px', borderRadius: 5, border: '1px solid var(--border)',
                            cursor: 'pointer', fontSize: 'var(--text-xs)', background: 'var(--bg-card)', color: 'var(--text-secondary)' }}>
                          Edit
                        </button>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}

        {/* Show more / less */}
        {filtered.length > LIMIT && (
          <div style={{ textAlign: 'center', marginTop: 12 }}>
            <button onClick={() => setShowAll(s => !s)}
              style={{ padding: '7px 20px', borderRadius: 6, border: '1px solid var(--border)',
                cursor: 'pointer', fontSize: 'var(--text-sm)', fontWeight: 500,
                background: 'var(--bg-card)', color: 'var(--text-secondary)' }}>
              {showAll
                ? `▲ Show less`
                : `▼ Show ${filtered.length - LIMIT} more (${filtered.length} total)`}
            </button>
          </div>
        )}
      </div>
    </div>
  );
}

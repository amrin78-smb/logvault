'use client';
import { useEffect, useState } from 'react';

const CARD  = { background: '#ffffff', border: '1px solid #e2e6ea', borderRadius: 10, padding: 20, marginBottom: 16 };
const INPUT = { background: '#f8f9fb', border: '1px solid #e2e6ea', borderRadius: 6, padding: '8px 12px', color: '#1a202c', fontSize: 13, outline: 'none', width: '100%' };
const VENDORS = ['cisco', 'paloalto', 'fortinet', 'aruba', 'sangfor', 'generic', 'other'];
const VENDOR_COLORS: Record<string, string> = {
  cisco: '#2563eb', paloalto: '#ea580c', fortinet: '#dc2626',
  aruba: '#7c3aed', sangfor: '#0891b2', generic: '#9ca3af', other: '#6b7280',
};
const EMPTY = { ip_address: '', hostname: '', vendor: 'generic', description: '' };

export default function KnownHosts() {
  const [hosts, setHosts]     = useState<any[]>([]);
  const [form, setForm]       = useState({ ...EMPTY });
  const [loading, setLoading] = useState(false);
  const [saving, setSaving]   = useState(false);
  const [error, setError]     = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [editIp, setEditIp]   = useState<string | null>(null);
  const [search, setSearch]   = useState('');

  const fetchHosts = async () => {
    setLoading(true);
    try { const r = await fetch('/api/hosts'); const d = await r.json(); setHosts(d.data || []); } catch (e: any) { setError(e.message); }
    setLoading(false);
  };

  useEffect(() => { fetchHosts(); }, []);

  const showSuccess = (msg: string) => { setSuccess(msg); setTimeout(() => setSuccess(null), 3000); };

  const handleSave = async () => {
    if (!form.ip_address || !form.hostname) { setError('IP address and hostname are required.'); return; }
    setSaving(true); setError(null);
    try {
      const r = await fetch('/api/hosts', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(form) });
      if (!r.ok) throw new Error(`Save failed: ${r.status}`);
      setForm({ ...EMPTY }); setEditIp(null); await fetchHosts();
      showSuccess(editIp ? 'Host updated.' : 'Host added.');
    } catch (e: any) { setError(e.message); }
    setSaving(false);
  };

  const handleEdit = (host: any) => {
    setForm({ ip_address: host.ip_address, hostname: host.hostname || '', vendor: host.vendor || 'generic', description: host.description || '' });
    setEditIp(host.ip_address); setError(null);
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  const filtered = search ? hosts.filter(h =>
    h.ip_address?.includes(search) || h.hostname?.toLowerCase().includes(search.toLowerCase()) ||
    h.vendor?.toLowerCase().includes(search.toLowerCase())) : hosts;

  return (
    <div>
      <div style={CARD}>
        <div style={{ fontSize: 14, fontWeight: 600, color: '#1a202c', marginBottom: 2 }}>{editIp ? `Editing: ${editIp}` : 'Add Known Host'}</div>
        <div style={{ fontSize: 11, color: '#718096', marginBottom: 16 }}>Register device IPs for friendly name display in logs</div>
        {error   && <div style={{ marginBottom: 12, padding: '8px 12px', background: '#fef2f2', border: '1px solid #fecaca', borderRadius: 6, fontSize: 12, color: '#dc2626' }}>{error}</div>}
        {success && <div style={{ marginBottom: 12, padding: '8px 12px', background: '#f0fdf4', border: '1px solid #bbf7d0', borderRadius: 6, fontSize: 12, color: '#16a34a' }}>{success}</div>}
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr 2fr', gap: 12, marginBottom: 12 }}>
          <div>
            <label style={{ fontSize: 11, color: '#718096', display: 'block', marginBottom: 4, fontWeight: 600 }}>IP Address *</label>
            <input value={form.ip_address} onChange={e => setForm(f => ({ ...f, ip_address: e.target.value }))}
              placeholder="10.1.1.1" disabled={!!editIp} style={{ ...INPUT, opacity: editIp ? 0.6 : 1 }} />
          </div>
          <div>
            <label style={{ fontSize: 11, color: '#718096', display: 'block', marginBottom: 4, fontWeight: 600 }}>Hostname *</label>
            <input value={form.hostname} onChange={e => setForm(f => ({ ...f, hostname: e.target.value }))} placeholder="FG-BKK-01" style={INPUT} />
          </div>
          <div>
            <label style={{ fontSize: 11, color: '#718096', display: 'block', marginBottom: 4, fontWeight: 600 }}>Vendor</label>
            <select value={form.vendor} onChange={e => setForm(f => ({ ...f, vendor: e.target.value }))} style={{ ...INPUT, cursor: 'pointer' }}>
              {VENDORS.map(v => <option key={v} value={v}>{v.charAt(0).toUpperCase() + v.slice(1)}</option>)}
            </select>
          </div>
          <div>
            <label style={{ fontSize: 11, color: '#718096', display: 'block', marginBottom: 4, fontWeight: 600 }}>Description</label>
            <input value={form.description} onChange={e => setForm(f => ({ ...f, description: e.target.value }))} placeholder="Bangkok HQ Firewall" style={INPUT} />
          </div>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <button onClick={handleSave} disabled={saving}
            style={{ padding: '8px 20px', borderRadius: 6, border: 'none', cursor: 'pointer', fontSize: 13,
              fontWeight: 600, background: '#2563eb', color: '#ffffff', opacity: saving ? 0.7 : 1 }}>
            {saving ? 'Saving...' : editIp ? 'Update Host' : 'Add Host'}
          </button>
          {editIp && (
            <button onClick={() => { setForm({ ...EMPTY }); setEditIp(null); setError(null); }}
              style={{ padding: '8px 20px', borderRadius: 6, border: '1px solid #e2e6ea', cursor: 'pointer', fontSize: 13, background: '#f8f9fb', color: '#4a5568' }}>
              Cancel
            </button>
          )}
        </div>
      </div>

      <div style={CARD}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 16 }}>
          <span style={{ fontSize: 14, fontWeight: 600, color: '#1a202c' }}>
            Registered Hosts
            <span style={{ marginLeft: 8, padding: '2px 8px', borderRadius: 10, background: '#f0f2f5', color: '#718096', fontSize: 11 }}>{hosts.length}</span>
          </span>
          <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search..."
            style={{ marginLeft: 'auto', background: '#f8f9fb', border: '1px solid #e2e6ea', borderRadius: 6, padding: '6px 12px', color: '#1a202c', fontSize: 12, outline: 'none', width: 180 }} />
          <button onClick={fetchHosts} style={{ padding: '6px 14px', borderRadius: 6, border: '1px solid #e2e6ea', cursor: 'pointer', fontSize: 12, background: '#f8f9fb', color: '#4a5568' }}>Refresh</button>
        </div>
        {loading ? (
          <div style={{ padding: '32px 0', textAlign: 'center', color: '#9ca3af' }}>Loading...</div>
        ) : filtered.length === 0 ? (
          <div style={{ padding: '32px 0', textAlign: 'center', color: '#9ca3af' }}>
            {hosts.length === 0 ? 'No hosts registered yet.' : 'No hosts match your search.'}
          </div>
        ) : (
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
            <thead>
              <tr style={{ borderBottom: '2px solid #f0f2f5' }}>
                {['IP Address','Hostname','Vendor','Description','Last Seen',''].map(h => (
                  <th key={h} style={{ padding: '8px 12px', textAlign: 'left', color: '#718096', fontWeight: 600, fontSize: 11 }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {filtered.map((host, i) => (
                <tr key={host.ip_address} style={{ borderBottom: '1px solid #f0f2f5', background: i % 2 === 0 ? '#fafbfc' : '#fff' }}>
                  <td style={{ padding: '9px 12px', color: '#2563eb', fontFamily: 'JetBrains Mono, monospace', fontSize: 11, fontWeight: 500 }}>{host.ip_address}</td>
                  <td style={{ padding: '9px 12px', color: '#1a202c', fontWeight: 600 }}>{host.hostname}</td>
                  <td style={{ padding: '9px 12px' }}>
                    <span style={{ padding: '2px 8px', borderRadius: 4, fontSize: 11, fontWeight: 500,
                      background: `${VENDOR_COLORS[host.vendor] || '#9ca3af'}18`,
                      color: VENDOR_COLORS[host.vendor] || '#9ca3af',
                      border: `1px solid ${VENDOR_COLORS[host.vendor] || '#9ca3af'}44`,
                      textTransform: 'capitalize' }}>
                      {host.vendor}
                    </span>
                  </td>
                  <td style={{ padding: '9px 12px', color: '#718096' }}>{host.description || '-'}</td>
                  <td style={{ padding: '9px 12px', color: '#9ca3af', fontSize: 11 }}>
                    {host.last_seen ? new Date(host.last_seen).toLocaleString() : '-'}
                  </td>
                  <td style={{ padding: '9px 12px' }}>
                    <button onClick={() => handleEdit(host)}
                      style={{ padding: '3px 10px', borderRadius: 4, border: '1px solid #e2e6ea', cursor: 'pointer', fontSize: 11, background: '#f8f9fb', color: '#4a5568' }}>
                      Edit
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

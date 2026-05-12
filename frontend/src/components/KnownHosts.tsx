'use client';

import { useEffect, useState } from 'react';

const CARD  = { background: '#161b27', border: '1px solid #1e2d40', borderRadius: 8, padding: 20, marginBottom: 16 };
const INPUT = { background: '#0f1117', border: '1px solid #1e2d40', borderRadius: 6, padding: '8px 12px', color: '#e2e8f0', fontSize: 13, outline: 'none', width: '100%' };

const VENDORS = ['cisco', 'paloalto', 'fortinet', 'aruba', 'sangfor', 'generic', 'other'];

const VENDOR_COLORS: Record<string, string> = {
  cisco: '#1d6fa5', paloalto: '#f97316', fortinet: '#ef4444',
  aruba: '#8b5cf6', sangfor: '#06b6d4', generic: '#475569', other: '#374151',
};

const EMPTY_FORM = { ip_address: '', hostname: '', vendor: 'generic', description: '' };

export default function KnownHosts() {
  const [hosts, setHosts]     = useState<any[]>([]);
  const [form, setForm]       = useState({ ...EMPTY_FORM });
  const [loading, setLoading] = useState(false);
  const [saving, setSaving]   = useState(false);
  const [error, setError]     = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [editIp, setEditIp]   = useState<string | null>(null);
  const [search, setSearch]   = useState('');

  const fetchHosts = async () => {
    setLoading(true);
    try {
      const r = await fetch('/api/hosts');
      const d = await r.json();
      setHosts(d.data || []);
    } catch (e: any) {
      setError(e.message);
    }
    setLoading(false);
  };

  useEffect(() => { fetchHosts(); }, []);

  const showSuccess = (msg: string) => {
    setSuccess(msg);
    setTimeout(() => setSuccess(null), 3000);
  };

  const handleSave = async () => {
    if (!form.ip_address || !form.hostname) {
      setError('IP address and hostname are required.');
      return;
    }
    setSaving(true);
    setError(null);
    try {
      const r = await fetch('/api/hosts', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(form),
      });
      if (!r.ok) throw new Error(`Save failed: ${r.status}`);
      setForm({ ...EMPTY_FORM });
      setEditIp(null);
      await fetchHosts();
      showSuccess(editIp ? 'Host updated successfully.' : 'Host added successfully.');
    } catch (e: any) {
      setError(e.message);
    }
    setSaving(false);
  };

  const handleEdit = (host: any) => {
    setForm({
      ip_address:  host.ip_address,
      hostname:    host.hostname    || '',
      vendor:      host.vendor      || 'generic',
      description: host.description || '',
    });
    setEditIp(host.ip_address);
    setError(null);
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  const handleCancel = () => {
    setForm({ ...EMPTY_FORM });
    setEditIp(null);
    setError(null);
  };

  const filtered = search
    ? hosts.filter(h =>
        h.ip_address?.includes(search) ||
        h.hostname?.toLowerCase().includes(search.toLowerCase()) ||
        h.vendor?.toLowerCase().includes(search.toLowerCase()) ||
        h.description?.toLowerCase().includes(search.toLowerCase()))
    : hosts;

  return (
    <div>
      {/* Add / Edit Form */}
      <div style={CARD}>
        <div style={{ fontSize: 13, fontWeight: 600, color: '#94a3b8', marginBottom: 16 }}>
          {editIp ? `Editing: ${editIp}` : 'Add Known Host'}
        </div>

        {error && (
          <div style={{ marginBottom: 12, padding: '8px 12px', background: '#1f0a0a',
            border: '1px solid #7f1d1d', borderRadius: 6, fontSize: 12, color: '#fca5a5' }}>
            {error}
          </div>
        )}
        {success && (
          <div style={{ marginBottom: 12, padding: '8px 12px', background: '#0a1f0a',
            border: '1px solid #14532d', borderRadius: 6, fontSize: 12, color: '#86efac' }}>
            {success}
          </div>
        )}

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr 2fr', gap: 12, marginBottom: 12 }}>
          <div>
            <label style={{ fontSize: 11, color: '#64748b', display: 'block', marginBottom: 4 }}>IP Address *</label>
            <input value={form.ip_address} onChange={e => setForm(f => ({ ...f, ip_address: e.target.value }))}
              placeholder="10.1.1.1" disabled={!!editIp}
              style={{ ...INPUT, opacity: editIp ? 0.6 : 1 }} />
          </div>
          <div>
            <label style={{ fontSize: 11, color: '#64748b', display: 'block', marginBottom: 4 }}>Hostname *</label>
            <input value={form.hostname} onChange={e => setForm(f => ({ ...f, hostname: e.target.value }))}
              placeholder="FG-BKK-01"
              style={INPUT} />
          </div>
          <div>
            <label style={{ fontSize: 11, color: '#64748b', display: 'block', marginBottom: 4 }}>Vendor</label>
            <select value={form.vendor} onChange={e => setForm(f => ({ ...f, vendor: e.target.value }))}
              style={{ ...INPUT, cursor: 'pointer' }}>
              {VENDORS.map(v => (
                <option key={v} value={v}>{v.charAt(0).toUpperCase() + v.slice(1)}</option>
              ))}
            </select>
          </div>
          <div>
            <label style={{ fontSize: 11, color: '#64748b', display: 'block', marginBottom: 4 }}>Description</label>
            <input value={form.description} onChange={e => setForm(f => ({ ...f, description: e.target.value }))}
              placeholder="Bangkok HQ Firewall"
              style={INPUT} />
          </div>
        </div>

        <div style={{ display: 'flex', gap: 8 }}>
          <button onClick={handleSave} disabled={saving}
            style={{ padding: '8px 20px', borderRadius: 6, border: 'none', cursor: 'pointer',
              fontSize: 13, fontWeight: 500, background: '#1e3a5f', color: '#38bdf8',
              opacity: saving ? 0.7 : 1 }}>
            {saving ? 'Saving...' : editIp ? 'Update Host' : 'Add Host'}
          </button>
          {editIp && (
            <button onClick={handleCancel}
              style={{ padding: '8px 20px', borderRadius: 6, border: '1px solid #1e2d40',
                cursor: 'pointer', fontSize: 13, background: 'transparent', color: '#64748b' }}>
              Cancel
            </button>
          )}
        </div>
      </div>

      {/* Host List */}
      <div style={CARD}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 16 }}>
          <span style={{ fontSize: 13, fontWeight: 600, color: '#94a3b8' }}>
            Registered Hosts
            <span style={{ marginLeft: 8, padding: '2px 8px', borderRadius: 10,
              background: '#1e2d40', color: '#64748b', fontSize: 11 }}>
              {hosts.length}
            </span>
          </span>
          <input value={search} onChange={e => setSearch(e.target.value)}
            placeholder="Search hosts..."
            style={{ marginLeft: 'auto', background: '#0f1117', border: '1px solid #1e2d40',
              borderRadius: 6, padding: '6px 12px', color: '#e2e8f0', fontSize: 12,
              outline: 'none', width: 200 }} />
          <button onClick={fetchHosts}
            style={{ padding: '6px 14px', borderRadius: 6, border: '1px solid #1e2d40',
              cursor: 'pointer', fontSize: 12, background: 'transparent', color: '#64748b' }}>
            Refresh
          </button>
        </div>

        {loading ? (
          <div style={{ padding: '32px 0', textAlign: 'center', color: '#475569', fontSize: 13 }}>Loading...</div>
        ) : filtered.length === 0 ? (
          <div style={{ padding: '32px 0', textAlign: 'center', color: '#475569', fontSize: 13 }}>
            {hosts.length === 0 ? 'No hosts registered yet. Add your first device above.' : 'No hosts match your search.'}
          </div>
        ) : (
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
            <thead>
              <tr style={{ borderBottom: '1px solid #1e2d40' }}>
                {['IP Address','Hostname','Vendor','Description','Last Seen',''].map(h => (
                  <th key={h} style={{ padding: '8px 12px', textAlign: 'left', color: '#64748b', fontWeight: 600 }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {filtered.map((host, i) => (
                <tr key={host.ip_address}
                  style={{ borderBottom: '1px solid #0f1117', background: i % 2 === 0 ? '#0f1520' : 'transparent' }}>
                  <td style={{ padding: '8px 12px', color: '#7dd3fc', fontFamily: 'monospace' }}>
                    {host.ip_address}
                  </td>
                  <td style={{ padding: '8px 12px', color: '#e2e8f0', fontWeight: 500 }}>
                    {host.hostname}
                  </td>
                  <td style={{ padding: '8px 12px' }}>
                    <span style={{ padding: '2px 8px', borderRadius: 4, fontSize: 11, fontWeight: 500,
                      background: `${VENDOR_COLORS[host.vendor] || '#374151'}33`,
                      color: VENDOR_COLORS[host.vendor] || '#94a3b8',
                      textTransform: 'capitalize', border: `1px solid ${VENDOR_COLORS[host.vendor] || '#374151'}55` }}>
                      {host.vendor}
                    </span>
                  </td>
                  <td style={{ padding: '8px 12px', color: '#64748b' }}>{host.description || '-'}</td>
                  <td style={{ padding: '8px 12px', color: '#475569', whiteSpace: 'nowrap' }}>
                    {host.last_seen ? new Date(host.last_seen).toLocaleString() : '-'}
                  </td>
                  <td style={{ padding: '8px 12px' }}>
                    <button onClick={() => handleEdit(host)}
                      style={{ padding: '3px 10px', borderRadius: 4, border: '1px solid #1e2d40',
                        cursor: 'pointer', fontSize: 11, background: 'transparent', color: '#94a3b8' }}>
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

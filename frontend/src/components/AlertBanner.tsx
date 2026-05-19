'use client';
import { useEffect, useState, useRef } from 'react';

interface BannerAlert { id: number; message: string; rule_name: string; fired_at: string; }

export default function AlertBanner() {
  const [alerts,   setAlerts]   = useState<BannerAlert[]>([]);
  const [visible,  setVisible]  = useState(false);
  const lastIdRef  = useRef<number>(0);
  const wsRef      = useRef<WebSocket | null>(null);

  // Also poll for new unacknowledged alerts every 15s as fallback
  useEffect(() => {
    const check = async () => {
      try {
        const r = await fetch('/api/alerts/events/recent-unacked');
        const d = await r.json();
        if (d.data?.length > 0) {
          const newAlerts = d.data.filter((a: any) => a.id > lastIdRef.current);
          if (newAlerts.length > 0) {
            lastIdRef.current = Math.max(...newAlerts.map((a: any) => a.id));
            setAlerts(prev => [...newAlerts, ...prev].slice(0, 5));
            setVisible(true);
          }
        }
      } catch {}
    };
    check();
    const t = setInterval(check, 15000);
    return () => clearInterval(t);
  }, []);

  if (!visible || alerts.length === 0) return null;

  const latest = alerts[0];
  const isLoop     = /loop|mac flap/i.test(latest.rule_name);
  const isBrute    = /brute force/i.test(latest.rule_name);
  const isIPS      = /ips/i.test(latest.rule_name);
  const emoji      = isLoop ? '🔁' : isBrute ? '🚨' : isIPS ? '🛡️' : '⚠️';
  const bg         = isLoop || isBrute ? '#fef2f2' : '#fefce8';
  const border     = isLoop || isBrute ? '#fecaca' : '#fde68a';
  const color      = isLoop || isBrute ? '#dc2626' : '#ca8a04';

  return (
    <div style={{ background: bg, border: `1px solid ${border}`, borderBottom: `2px solid ${border}`,
      padding: '8px 20px', display: 'flex', alignItems: 'center', gap: 12,
      animation: 'fadeIn 0.3s ease', zIndex: 100 }}>
      <span style={{ fontSize: 18, flexShrink: 0 }}>{emoji}</span>
      <div style={{ flex: 1 }}>
        <span style={{ fontSize: 13, fontWeight: 700, color }}>{latest.rule_name}</span>
        <span style={{ fontSize: 12, color: 'var(--text-secondary)', marginLeft: 10 }}>
          {latest.message}
        </span>
        {alerts.length > 1 && (
          <span style={{ fontSize: 11, color: 'var(--text-muted)', marginLeft: 8 }}>
            +{alerts.length - 1} more
          </span>
        )}
      </div>
      <span style={{ fontSize: 11, color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>
        {new Date(latest.fired_at).toLocaleTimeString()}
      </span>
      <button onClick={() => setVisible(false)}
        style={{ background: 'none', border: 'none', cursor: 'pointer', color, fontSize: 16, padding: '0 4px', flexShrink: 0 }}>
        ×
      </button>
    </div>
  );
}

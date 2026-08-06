'use client';
import { useState, useRef, useEffect, useMemo } from 'react';

interface Props {
  hours: number;
  onHoursChange: (hours: number) => void;
  refreshInterval: number;
  onRefreshChange: (seconds: number) => void;
  onRefreshNow: () => void;
}

const PRESETS = [
  { label: '15m', value: 0.25 },
  { label: '1h',  value: 1    },
  { label: '6h',  value: 6    },
  { label: '24h', value: 24   },
  { label: '48h', value: 48   },
  { label: '7d',  value: 168  },
  { label: '30d', value: 720  },
];

export default function TimeRangePicker({ hours, onHoursChange, refreshInterval, onRefreshChange, onRefreshNow }: Props) {
  const [showCustom, setShowCustom] = useState(false);
  const [countdown,  setCountdown]  = useState(refreshInterval);
  const ref = useRef<HTMLDivElement>(null);

  // Memoize quick picks so Date objects aren't created on every render
  const quickPicks = useMemo(() => {
    const now = new Date();
    return [
      { label: 'Last 15 minutes', hours: 0.25 },
      { label: 'Last 30 minutes', hours: 0.5  },
      { label: 'Last 2 hours',    hours: 2    },
      { label: 'Last 4 hours',    hours: 4    },
      { label: 'Last 12 hours',   hours: 12   },
      { label: 'Since midnight',  hours: now.getHours() + now.getMinutes() / 60 },
      { label: 'Yesterday',       hours: 48   },
      { label: 'This week',       hours: now.getDay() * 24 },
    ];
  }, [showCustom]); // Only recalculate when dropdown opens

  // The auto-refresh tick must call the CURRENT onRefreshNow, not the one that
  // happened to exist when the interval was created. This effect deliberately
  // depends only on `refreshInterval` (adding onRefreshNow would restart the
  // countdown every time the parent re-created its callback), so without this
  // ref the interval closes over a stale callback for its whole life.
  //
  // That was harmless while callers passed a fetch-everything function whose
  // identity only changed with `hours`. It stopped being harmless in 2.31.1,
  // when SecurityAnalysis's refresh became section-aware: the stale closure
  // then refreshed whichever section was open when the timer started, so
  // sitting on IPS/Threats quietly re-fetched Overview's data every 30s.
  const refreshRef = useRef(onRefreshNow);
  refreshRef.current = onRefreshNow;

  useEffect(() => {
    setCountdown(refreshInterval);
    const t = setInterval(() => {
      setCountdown(c => {
        // queueMicrotask keeps the fetch out of the state updater — an updater
        // must stay pure, and React may invoke it more than once.
        if (c <= 1) { queueMicrotask(() => refreshRef.current()); return refreshInterval; }
        return c - 1;
      });
    }, 1000);
    return () => clearInterval(t);
  }, [refreshInterval]);

  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setShowCustom(false);
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, []);

  const pct = ((refreshInterval - countdown) / refreshInterval) * 100;

  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }} ref={ref}>
      {/* Refresh interval */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 4,
        background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)', padding: '4px 8px' }}>
        <svg width="16" height="16" viewBox="0 0 16 16" style={{ flexShrink: 0 }}>
          <circle cx="8" cy="8" r="6" fill="none" stroke="var(--border)" strokeWidth="2"/>
          <circle cx="8" cy="8" r="6" fill="none" stroke="#2563eb" strokeWidth="2"
            strokeDasharray={`${pct * 0.377} 37.7`}
            strokeLinecap="round" transform="rotate(-90 8 8)"
            style={{ transition: 'stroke-dasharray 1s linear' }}/>
        </svg>
        {[10, 30, 60, 300].map(s => (
          <button key={s} onClick={() => onRefreshChange(s)}
            style={{ padding: '3px 7px', borderRadius: 'var(--radius-sm)', border: 'none', fontSize: 'var(--text-xs)', cursor: 'pointer',
              fontWeight: refreshInterval === s ? 600 : 400,
              background: refreshInterval === s ? '#1a202c' : 'transparent',
              color: refreshInterval === s ? '#fff' : 'var(--text-muted)' }}>
            {s < 60 ? `${s}s` : `${s/60}m`}
          </button>
        ))}
        <button onClick={onRefreshNow}
          style={{ padding: '3px 7px', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border)',
            cursor: 'pointer', fontSize: 'var(--text-xs)', background: 'var(--bg-input)',
            color: 'var(--text-secondary)', marginLeft: 2 }}>
          Now
        </button>
      </div>

      {/* Time range presets */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 3, position: 'relative',
        background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)', padding: '4px 6px' }}>
        <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginRight: 2 }}>Range</span>
        {PRESETS.map(p => (
          <button key={p.value} onClick={() => { onHoursChange(p.value); setShowCustom(false); }}
            style={{ padding: '3px 8px', borderRadius: 'var(--radius-sm)', border: 'none', fontSize: 'var(--text-xs)', cursor: 'pointer',
              fontWeight: hours === p.value ? 600 : 400,
              background: hours === p.value ? '#1a202c' : 'transparent',
              color: hours === p.value ? '#fff' : 'var(--text-muted)' }}>
            {p.label}
          </button>
        ))}
        <button onClick={() => setShowCustom(s => !s)}
          style={{ padding: '3px 8px', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border)',
            fontSize: 'var(--text-xs)', cursor: 'pointer', background: 'var(--bg-input)',
            color: 'var(--text-secondary)', display: 'flex', alignItems: 'center', gap: 4 }}>
          <svg width="10" height="10" viewBox="0 0 10 10" fill="none">
            <rect x="1" y="1" width="8" height="8" rx="1" stroke="currentColor" strokeWidth="1.2" fill="none"/>
            <line x1="3" y1="3.5" x2="7" y2="3.5" stroke="currentColor" strokeWidth="1"/>
            <line x1="3" y1="5.5" x2="6" y2="5.5" stroke="currentColor" strokeWidth="1"/>
          </svg>
          Custom
        </button>

        {/* Custom dropdown */}
        {showCustom && (
          <div style={{ position: 'absolute', top: 34, right: 0, zIndex: 200,
            background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 'var(--radius)',
            padding: 16, boxShadow: '0 1px 3px rgba(0,0,0,0.06)', minWidth: 260 }}>
            <div style={{ fontSize: 'var(--text-sm)', fontWeight: 600, color: 'var(--text-primary)', marginBottom: 10 }}>
              Quick Ranges
            </div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
              {quickPicks.map(q => (
                <button key={q.label}
                  onClick={() => { onHoursChange(Math.max(q.hours, 0.1)); setShowCustom(false); }}
                  style={{ padding: '5px 10px', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border)',
                    fontSize: 'var(--text-xs)', cursor: 'pointer', background: 'var(--bg-input)',
                    color: 'var(--text-secondary)', transition: 'all 0.15s' }}
                  onMouseEnter={e => { (e.currentTarget as HTMLElement).style.background = 'var(--bg-hover)'; (e.currentTarget as HTMLElement).style.color = 'var(--text-primary)'; }}
                  onMouseLeave={e => { (e.currentTarget as HTMLElement).style.background = 'var(--bg-input)'; (e.currentTarget as HTMLElement).style.color = 'var(--text-secondary)'; }}>
                  {q.label}
                </button>
              ))}
            </div>
            <button onClick={() => setShowCustom(false)}
              style={{ width: '100%', marginTop: 12, padding: '6px', borderRadius: 'var(--radius-sm)',
                border: '1px solid var(--border)', cursor: 'pointer', fontSize: 'var(--text-xs)',
                background: 'var(--bg-input)', color: 'var(--text-secondary)' }}>
              Close
            </button>
          </div>
        )}
      </div>
    </div>
  );
}

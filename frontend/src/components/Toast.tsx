'use client';
import { createContext, useContext, useState, useCallback } from 'react';

type ToastType = 'success' | 'error' | 'warning' | 'info';
interface Toast { id: number; message: string; type: ToastType; }

const ToastContext = createContext<{ toast: (message: string, type?: ToastType) => void }>({ toast: () => {} });

let toastId = 0;
const MAX_TOASTS = 5;

export function ToastProvider({ children }: { children: React.ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);

  const toast = useCallback((message: string, type: ToastType = 'info') => {
    const id = ++toastId;
    setToasts(prev => {
      // Cap at MAX_TOASTS — drop oldest if exceeded
      const next = [...prev, { id, message, type }];
      return next.slice(-MAX_TOASTS);
    });
    setTimeout(() => setToasts(prev => prev.filter(t => t.id !== id)), 3500);
  }, []);

  const ICONS: Record<ToastType, string> = { success: '✓', error: '✕', warning: '⚠', info: 'ℹ' };
  const COLORS: Record<ToastType, { bg: string; border: string; color: string }> = {
    success: { bg: 'var(--tint-success)', border: 'var(--tint-success)', color: 'var(--tint-success-fg)' },
    error:   { bg: 'var(--tint-danger)',  border: 'var(--tint-danger)',  color: 'var(--tint-danger-fg)' },
    warning: { bg: 'var(--tint-warn)',    border: 'var(--tint-warn)',    color: 'var(--tint-warn-fg)' },
    info:    { bg: 'var(--tint-info)',     border: 'var(--tint-info)',     color: 'var(--tint-info-fg)' },
  };

  return (
    <ToastContext.Provider value={{ toast }}>
      {children}
      <div style={{ position: 'fixed', bottom: 20, right: 20, zIndex: 9999,
        display: 'flex', flexDirection: 'column', gap: 8 }}>
        {toasts.map(t => {
          const c = COLORS[t.type];
          return (
            <div key={t.id} style={{ display: 'flex', alignItems: 'center', gap: 10,
              background: c.bg, border: `1px solid ${c.border}`, borderRadius: 'var(--radius)',
              padding: '10px 16px', boxShadow: '0 4px 12px rgba(0,0,0,0.1)',
              animation: 'fadeIn 0.2s ease', fontSize: 'var(--text-base)', color: c.color,
              minWidth: 260, maxWidth: 380 }}>
              <span style={{ fontWeight: 700, fontSize: 'var(--text-md)' }}>{ICONS[t.type]}</span>
              <span style={{ color: 'var(--text-primary)', flex: 1 }}>{t.message}</span>
              <button onClick={() => setToasts(prev => prev.filter(x => x.id !== t.id))}
                style={{ background: 'none', border: 'none', cursor: 'pointer',
                  color: 'var(--text-muted)', fontSize: 'var(--text-md)', padding: 0 }}>
                ×
              </button>
            </div>
          );
        })}
      </div>
    </ToastContext.Provider>
  );
}

export const useToast = () => useContext(ToastContext);

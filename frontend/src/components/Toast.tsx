'use client';
import { createContext, useContext, useState, useCallback, useEffect } from 'react';

type ToastType = 'success' | 'error' | 'warning' | 'info';
interface Toast { id: number; message: string; type: ToastType; }

const ToastContext = createContext<{ toast: (message: string, type?: ToastType) => void }>({ toast: () => {} });

let toastId = 0;

export function ToastProvider({ children }: { children: React.ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);

  const toast = useCallback((message: string, type: ToastType = 'info') => {
    const id = ++toastId;
    setToasts(prev => [...prev, { id, message, type }]);
    setTimeout(() => setToasts(prev => prev.filter(t => t.id !== id)), 3500);
  }, []);

  const ICONS: Record<ToastType, string> = { success: '✓', error: '✕', warning: '⚠', info: 'ℹ' };
  const COLORS: Record<ToastType, { bg: string; border: string; color: string }> = {
    success: { bg: '#f0fdf4', border: '#bbf7d0', color: '#16a34a' },
    error:   { bg: '#fef2f2', border: '#fecaca', color: '#dc2626' },
    warning: { bg: '#fefce8', border: '#fde68a', color: '#ca8a04' },
    info:    { bg: '#eff6ff', border: '#bfdbfe', color: '#2563eb' },
  };

  return (
    <ToastContext.Provider value={{ toast }}>
      {children}
      <div style={{ position: 'fixed', bottom: 20, right: 20, zIndex: 9999, display: 'flex', flexDirection: 'column', gap: 8 }}>
        {toasts.map(t => {
          const c = COLORS[t.type];
          return (
            <div key={t.id} style={{ display: 'flex', alignItems: 'center', gap: 10,
              background: c.bg, border: `1px solid ${c.border}`, borderRadius: 8,
              padding: '10px 16px', boxShadow: '0 4px 12px rgba(0,0,0,0.1)',
              animation: 'fadeIn 0.2s ease', fontSize: 13, color: c.color, minWidth: 260, maxWidth: 380 }}>
              <span style={{ fontWeight: 700, fontSize: 14 }}>{ICONS[t.type]}</span>
              <span style={{ color: 'var(--text-primary)', flex: 1 }}>{t.message}</span>
              <button onClick={() => setToasts(prev => prev.filter(x => x.id !== t.id))}
                style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)', fontSize: 14, padding: 0 }}>
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

'use client';
import { Suspense, useEffect } from 'react';
import { signIn } from 'next-auth/react';
import { useSearchParams } from 'next/navigation';

const HUB_URL = process.env.NEXT_PUBLIC_NOCVAULT_HUB_URL || 'http://localhost:3000';

function SSOHandler() {
  const params = useSearchParams();

  useEffect(() => {
    const token = params.get('token');
    if (!token) {
      window.location.href = `${HUB_URL}/login`;
      return;
    }
    signIn('credentials', { ssoToken: token, redirect: false }).then(result => {
      if (result?.ok) {
        window.location.href = '/';
      } else {
        window.location.href = `${HUB_URL}/login?error=sso_failed`;
      }
    });
  }, [params]);

  return null;
}

function Spinner() {
  return (
    <div style={{ minHeight: '100vh', display: 'flex', alignItems: 'center',
      justifyContent: 'center', background: '#0f172a', fontFamily: 'Inter, system-ui, sans-serif' }}>
      <div style={{ textAlign: 'center', color: '#94a3b8' }}>
        <div style={{ width: 40, height: 40, border: '3px solid #334155',
          borderTop: '3px solid #3b82f6', borderRadius: '50%', margin: '0 auto 16px',
          animation: 'spin 1s linear infinite' }} />
        <div style={{ fontSize: 'var(--text-md)', fontWeight: 500 }}>Signing in to LogVault...</div>
        <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
      </div>
    </div>
  );
}

export default function SSOPage() {
  return (
    <Suspense fallback={<Spinner />}>
      <Spinner />
      <SSOHandler />
    </Suspense>
  );
}

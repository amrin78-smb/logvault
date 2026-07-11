import { NextRequest } from 'next/server';

// A cross-app redirect target (the NocVault hub URL) used to be built from a
// static install-time env var (NOCVAULT_HUB_URL / NEXT_PUBLIC_NOCVAULT_HUB_URL)
// baked in at install time to the literal server IP — so it always pointed at
// the original install IP no matter what hostname the browser actually used (a
// customer's own local-DNS name, for instance). resolveOrigin() derives the
// correct origin from the CURRENT request instead, so it follows whatever
// hostname is in use. Mirrors netvault's lib/publicUrl.ts (the opposite hub→app
// direction) — duplicated here rather than shared since the two repos don't
// share code.
//
// x-forwarded-host/-proto are checked first for reverse-proxy deployments (the
// app itself would otherwise only see the proxy's own local host/scheme); a
// lightweight hostname-shape check guards against a malformed/unexpected header
// value before it's used to build a redirect URL — not a security allowlist,
// just input validation. Falls back to the legacy static env var if the request
// doesn't carry a usable Host — never worse than today's behavior.
const HOSTNAME_RE = /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;

export function resolveOrigin(req: NextRequest, port: number | null, legacyFallback: string): string {
  const rawHost = req.headers.get('x-forwarded-host') || req.headers.get('host') || '';
  const hostname = rawHost.split(':')[0].trim();
  const proto = (req.headers.get('x-forwarded-proto') || req.nextUrl.protocol.replace(':', '') || 'http')
    .split(',')[0]
    .trim();

  if (hostname && hostname.length <= 253 && HOSTNAME_RE.test(hostname) && (proto === 'http' || proto === 'https')) {
    return `${proto}://${hostname}${port ? ':' + port : ''}`;
  }
  return legacyFallback;
}

// Client-side counterpart used by 'use client' components — derives the hub
// origin from window.location (so it follows whatever hostname the browser is
// actually using) instead of the install-time NEXT_PUBLIC_NOCVAULT_HUB_URL
// bake-in. Guarded for the server-render pass of a 'use client' component
// (window is undefined there), falling back to the same static env var.
// NetVault always runs on port 3000, regardless of this app's own port.
export function getHubUrl(): string {
  if (typeof window !== 'undefined') {
    return `${window.location.protocol}//${window.location.hostname}:3000`;
  }
  return process.env.NEXT_PUBLIC_NOCVAULT_HUB_URL || 'http://localhost:3000';
}

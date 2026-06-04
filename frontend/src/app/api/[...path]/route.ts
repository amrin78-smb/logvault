// Authenticated API proxy → Express API (port 3005).
//
// All browser /api/* calls (except /api/auth/* which is handled by the more
// specific next-auth route) flow through here. We read the NextAuth session
// server-side — where next-auth can decrypt its own JWE session cookie — and
// forward the user's id and role to the Express API as X-User-Id / X-User-Role
// headers. Express enforces RBAC from those headers (see api/rbac.js).
//
// This replaces the previous next.config.js rewrite, which could not attach
// per-request session headers.

import { getServerSession } from 'next-auth/next';
import { authOptions } from '@/auth';
import { NextRequest, NextResponse } from 'next/server';

// Never cache proxied API responses — they are per-user and live data.
export const dynamic = 'force-dynamic';

const API_BASE = process.env.LV_API_URL || 'http://localhost:3005';

export async function GET(req: NextRequest, ctx: { params: Promise<{ path: string[] }> }) {
  return proxyRequest(req, ctx, 'GET');
}
export async function POST(req: NextRequest, ctx: { params: Promise<{ path: string[] }> }) {
  return proxyRequest(req, ctx, 'POST');
}
export async function PUT(req: NextRequest, ctx: { params: Promise<{ path: string[] }> }) {
  return proxyRequest(req, ctx, 'PUT');
}
export async function PATCH(req: NextRequest, ctx: { params: Promise<{ path: string[] }> }) {
  return proxyRequest(req, ctx, 'PATCH');
}
export async function DELETE(req: NextRequest, ctx: { params: Promise<{ path: string[] }> }) {
  return proxyRequest(req, ctx, 'DELETE');
}

async function proxyRequest(
  req: NextRequest,
  ctx: { params: Promise<{ path: string[] }> },
  method: string
) {
  const { path } = await ctx.params;
  const session = await getServerSession(authOptions);

  const user = (session?.user as { id?: string; role?: string } | undefined) || undefined;
  const qs = req.nextUrl.searchParams.toString();
  const targetUrl = `${API_BASE}/api/${path.join('/')}${qs ? '?' + qs : ''}`;

  const headers: Record<string, string> = {
    'Content-Type': req.headers.get('content-type') || 'application/json',
    'X-User-Id':   String(user?.id   ?? '0'),
    'X-User-Role': String(user?.role ?? 'user'),
  };

  const body = method !== 'GET' && method !== 'HEAD' ? await req.text() : undefined;

  let response: Response;
  try {
    response = await fetch(targetUrl, { method, headers, body, cache: 'no-store' });
  } catch (err) {
    console.error('[API Proxy] Upstream fetch failed:', (err as Error).message);
    return NextResponse.json({ error: 'Upstream API unavailable' }, { status: 502 });
  }

  const data = await response.arrayBuffer();

  // Forward content type + any download disposition (e.g. CSV export).
  const outHeaders: Record<string, string> = {
    'Content-Type': response.headers.get('content-type') || 'application/json',
  };
  const disposition = response.headers.get('content-disposition');
  if (disposition) outHeaders['Content-Disposition'] = disposition;

  return new NextResponse(data, { status: response.status, headers: outHeaders });
}

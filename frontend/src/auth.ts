import NextAuth, { NextAuthOptions } from 'next-auth';
import CredentialsProvider from 'next-auth/providers/credentials';
import { Pool } from 'pg';
import bcrypt from 'bcryptjs';

// Fail fast if the shared SSO secret is not provided by the environment
// (NSSM AppEnvironmentExtra in prod, .env.local in dev). Never fall back to a
// baked-in literal — that would let a leaked default forge sessions.
// Skip during `next build` (page-data collection runs with no runtime env);
// the check still fires when the server actually boots.
if (!process.env.NEXTAUTH_SECRET && process.env.NEXT_PHASE !== 'phase-production-build') {
  throw new Error('NEXTAUTH_SECRET is not set — provide it via NSSM env / .env.local');
}

// Connect to netvault DB for shared user authentication.
// Secrets (DB password) come from the environment only — no hardcoded fallback.
const netvaultPool = new Pool({
  host:     process.env.NETVAULT_DB_HOST     || 'localhost',
  port:     parseInt(process.env.NETVAULT_DB_PORT || '5432'),
  database: process.env.NETVAULT_DB_NAME     || 'netvault',
  user:     process.env.NETVAULT_DB_USER     || 'netvault',
  password: process.env.NETVAULT_DB_PASS,
  ssl:      false,
  max:      3,
});

// Resolve the allowed-apps claim for the direct email/password login path from the
// SAME source the SSO path's issuer (NetVault) uses — the `user_apps` table — so both
// login paths produce a consistent, correctly-enforced `apps` claim instead of the
// credentials path silently granting unrestricted access. Mirrors the semantics of
// netvault's lib/appAccess.ts: super_admin and an existing user with zero rows both
// mean full access (return undefined — proxy.ts's appAllowed() treats no claim as
// allow-all, matching legacy tokens). A DB error must FAIL CLOSED, not open — but
// appAllowed() treats an EMPTY apps array the same as "no claim" (allow-all), so a
// closed failure can't be represented as `[]` here; instead resolve to a non-empty
// sentinel array containing no real app slug, so appAllowed()'s `apps.includes(slug)`
// check denies every app (netvault itself stays allowed — that check runs before the
// apps check in proxy.ts).
const DB_ERROR_DENY_ALL_APPS = ['__db_error_deny_all__'];

async function resolveDirectLoginApps(userId: string, role: string): Promise<string[] | undefined> {
  if (role === 'super_admin') return undefined; // full access, no query needed
  try {
    const { rows } = await netvaultPool.query('SELECT app FROM user_apps WHERE user_id = $1', [userId]);
    if (rows.length === 0) return undefined; // existing user, no rows = full access (legacy/default-all)
    return rows.map((r: any) => r.app);
  } catch (err) {
    console.error('[Auth] user_apps lookup failed for direct login, failing closed:', err);
    return DB_ERROR_DENY_ALL_APPS;
  }
}

export const authOptions: NextAuthOptions = {
  secret: process.env.NEXTAUTH_SECRET,

  providers: [
    CredentialsProvider({
      name: 'NocVault',
      credentials: {
        email:    { label: 'Email',    type: 'email' },
        password: { label: 'Password', type: 'password' },
        // SSO token passed from NetVault launcher
        ssoToken: { label: 'SSO Token', type: 'text' },
      },
      async authorize(credentials) {
        if (!credentials) return null;

        // ── SSO path: token passed from NetVault ──────────────
        if (credentials.ssoToken) {
          try {
            const { verify } = await import('jsonwebtoken');
            const payload = verify(
              credentials.ssoToken,
              process.env.NEXTAUTH_SECRET!
            ) as any;
            if (payload?.userId) {
              const { rows } = await netvaultPool.query(
                'SELECT id, name, email, role FROM users WHERE id = $1',
                [payload.userId]
              );
              if (rows.length > 0) {
                // Carry the allowed-apps claim from the incoming SSO token so
                // proxy.ts can gate per-user app access. `apps` is a string[] of
                // slugs (e.g. ["netvault","logvault"]); absent/empty = default-all.
                return {
                  id: String(rows[0].id),
                  name: rows[0].name,
                  email: rows[0].email,
                  role: rows[0].role,
                  apps: Array.isArray(payload.apps) ? payload.apps : undefined,
                };
              }
            }
          } catch {
            return null;
          }
        }

        // ── Credentials path: direct login ────────────────────
        if (!credentials.email || !credentials.password) return null;

        try {
          const { rows } = await netvaultPool.query(
            'SELECT id, name, email, password_hash, role FROM users WHERE email = $1',
            [credentials.email.toLowerCase().trim()]
          );
          if (rows.length === 0) return null;

          const user = rows[0];
          const valid = await bcrypt.compare(credentials.password, user.password_hash);
          if (!valid) return null;

          // Resolve the allowed-apps claim here too (see resolveDirectLoginApps) —
          // this path must be gated exactly like the SSO path, not left to the
          // fail-open "no claim = default-all" behavior in appAllowed()/jwt().
          const apps = await resolveDirectLoginApps(String(user.id), user.role);
          return { id: String(user.id), name: user.name, email: user.email, role: user.role, apps };
        } catch (err) {
          console.error('[Auth] DB error:', err);
          return null;
        }
      },
    }),
  ],

  callbacks: {
    async jwt({ token, user }) {
      if (user) {
        token.id   = user.id;
        token.role = (user as any).role;
        // Persist the allowed-apps claim into LogVault's own JWT so proxy.ts
        // (getToken) can enforce per-user app access. Only set when present on
        // the SSO login so older tokens (no claim) stay default-all.
        if (Array.isArray((user as any).apps)) {
          (token as any).apps = (user as any).apps;
        }
      }
      return token;
    },
    async session({ session, token }) {
      if (session.user) {
        (session.user as any).id   = token.id;
        (session.user as any).role = token.role;
        (session.user as any).apps = (token as any).apps;
      }
      return session;
    },
  },

  pages: {
    // Redirect to NetVault hub for login — no separate LogVault login page
    signIn: `${process.env.NOCVAULT_HUB_URL || 'http://localhost:3000'}/login`,
    error:  `${process.env.NOCVAULT_HUB_URL || 'http://localhost:3000'}/login`,
  },

  session: {
    strategy:  'jwt',
    maxAge:    8 * 60 * 60, // 8 hours
  },

  cookies: {
    sessionToken: {
      name: 'nexvault.session-token',
      options: {
        httpOnly: true,
        sameSite: 'lax',
        path:     '/',
        // Secure cookies only when served over HTTPS — derived from NEXTAUTH_URL
        // so the current HTTP deployment keeps working and HTTPS auto-enables it.
        secure:   (process.env.NEXTAUTH_URL || '').startsWith('https'),
      },
    },
  },
};

const handler = NextAuth(authOptions);
export { handler as GET, handler as POST };

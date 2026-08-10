import NextAuth, { NextAuthOptions } from 'next-auth';
import CredentialsProvider from 'next-auth/providers/credentials';
import { Pool } from 'pg';

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

        // Direct email/password is NOT supported — LogVault has no login UI, and
        // the hub is the suite's single authentication point.
        //
        // This used to bcrypt-compare against netvault.users.password_hash right
        // here, which made LogVault a second front door into the hub's own user
        // table. Nothing in this app ever used it: there is no login page, and
        // the only signIn('credentials') call site is /sso, which passes an
        // ssoToken. It was reachable solely by POSTing directly to
        // /api/auth/callback/credentials — so it added no capability for a user
        // and one whole bypass route for everyone else.
        //
        // It has to stay closed. Any authentication policy the hub enforces
        // (MFA being the immediate reason, but equally password rotation,
        // lockout, or an IdP migration) is enforced in NetVault's authorize().
        // A second password path here silently opts out of all of it, and would
        // do so while the hub reported the policy as active.
        //
        // Matches SpanVault, which has always returned null here.
        return null;
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

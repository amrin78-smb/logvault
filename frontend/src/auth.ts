import NextAuth, { NextAuthOptions } from 'next-auth';
import CredentialsProvider from 'next-auth/providers/credentials';
import { Pool } from 'pg';
import bcrypt from 'bcryptjs';

// Connect to netvault DB for shared user authentication
const netvaultPool = new Pool({
  host:     process.env.NETVAULT_DB_HOST     || 'localhost',
  port:     parseInt(process.env.NETVAULT_DB_PORT || '5432'),
  database: process.env.NETVAULT_DB_NAME     || 'netvault',
  user:     process.env.NETVAULT_DB_USER     || 'netvault',
  password: process.env.NETVAULT_DB_PASS     || 'PgAdmin@2026!',
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
                return { id: String(rows[0].id), name: rows[0].name, email: rows[0].email, role: rows[0].role };
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

          return { id: String(user.id), name: user.name, email: user.email, role: user.role };
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
      }
      return token;
    },
    async session({ session, token }) {
      if (session.user) {
        (session.user as any).id   = token.id;
        (session.user as any).role = token.role;
      }
      return session;
    },
  },

  pages: {
    // Redirect to NetVault hub for login — no separate LogVault login page
    signIn: `${process.env.NETVAULT_HUB_URL || 'http://192.168.6.111:3000'}/login`,
    error:  `${process.env.NETVAULT_HUB_URL || 'http://192.168.6.111:3000'}/login`,
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
        secure:   false, // HTTP on local network
      },
    },
  },
};

const handler = NextAuth(authOptions);
export { handler as GET, handler as POST };

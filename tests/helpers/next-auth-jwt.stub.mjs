//
// tests/helpers/next-auth-jwt.stub.mjs — stands in for `next-auth/jwt` so the
// page gate in frontend/src/proxy.ts can be called without a real encrypted
// session cookie or NEXTAUTH_SECRET.
//
// Only `getToken` is used by proxy.ts. The tests that matter here are all
// "getToken returned null" cases — the whole point of the guard under test is
// what the gate does WHEN IT CANNOT READ A TOKEN — so null is the default, and
// `__setToken` exists for the authenticated case.
//
let nextToken = null;

export function __setToken(token) {
  nextToken = token;
}

export async function getToken() {
  return nextToken;
}

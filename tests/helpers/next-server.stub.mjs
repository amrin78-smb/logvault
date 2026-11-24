//
// tests/helpers/next-server.stub.mjs — the smallest honest stand-in for
// `next/server`, so a frontend route handler and the page gate in proxy.ts can
// be LOADED AND CALLED by `node --test` with no Next.js runtime.
//
// ⛔ WHY A STUB IS NEEDED AT ALL: `next` lives under `frontend/`, and `next`
// ships no `exports` map, so a bare ESM `import 'next/server'` cannot resolve
// outside the bundler (`ERR_MODULE_NOT_FOUND` on an extensionless path). The
// alternative was to keep editing `publicUrl.ts`'s import out of the source at
// load time, which hid the real module graph; this resolves the specifier
// instead, so every file under test is loaded exactly as written.
//
// `redirect` delegates to the WHATWG `Response.redirect`, which is what Next's
// own implementation ultimately produces — so an asserted `status` /
// `location` is the real one and not an invention of this file.
//

export class NextRequest {}

export const NextResponse = {
  redirect(url, status = 307) {
    return Response.redirect(String(url), status);
  },
  json(body, init) {
    return Response.json(body, init);
  },
  next() {
    return new Response(null, { status: 200, headers: { 'x-stub': 'next' } });
  },
  rewrite(url, init) {
    return new Response(null, {
      status: 200,
      headers: { 'x-stub': 'rewrite', 'x-rewrite-target': String(url) },
      ...(init && {}),
    });
  },
};

// pages-passcode-gate: a fail-closed passcode gate for Cloudflare Pages.
//
// Runs as Pages Functions middleware on every request (static files included). Without a valid session cookie nothing
// of the site is served, only a small neutral passcode page (401). If the PASSCODE secret is unset or too short, or
// anything throws, everything is denied.
//
// The session cookie holds HMAC-SHA256(PASSCODE, sessionLabel): changing the passcode logs every device out, and the
// cookie never contains the passcode itself.
//
// Optional "neutral install files" (on by default): iOS's "Add to Home Screen" fetches the web app manifest and icons
// without cookies, so a gated manifest would fail. Files under /_n/ are public, and /manifest.webmanifest and
// /icons/<name>.png answer with /_n/manifest.webmanifest and /_n/<name>.png before login (the real ones after), so a
// site can be installed as a home-screen app without its name or art leaking to people without the passcode.

export interface GateEnv {
  PASSCODE?: string;
  ASSETS?: { fetch(input: Request | string | URL, init?: RequestInit): Promise<Response> };
}

export interface GateContext {
  request: Request;
  env: GateEnv;
  next(input?: Request | string, init?: RequestInit): Promise<Response>;
}

export interface GateOptions {
  /** The passcode page's <title>. Keep it neutral: it is visible to everyone. Default "Private". */
  title?: string;
  /** Mixed into the session token; change it to log every device out without changing the passcode. */
  sessionLabel?: string;
  /** Serve the public /_n/ install files (manifest and icons) before login. Default true. */
  neutralInstallFiles?: boolean;
  /** Logged-in responses under this path prefix are cached as immutable (hashed build files). Default "/assets/"; "" turns it off. */
  immutablePrefix?: string;
  /** Answer a missing file with a real 404 instead of Pages' single-page-app fallback (index.html, 200). Default true. */
  missingFiles404?: boolean;
  /** Minimum delay before answering a wrong passcode, in ms (plus up to 500 ms of jitter). Default 1500. */
  wrongDelayMs?: number;
}

export const COOKIE = "__Host-session";
export const LOGIN_PATH = "/__gate";
export const LOGOUT_PATH = "/__gate/logout";
/** Passcodes shorter than this are treated as unset (deny everything). */
export const MIN_PASSCODE = 8;
/** 400 days, the longest a browser keeps a cookie. */
const COOKIE_MAX_AGE = 400 * 24 * 3600;
const DEFAULTS: Required<GateOptions> = {
  title: "Private",
  sessionLabel: "pages-passcode-gate-v1",
  neutralInstallFiles: true,
  immutablePrefix: "/assets/",
  missingFiles404: true,
  wrongDelayMs: 1500,
};

const ROBOTS = "User-agent: *\nDisallow: /\n";

// Headers on every response, passcode page or site.
const COMMON: Record<string, string> = {
  "X-Robots-Tag": "noindex, nofollow, noarchive, nosnippet, noimageindex",
  "Referrer-Policy": "no-referrer",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
};

const enc = new TextEncoder();

async function sha256(s: string): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(s)));
}

/** Constant-time comparison of two strings (compares their SHA-256 digests, so lengths don't leak). */
export async function safeEqual(a: string, b: string): Promise<boolean> {
  const [x, y] = await Promise.all([sha256(a), sha256(b)]);
  let d = 0;
  for (let i = 0; i < x.length; i++) d |= x[i]! ^ y[i]!;
  return d === 0;
}

function b64url(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** The session token for a passcode: HMAC-SHA256(passcode, label), base64url. */
export async function sessionToken(passcode: string, label = DEFAULTS.sessionLabel): Promise<string> {
  const key = await crypto.subtle.importKey("raw", enc.encode(passcode), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return b64url(new Uint8Array(await crypto.subtle.sign("HMAC", key, enc.encode(label))));
}

function readCookie(req: Request, name: string): string | null {
  const header = req.headers.get("Cookie");
  if (!header) return null;
  for (const part of header.split(";")) {
    const i = part.indexOf("=");
    if (i > 0 && part.slice(0, i).trim() === name) return part.slice(i + 1).trim();
  }
  return null;
}

function passcodeOf(env: GateEnv): string | null {
  const p = typeof env.PASSCODE === "string" ? env.PASSCODE : "";
  return p.length >= MIN_PASSCODE ? p : null;
}

function withHeaders(res: Response, extra: Record<string, string>): Response {
  const out = new Response(res.body, res);
  for (const [k, v] of Object.entries({ ...COMMON, ...extra })) out.headers.set(k, v);
  // Pages adds "Access-Control-Allow-Origin: *" to static files; nothing behind the gate is for other sites.
  out.headers.delete("Access-Control-Allow-Origin");
  return out;
}

const escapeHtml = (s: string) => s.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);

/** Only same-site paths are followed after login. */
export function safeNext(next: string | null | undefined): string {
  if (!next || !next.startsWith("/") || next.startsWith("//") || next.startsWith("/\\") || next.startsWith(LOGIN_PATH)) return "/";
  return next;
}

/** The neutral passcode page: no site name, no art. */
export function gatePage(next: string, message = "", status = 401, title = DEFAULTS.title): Response {
  const html = `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="robots" content="noindex, nofollow, noarchive">
<meta name="referrer" content="no-referrer">
<title>${escapeHtml(title)}</title>
<style>
html,body{margin:0;height:100%;background:#16191d;color:#e8eaed;font:16px -apple-system,system-ui,sans-serif}
main{min-height:100%;display:grid;place-items:center;padding:24px;box-sizing:border-box}
form{width:100%;max-width:320px;display:grid;gap:12px}
input,button{font:inherit;padding:12px 14px;border-radius:10px;border:1px solid #3a3f45;background:#22262b;color:inherit}
button{background:#3b6fd8;border-color:#3b6fd8;color:#fff}
p{margin:0;color:#ff8a80;min-height:1.2em;font-size:14px}
.u{position:absolute;left:-9999px}
</style></head>
<body><main><form method="post" action="${LOGIN_PATH}">
<input class="u" type="text" name="u" value="me" autocomplete="username" tabindex="-1" aria-hidden="true">
<input type="password" name="passcode" placeholder="Passcode" autocomplete="current-password" required autofocus aria-label="Passcode">
<input type="hidden" name="next" value="${escapeHtml(next)}">
<button type="submit">Continue</button>
<p role="alert">${escapeHtml(message)}</p>
</form></main></body></html>`;
  return withHeaders(new Response(html, { status }), {
    "Content-Type": "text/html; charset=utf-8",
    "Cache-Control": "no-store",
    "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
  });
}

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

/** The neutral variant of a public install file, or null if the path has none. */
function neutralPath(path: string): string | null {
  if (path === "/manifest.webmanifest") return "/_n/manifest.webmanifest";
  const m = /^\/icons\/([A-Za-z0-9-]+\.png)$/.exec(path);
  return m ? `/_n/${m[1]}` : null;
}

/** A path that names a file (its last segment has an extension), not a page. */
export function isFilePath(path: string): boolean {
  const last = path.slice(path.lastIndexOf("/") + 1);
  return /\.[A-Za-z0-9]+$/.test(last) && !/\.html?$/i.test(last);
}

/** Whether the static answer for `path` means the file isn't in this deployment (a 404, or the SPA fallback page). */
export function isMissingFile(path: string, res: Response): boolean {
  if (!isFilePath(path)) return false;
  if (res.status === 404) return true;
  return /^text\/html\b/i.test(res.headers.get("Content-Type") ?? "");
}

/** Builds the gate. `createGate(options)(ctx)` answers one request; it may throw (onRequest below fails closed). */
export function createGate(options: GateOptions = {}) {
  const o: Required<GateOptions> = { ...DEFAULTS, ...options };
  const page = (next: string, message = "", status = 401) => gatePage(next, message, status, o.title);

  async function serveNeutral(ctx: GateContext, path: string): Promise<Response> {
    const url = new URL(path, ctx.request.url);
    const req = new Request(url, { method: "GET" });
    const res = ctx.env.ASSETS ? await ctx.env.ASSETS.fetch(req) : await ctx.next(req);
    if (!res.ok || isMissingFile(path, res)) return page("/");
    return withHeaders(res, { "Cache-Control": "no-cache", Vary: "Cookie" });
  }

  async function handleLogin(ctx: GateContext, passcode: string): Promise<Response> {
    const req = ctx.request;
    if (req.method !== "POST") return page("/");
    if (Number(req.headers.get("Content-Length") ?? "0") > 4096) return page("/", "", 413);
    let given = "";
    let next = "/";
    try {
      const form = await req.formData();
      given = String(form.get("passcode") ?? "");
      next = safeNext(String(form.get("next") ?? "/"));
    } catch {
      return page("/");
    }
    if (given.length > 0 && given.length <= 512 && (await safeEqual(given, passcode))) {
      const token = await sessionToken(passcode, o.sessionLabel);
      return withHeaders(new Response(null, { status: 303 }), {
        Location: next,
        "Cache-Control": "no-store",
        "Set-Cookie": `${COOKIE}=${token}; Max-Age=${COOKIE_MAX_AGE}; Path=/; HttpOnly; Secure; SameSite=Lax`,
      });
    }
    await sleep(o.wrongDelayMs + Math.floor(Math.random() * 500));
    return page(next, "Wrong passcode.");
  }

  return async function gate(ctx: GateContext): Promise<Response> {
    const req = ctx.request;
    const url = new URL(req.url);
    const path = url.pathname;

    if (path === "/robots.txt") {
      return withHeaders(new Response(ROBOTS, { status: 200 }), { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-cache" });
    }

    const passcode = passcodeOf(ctx.env);
    // Not configured: deny everything (the neutral install files too).
    if (!passcode) return page("/");

    if (path === LOGIN_PATH) return handleLogin(ctx, passcode);
    if (path === LOGOUT_PATH) {
      return withHeaders(new Response(null, { status: 303 }), {
        Location: "/",
        "Cache-Control": "no-store",
        "Set-Cookie": `${COOKIE}=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Lax`,
      });
    }

    const cookie = readCookie(req, COOKIE);
    const authed = cookie !== null && (await safeEqual(cookie, await sessionToken(passcode, o.sessionLabel)));

    if (!authed) {
      if (o.neutralInstallFiles && (req.method === "GET" || req.method === "HEAD")) {
        if (/^\/_n\/[A-Za-z0-9-]+(\.[A-Za-z0-9]+)+$/.test(path)) return serveNeutral(ctx, path);
        const neutral = neutralPath(path);
        if (neutral) return serveNeutral(ctx, neutral);
      }
      return page(safeNext(path + url.search));
    }

    const res = await ctx.next();
    // A file that isn't in this deployment (e.g. an older build's hashed chunk): Pages answers it with index.html and
    // 200 (its single-page-app fallback), which a module import then chokes on and the browser may keep. Answer a real
    // 404 that nothing may keep.
    if (o.missingFiles404 && isMissingFile(path, res)) {
      return withHeaders(new Response("Not found\n", { status: 404 }), { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store", Vary: "Cookie" });
    }
    const immutable = o.immutablePrefix !== "" && path.startsWith(o.immutablePrefix) && res.ok;
    return withHeaders(res, {
      // Never in a shared cache; hashed build files may stay in the browser's.
      "Cache-Control": immutable ? "private, max-age=31536000, immutable" : "private, no-cache",
      Vary: "Cookie",
      "Content-Security-Policy": "frame-ancestors 'none'",
    });
  };
}

/** A Pages Functions `onRequest` handler for the gate that fails closed on any error. */
export function passcodeGate(options: GateOptions = {}) {
  const gate = createGate(options);
  const title = options.title ?? DEFAULTS.title;
  return async (ctx: GateContext): Promise<Response> => {
    try {
      return await gate(ctx);
    } catch {
      return gatePage("/", "", 401, title);
    }
  };
}

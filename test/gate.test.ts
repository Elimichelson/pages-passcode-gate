import { describe, expect, it, beforeEach } from "vitest";
import {
  passcodeGate,
  sessionToken,
  safeNext,
  isFilePath,
  isMissingFile,
  COOKIE,
  LOGIN_PATH,
  LOGOUT_PATH,
  type GateContext,
  type GateEnv,
  type GateOptions,
} from "../src/index";

const ORIGIN = "https://example.pages.dev";
const PASS = "correct horse battery";
const APP_HTML = "<!doctype html><title>Secret Site</title>";

/** A fake Pages context whose static files are a tiny site. */
function ctx(path: string, init: RequestInit & { cookie?: string } = {}, env: GateEnv = { PASSCODE: PASS }) {
  const headers = new Headers(init.headers);
  if (init.cookie) headers.set("Cookie", init.cookie);
  const request = new Request(ORIGIN + path, { ...init, headers });
  const served: string[] = [];
  const files: Record<string, [string, string]> = {
    "/": [APP_HTML, "text/html"],
    "/index.html": [APP_HTML, "text/html"],
    "/assets/index-abc.js": ["console.log('site')", "text/javascript"],
    "/manifest.webmanifest": ['{"name":"Secret Site"}', "application/manifest+json"],
    "/icons/apple-touch-icon.png": ["REAL-ICON", "image/png"],
    "/_n/manifest.webmanifest": ['{"name":"App"}', "application/manifest+json"],
    "/_n/apple-touch-icon.png": ["NEUTRAL-ICON", "image/png"],
  };
  const serve = async (input?: Request | string | URL) => {
    const u = new URL(input === undefined ? request.url : input instanceof Request ? input.url : String(input), ORIGIN);
    served.push(u.pathname);
    const f = files[u.pathname];
    return f
      ? new Response(f[0], { status: 200, headers: { "Content-Type": f[1], "Access-Control-Allow-Origin": "*" } })
      : new Response("not found", { status: 404 });
  };
  const c: GateContext = { request, env: { ...env, ASSETS: { fetch: serve } }, next: serve };
  return { c, served };
}

const onRequest = passcodeGate();

const login = (passcode: string, next = "/") =>
  ctx(LOGIN_PATH, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ passcode, next }).toString(),
  });

async function expectGate(res: Response, served: string[]) {
  expect(res.status).toBe(401);
  const body = await res.text();
  expect(body).toContain('type="password"');
  expect(body).toContain("<title>Private</title>");
  expect(body).not.toContain("Secret Site");
  expect(res.headers.get("Cache-Control")).toBe("no-store");
  expect(res.headers.get("X-Robots-Tag")).toMatch(/noindex, nofollow, noarchive/);
  expect(served).toEqual([]);
}

let cookie = "";
beforeEach(async () => {
  cookie = `${COOKIE}=${await sessionToken(PASS)}`;
});

describe("passcode gate", () => {
  it("serves only the passcode page without a cookie", async () => {
    for (const p of ["/", "/index.html", "/assets/index-abc.js", "/sw.js", "/nope", "/?x=1"]) {
      const { c, served } = ctx(p);
      await expectGate(await onRequest(c), served);
    }
  });

  it("denies everything when PASSCODE is unset or too short", async () => {
    for (const env of [{}, { PASSCODE: "" }, { PASSCODE: "short" }]) {
      for (const p of ["/", "/assets/index-abc.js", "/manifest.webmanifest", "/_n/apple-touch-icon.png", LOGIN_PATH]) {
        const { c, served } = ctx(p, { cookie: `${COOKIE}=${await sessionToken("short")}` }, env);
        await expectGate(await onRequest(c), served);
      }
      const { c } = ctx(LOGIN_PATH, { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: "passcode=short" }, env);
      const res = await onRequest(c);
      expect(res.status).toBe(401);
      expect(res.headers.get("Set-Cookie")).toBeNull();
    }
  });

  it("rejects a wrong passcode slowly and sets no cookie", async () => {
    const { c } = login("wrong passcode!", "/assets/index-abc.js");
    const t0 = Date.now();
    const res = await onRequest(c);
    expect(Date.now() - t0).toBeGreaterThanOrEqual(1450);
    expect(res.status).toBe(401);
    expect(res.headers.get("Set-Cookie")).toBeNull();
    const body = await res.text();
    expect(body).toContain("Wrong passcode.");
    expect(body).toContain('value="/assets/index-abc.js"');
  });

  it("sets a long-lived HttpOnly Secure SameSite=Lax cookie for the right passcode and redirects back", async () => {
    const { c } = login(PASS, "/?page=1");
    const res = await onRequest(c);
    expect(res.status).toBe(303);
    expect(res.headers.get("Location")).toBe("/?page=1");
    const set = res.headers.get("Set-Cookie")!;
    expect(set).toContain(cookie);
    expect(set).toMatch(/Max-Age=34560000/);
    expect(set).toMatch(/HttpOnly/);
    expect(set).toMatch(/Secure/);
    expect(set).toMatch(/SameSite=Lax/);
    expect(set).not.toContain(PASS);
    expect(res.headers.get("Cache-Control")).toBe("no-store");
  });

  it("only answers GET on the login path with the passcode page", async () => {
    const res = await onRequest(ctx(LOGIN_PATH).c);
    expect(res.status).toBe(401);
    expect(res.headers.get("Set-Cookie")).toBeNull();
  });

  it("never redirects off-site after login", () => {
    expect(safeNext("//evil.example/")).toBe("/");
    expect(safeNext("https://evil.example/")).toBe("/");
    expect(safeNext("/\\evil.example")).toBe("/");
    expect(safeNext(LOGIN_PATH)).toBe("/");
    expect(safeNext("/a?b=1")).toBe("/a?b=1");
  });

  it("escapes the next path in the passcode page", async () => {
    const { c } = ctx('/"><script>alert(1)</script>');
    const body = await (await onRequest(c)).text();
    expect(body).not.toContain("<script>");
  });

  it("serves the site with the cookie, private and noindex", async () => {
    const { c, served } = ctx("/", { cookie: `other=1; ${cookie}` });
    const res = await onRequest(c);
    expect(res.status).toBe(200);
    expect(await res.text()).toBe(APP_HTML);
    expect(served).toEqual(["/"]);
    expect(res.headers.get("X-Robots-Tag")).toMatch(/noindex/);
    expect(res.headers.get("Cache-Control")).toBe("private, no-cache");
    expect(res.headers.get("Access-Control-Allow-Origin")).toBeNull();
    expect(res.headers.get("Referrer-Policy")).toBe("no-referrer");
    const js = await onRequest(ctx("/assets/index-abc.js", { cookie }).c);
    expect(js.status).toBe(200);
    expect(js.headers.get("Cache-Control")).toBe("private, max-age=31536000, immutable");
  });

  it("logs every device out when the passcode changes", async () => {
    const { c, served } = ctx("/", { cookie }, { PASSCODE: "a brand new passcode" });
    await expectGate(await onRequest(c), served);
  });

  it("logs every device out when the session label changes", async () => {
    const { c, served } = ctx("/", { cookie });
    await expectGate(await passcodeGate({ sessionLabel: "rotated-2" })(c), served);
  });

  it("serves robots.txt publicly, disallowing everything", async () => {
    const { c, served } = ctx("/robots.txt");
    const res = await onRequest(c);
    expect(res.status).toBe(200);
    expect(await res.text()).toBe("User-agent: *\nDisallow: /\n");
    expect(served).toEqual([]);
  });

  it("answers the manifest and icons with neutral files before login, real ones after", async () => {
    const m = await onRequest(ctx("/manifest.webmanifest").c);
    expect(m.status).toBe(200);
    expect(await m.text()).toBe('{"name":"App"}');
    expect(m.headers.get("Vary")).toBe("Cookie");
    const i = await onRequest(ctx("/icons/apple-touch-icon.png").c);
    expect(await i.text()).toBe("NEUTRAL-ICON");
    const n = await onRequest(ctx("/_n/apple-touch-icon.png").c);
    expect(await n.text()).toBe("NEUTRAL-ICON");
    const real = await onRequest(ctx("/manifest.webmanifest", { cookie }).c);
    expect(await real.text()).toBe('{"name":"Secret Site"}');
    const realIcon = await onRequest(ctx("/icons/apple-touch-icon.png", { cookie }).c);
    expect(await realIcon.text()).toBe("REAL-ICON");
  });

  it("shows the passcode page for a missing neutral file, and serves none when they are turned off", async () => {
    const { c, served } = ctx("/_n/missing.png");
    expect((await onRequest(c)).status).toBe(401);
    expect(served).toEqual(["/_n/missing.png"]);
    const off: GateOptions = { neutralInstallFiles: false };
    for (const p of ["/manifest.webmanifest", "/_n/apple-touch-icon.png", "/icons/apple-touch-icon.png"]) {
      const { c: c2, served: s2 } = ctx(p);
      await expectGate(await passcodeGate(off)(c2), s2);
    }
  });

  it("uses a custom title", async () => {
    const body = await (await passcodeGate({ title: "Family photos" })(ctx("/").c)).text();
    expect(body).toContain("<title>Family photos</title>");
  });

  it("logout clears the cookie", async () => {
    const res = await onRequest(ctx(LOGOUT_PATH, { cookie }).c);
    expect(res.status).toBe(303);
    expect(res.headers.get("Set-Cookie")).toMatch(new RegExp(`^${COOKIE}=; Max-Age=0`));
  });

  it("fails closed when serving throws", async () => {
    const { c } = ctx("/", { cookie });
    c.next = () => Promise.reject(new Error("boom"));
    const res = await onRequest(c);
    expect(res.status).toBe(401);
    expect(await res.text()).not.toContain("Secret Site");
  });
});

describe("passcode gate: files missing from the deployment", () => {
  /** Pages without a 404.html answers every unknown path with index.html and 200 (its single-page-app fallback). */
  function spaCtx(path: string) {
    const { c, served } = ctx(path, { cookie });
    const next = c.next;
    c.next = async (input) => {
      const r = await next(input);
      return r.status === 404 ? new Response(APP_HTML, { status: 200, headers: { "Content-Type": "text/html; charset=utf-8" } }) : r;
    };
    return { c, served };
  }

  it("answers an old build's chunk 404, no-store, never the page", async () => {
    for (const p of ["/assets/index-old123.js", "/assets/data-old.json", "/assets/index-old.css", "/sw-old.js"]) {
      for (const make of [spaCtx, (q: string) => ctx(q, { cookie })]) {
        const res = await onRequest(make(p).c);
        expect(res.status, p).toBe(404);
        expect(res.headers.get("Cache-Control")).toBe("no-store");
        expect(await res.text()).not.toContain("Secret Site");
      }
    }
  });

  it("can leave Pages' fallback alone", async () => {
    const res = await passcodeGate({ missingFiles404: false })(spaCtx("/assets/index-old123.js").c);
    expect(res.status).toBe(200);
  });

  it("still serves the files that are there, and pages as pages", async () => {
    const js = await onRequest(spaCtx("/assets/index-abc.js").c);
    expect(js.status).toBe(200);
    for (const p of ["/", "/index.html", "/some/route", "/?x=1"]) {
      const res = await onRequest(spaCtx(p).c);
      expect(res.status, p).toBe(200);
      expect(await res.text()).toContain("Secret Site");
    }
  });

  it("still shows the passcode page for a missing file without a cookie (nothing reveals what exists)", async () => {
    const { c, served } = ctx("/assets/index-old123.js");
    await expectGate(await onRequest(c), served);
  });

  it("tells files from pages", () => {
    expect(isFilePath("/assets/a-1.js")).toBe(true);
    expect(isFilePath("/assets/a.wasm")).toBe(true);
    expect(isFilePath("/")).toBe(false);
    expect(isFilePath("/index.html")).toBe(false);
    expect(isFilePath("/some/route")).toBe(false);
    expect(isMissingFile("/a.js", new Response("x", { status: 200, headers: { "Content-Type": "text/javascript" } }))).toBe(false);
  });
});

# pages-passcode-gate

A small, **fail-closed passcode gate for Cloudflare Pages**. Put it in front of any static site (a game, a photo
album, a family app, a prototype) to keep the whole site private on Cloudflare's **free plan**, with no accounts and
no paid Cloudflare Access.

I built it, with Claude Code, to keep my hobby web game private: friends and family get a passcode, and nobody else, search engines
included, sees anything. The game is installed on an iPhone home screen, which needed some extra care (see below).

## What it does

- **Everything is locked**, static files included: every request goes through Pages Functions middleware. Without a
  valid session cookie, the only answer is a small, neutral passcode page (`401`) with no site name and no art.
- **Fails closed.** If the `PASSCODE` secret is missing or shorter than 8 characters, or anything throws, everything is
  denied. A mistake can't make the site public.
- **No passcode in the cookie.** The session cookie holds `HMAC-SHA256(PASSCODE, label)`, `HttpOnly`, `Secure`,
  `SameSite=Lax`, under a `__Host-` name. Changing the passcode logs every device out.
- **Slows down guessing**: each wrong passcode waits about 1.5 seconds before the answer. Comparisons are
  constant-time.
- **Stays out of search engines**: `robots.txt` disallows everything, and every response carries `X-Robots-Tag:
  noindex`, `Referrer-Policy: no-referrer` and anti-framing headers.
- **Works as an iPhone home-screen app.** iOS fetches the web app manifest and icons *without cookies* when you tap
  "Add to Home Screen", so a fully gated manifest breaks installing. The gate serves neutral stand-ins from `/_n/`
  (for example a manifest named "App" and a plain icon) until you log in, so the site installs properly without its
  real name or icon showing to anyone without the passcode.
- **Fixes stale-chunk errors after a deploy.** Pages answers a missing file with `index.html` and `200` (its
  single-page-app fallback), so a cached page that imports an old hashed chunk gets HTML instead of JavaScript. The
  gate turns that into a real, uncached `404`.
- **Safe redirects**: after logging in you return to the page you asked for, never to another site.

## Use it

1. Copy `src/index.ts` into your Pages project, outside the `functions/` folder (for example as
   `lib/passcode-gate.ts`), and add `functions/_middleware.ts`:

   ```ts
   import { passcodeGate } from "../lib/passcode-gate";

   export const onRequest = passcodeGate();
   ```

2. Set the passcode as a **secret**: Cloudflare dashboard → Workers & Pages → your project → Settings → Variables and
   secrets → add `PASSCODE` (at least 8 characters; longer is better), then redeploy. With Wrangler:
   `npx wrangler pages secret put PASSCODE --project-name <your-project>`.

3. Optional, for home-screen installs: put a neutral manifest and icons in your site's `/_n/` folder (see
   [`example/public`](example/public)). `/manifest.webmanifest` and `/icons/<name>.png` answer with
   `/_n/manifest.webmanifest` and `/_n/<name>.png` until the visitor logs in.

Log out by visiting `/__gate/logout`.

## Options

```ts
passcodeGate({
  title: "Private",               // the passcode page's <title>; keep it neutral
  sessionLabel: "my-site-v1",     // change it to log every device out without changing the passcode
  neutralInstallFiles: true,      // serve /_n/ install files before login
  immutablePrefix: "/assets/",    // logged-in files here are cached as immutable ("" turns it off)
  missingFiles404: true,          // a missing file answers 404, not Pages' index.html fallback
  wrongDelayMs: 1500,             // delay before answering a wrong passcode
});
```

## What it is not

A shared passcode is not per-person accounts: everyone who knows it gets in, and you can't lock out one person
without changing it for everyone. It is meant for keeping a personal or family site private, not for protecting
sensitive data. For that, use real authentication (for example Cloudflare Access).

## Develop

```sh
npm install
npm run typecheck
npm test
```

The tests run the gate against a fake Pages context: no Cloudflare account needed.

## License

MIT

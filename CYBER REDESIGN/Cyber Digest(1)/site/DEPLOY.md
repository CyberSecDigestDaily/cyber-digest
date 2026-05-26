# Deploy Cyber Digest

A walkthrough of the workflow: **Claude (design + iteration) → GitHub (source of truth) → Cloudflare Pages (production)**.
Everything in `/site` is plain static HTML, CSS and one vanilla JS file. No build step. No framework. No JS dependencies. That keeps the deploy fast, the iteration loop tight, and the bill near-zero.

---

## What's in `site/`

```
site/
├── index.html         Homepage — hero, live console, featured, wire preview, CVE grid
├── wire.html          The Wire — full chronological news index with live filter chips
├── cves.html          Vulnerabilities — full CVE / CISA-KEV tracker table
├── cve.html           CVE detail — single CVE deep view (CVE-2024-47575 sample)
├── briefing.html      Long-form article reader (Volt Typhoon deep-dive sample)
├── actor.html         Threat actor profile (Volt Typhoon sample)
├── about.html         Masthead · editorial standards · contact · press kit
├── subscribe.html     Pricing tiers + FAQs
├── tip.html           Confidential tip line (PGP / Signal / SecureDrop / postal)
├── legal.html         Privacy · Terms · Cookies · Disclosures · Corrections · Security
├── search.html        Standalone /search route (also opened by ⌘K palette)
├── 404.html           Not-found page
├── styles.css         Shared design system + light theme tokens
├── app.js             Shared client behaviour (theme, clock, search, filters, forms)
├── robots.txt         Allow main bots; opt out of AI training crawlers
├── sitemap.xml        For Google / Bing Search Console
├── feed.xml           RSS 2.0
├── feed.json          JSON Feed 1.1
└── DEPLOY.md          This file
```

Every page links the same `styles.css` and loads `app.js` with `defer`. Edit the stylesheet once and the change ripples through the site. Page-specific styles live inline in a `<style>` block at the top of each page so layouts that only one page uses don't bloat the shared CSS.

---

## What works on the page

- **Light / dark themes.** Click the moon/sun in the header. The preference is stored in `localStorage` (`cd-theme`) and an inline pre-paint script in every `<head>` applies it before first render, so there is no flash. New visitors get whatever their OS prefers.
- **Live UTC clock.** Every header (and the footer) renders a live UTC clock that ticks every second.
- **Search palette (⌘K / Ctrl+K).** A modal opens from anywhere on the site; click results route to the right page. The index lives at the top of `app.js` — extend it (or pull from `/search.json` on a CDN) as the corpus grows.
- **Filter chips.** The Wire and the Vulnerabilities tracker both filter live on click. No reload.
- **Subscribe forms.** All `<form data-form="subscribe">` instances are intercepted; the demo shows a toast. Swap the body of the handler in `app.js` for a `fetch()` against Postmark, Buttondown, ConvertKit, etc.
- **Contact form.** `<form data-form="contact">` on the tip line. Same pattern.
- **Threat-ops console.** Numeric metrics drift every 8s; a new feed line appends every 15s, capped at six rows. Replace the in-page `FEED_SAMPLES` array with a Cloudflare Worker that proxies real upstreams — see "Live data, for real" below.
- **Mobile drawer.** Below 1100 px the nav collapses into a drawer; the hamburger button activates it.
- **Working buttons.** Every CTA either routes to a real page, opens the search palette, opens a `mailto:` link, or surfaces a toast explaining what would happen in production.

---

## 1. Test locally

```bash
# Python (pre-installed on macOS / Linux)
cd site && python3 -m http.server 4321

# Or with Node
npx serve site -p 4321
```

Open <http://localhost:4321>. Tab around every page from the nav and the footer; they all resolve.

---

## 2. Push to GitHub

```bash
git init
git add .
git commit -m "Cyber Digest — full static site"
git branch -M main
git remote add origin git@github.com:<you>/cyber-digest.git
git push -u origin main
```

---

## 3. Cloudflare Pages

1. Cloudflare dashboard → **Workers & Pages** → **Create** → **Pages** → **Connect to Git**.
2. Authorise Cloudflare (one-time).
3. Pick the repo → **Begin setup**.
4. **Build settings**:

   | Field                  | Value     |
   | ---------------------- | --------- |
   | Framework preset       | **None**  |
   | Build command          | *(blank)* |
   | Build output directory | **`site`**|
   | Root directory         | *(blank)* |

5. **Save and Deploy**. Cloudflare publishes `/site` to `<project>.pages.dev` in ~30s.

Every push to `main` ships to production. Every other branch gets its own preview URL — `<branch>.<project>.pages.dev` — useful for reviewing a Claude change before merging.

### Custom domain

Cloudflare Pages → project → **Custom domains** → enter `cyberdigest.io`. If the apex is already on Cloudflare DNS, records and TLS are issued automatically.

### Headers & redirects (optional)

Add `_headers` to `site/` for production-grade security headers:

```
/*
  Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
  X-Content-Type-Options: nosniff
  Referrer-Policy: strict-origin-when-cross-origin
  Permissions-Policy: interest-cohort=()
  Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; script-src 'self' 'unsafe-inline'; connect-src 'self'
```

And `_redirects` for tidy URLs:

```
/feed       /feed.xml         200
/tip        /tip.html         200
/wire       /wire.html        200
/cves       /cves.html        200
/cve/:slug  /cve.html         200
/actor/:s   /actor.html       200
```

Both files are recognised natively by Cloudflare Pages — no config needed.

---

## 4. Live data, for real

The "threat ops" console on the homepage and the CVE tracker on `cves.html` ship with realistic seed data and a tick of drift via `app.js`. To make them actually live, plug in either of these paths:

**Path A — Cloudflare Worker that proxies upstreams** *(recommended)*. Workers are free up to 100k requests/day. A Worker route at `/api/cves` and `/api/kev` is the cleanest way to bypass CORS on NVD/CISA endpoints.

```js
// workers/index.js
export default {
  async fetch(req) {
    const url = new URL(req.url);
    if (url.pathname === '/api/kev') {
      const r = await fetch('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
        { cf: { cacheTtl: 600, cacheEverything: true } });
      return new Response(await r.text(), { headers: { 'content-type': 'application/json' }});
    }
    // ...NVD recent CVEs, EPSS, etc.
    return new Response('Not found', { status: 404 });
  }
}
```

Then in `app.js` swap the seed `FEED_SAMPLES` array for `await fetch('/api/kev').then(r=>r.json())` and render fresh KEV entries every 15s.

**Path B — a build-time JSON snapshot**. A GitHub Action that runs every 30 minutes, hits CISA/NVD, writes `site/data/kev.json`, commits, and Cloudflare auto-deploys. Slower but trivially cheap and serverless.

A working example of both lives in `DEPLOY.md` revision history of this repo once you commit.

---

## 5. The Claude cowork loop

1. In Claude, ask for a change — "add an actor profile for Salt Typhoon", "tighten the hero spacing", "add a CSP-strict header file".
2. Claude edits files in this project.
3. Pull the changes into your local repo, `git checkout -b claude/<change>`, commit, push.
4. Cloudflare builds a preview deployment for the PR — review on `<branch>.<project>.pages.dev`.
5. Merge to `main`. Production updates.

If you connect GitHub to the Claude project, Claude can read your repo when iterating so changes stay consistent with what's deployed.

---

## 6. Pre-launch checklist

- [ ] Fill the homepage <image-slot> cards by dragging real editorial images onto them (persists in localStorage; serve from R2 in production)
- [ ] Replace the article-hero striped placeholder on briefing.html with real editorial art
- [ ] Populate the masthead in about.html with real bylines, bios and headshots (currently marked TBA)
- [ ] Real `og:image` social card per page
- [ ] Real ICO registration number, VAT number, and Companies House number in the footer + legal page (placeholders are obviously fictional)
- [ ] Wire `data-form="subscribe"` to your ESP (Postmark / Buttondown / ConvertKit / Mailchimp)
- [ ] Wire `data-form="contact"` to your editorial inbox (Cloudflare Email Routing → Workers makes this free)
- [ ] Connect Stripe checkout to the **Practitioner** plan CTA on `subscribe.html`
- [ ] Generate and publish a real PGP key; replace fingerprints on `about.html` and `tip.html`
- [ ] Stand up the actual SecureDrop instance and replace the placeholder onion address on `tip.html`
- [ ] Set up Cloudflare Web Analytics (free, no cookies, no consent banner needed)
- [ ] Submit `sitemap.xml` to Google Search Console and Bing Webmaster Tools
- [ ] Add `_headers` and `_redirects` files
- [ ] Backfill `feed.xml` and `feed.json` from your CMS / source on every publish (a Worker cron job is fine)

That's it. Push the folder. Point Pages at it. Go live.

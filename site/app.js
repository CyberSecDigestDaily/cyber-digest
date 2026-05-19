/* ─────────────────────────────────────────────────────────────
   Cyber Digest — shared client behavior
   Loaded via <script defer src="app.js"></script> on every page.
   No build step, no dependencies.
   ───────────────────────────────────────────────────────────── */

(function(){
  'use strict';

  /* ---------- Theme ---------- */
  const THEME_KEY = 'cd-theme';
  const root = document.documentElement;
  const stored = localStorage.getItem(THEME_KEY);
  const prefersLight = window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches;
  const initial = stored || (prefersLight ? 'light' : 'dark');
  root.dataset.theme = initial;

  function setTheme(t){
    root.dataset.theme = t;
    localStorage.setItem(THEME_KEY, t);
  }
  window.toggleTheme = function(){
    setTheme(root.dataset.theme === 'light' ? 'dark' : 'light');
  };

  /* ---------- Live clock (UTC, ticks every second) ---------- */
  function tickClock(){
    const now = new Date();
    const hh = String(now.getUTCHours()).padStart(2,'0');
    const mm = String(now.getUTCMinutes()).padStart(2,'0');
    const ss = String(now.getUTCSeconds()).padStart(2,'0');
    document.querySelectorAll('[data-clock]').forEach(el=>{
      el.textContent = hh + ':' + mm + ':' + ss + ' UTC';
    });
    document.querySelectorAll('[data-clock-short]').forEach(el=>{
      el.textContent = hh + ':' + mm + ' UTC';
    });
  }
  setInterval(tickClock, 1000);

  /* ---------- Relative timestamps ("3 minutes ago") ---------- */
  // Elements: <time data-rel="2026-05-18T17:14:00Z">17:14 UTC</time>
  function fmtRel(secs){
    if (secs < 60) return Math.max(1,Math.round(secs))+'s ago';
    if (secs < 3600) return Math.round(secs/60)+'m ago';
    if (secs < 86400) return Math.round(secs/3600)+'h ago';
    return Math.round(secs/86400)+'d ago';
  }
  function tickRel(){
    const now = Date.now();
    document.querySelectorAll('time[data-rel]').forEach(el=>{
      const when = Date.parse(el.dataset.rel);
      if (!isNaN(when)) el.textContent = fmtRel((now - when)/1000);
    });
  }
  setInterval(tickRel, 30000);
  tickRel();

  /* ---------- Search modal (⌘K / Ctrl+K) ---------- */
  function openSearch(){
    let m = document.getElementById('cd-search-modal');
    if (!m){
      m = document.createElement('div');
      m.id = 'cd-search-modal';
      m.className = 'modal-backdrop';
      m.innerHTML = '\
        <div class="modal" role="dialog" aria-modal="true">\
          <div class="modal-search">\
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="color:var(--fg-dim)"><circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/></svg>\
            <input id="cd-search-input" placeholder="Search CVE, vendor, actor, briefing…" autocomplete="off" />\
            <span class="kbd">Esc</span>\
          </div>\
          <div class="modal-section">\
            <h6>Suggested</h6>\
            <div class="modal-results" id="cd-search-results"></div>\
          </div>\
          <div class="modal-foot">\
            <span>Powered by Cyber Digest index</span>\
            <span class="keys">\
              <span><span class="k">↵</span> open</span>\
              <span><span class="k">↑↓</span> navigate</span>\
              <span><span class="k">Esc</span> close</span>\
            </span>\
          </div>\
        </div>';
      document.body.appendChild(m);
      m.addEventListener('click', e=>{ if(e.target===m) closeSearch(); });
    }
    renderSearch('');
    m.classList.add('open');
    setTimeout(()=>document.getElementById('cd-search-input').focus(), 30);
    document.body.style.overflow = 'hidden';
  }
  function closeSearch(){
    const m = document.getElementById('cd-search-modal');
    if (m) m.classList.remove('open');
    document.body.style.overflow = '';
  }
  // Lightweight in-page index — extend this from a real /search.json in production
  const SEARCH_INDEX = [
    {t:'CVE',  l:'CVE-2024-47575 — FortiManager missing authentication (FortiJump)', h:'cve.html'},
    {t:'CVE',  l:'CVE-2024-3400 — Palo Alto PAN-OS GlobalProtect command injection', h:'cves.html'},
    {t:'CVE',  l:'CVE-2024-21762 — FortiOS out-of-bounds write', h:'cves.html'},
    {t:'CVE',  l:'CVE-2024-21887 — Ivanti Connect Secure command injection', h:'cves.html'},
    {t:'CVE',  l:'CVE-2024-37085 — VMware ESXi authentication bypass', h:'cves.html'},
    {t:'Actor',l:'Volt Typhoon — China-nexus, US critical infrastructure', h:'actor.html'},
    {t:'Actor',l:'Salt Typhoon — China-nexus, US telecommunications', h:'actor.html'},
    {t:'Actor',l:'Akira — eCrime ransomware affiliate group', h:'actor.html'},
    {t:'Brief',l:'Inside the Volt Typhoon resurgence (deep dive)', h:'briefing.html'},
    {t:'Page', l:'The Wire — chronological news feed', h:'wire.html'},
    {t:'Page', l:'Vulnerabilities — CVE index & tracker', h:'cves.html'},
    {t:'Page', l:'Subscribe — newsletter & pricing', h:'subscribe.html'},
    {t:'Page', l:'Tip line — secure submission (Signal, SecureDrop)', h:'tip.html'},
    {t:'Page', l:'About — masthead & editorial standards', h:'about.html'}
  ];
  function renderSearch(q){
    const results = document.getElementById('cd-search-results');
    const heading = results.parentElement.querySelector('h6');
    if (!results) return;
    const Q = q.trim().toLowerCase();
    const items = Q
      ? SEARCH_INDEX.filter(x => x.l.toLowerCase().includes(Q) || x.t.toLowerCase().includes(Q))
      : SEARCH_INDEX.slice(0, 6);
    heading.textContent = Q ? items.length + ' result' + (items.length===1?'':'s') : 'Suggested';
    results.innerHTML = items.map(x =>
      '<a class="modal-result" href="' + x.h + '">' +
      '<span class="typ">' + x.t + '</span>' +
      '<span class="ttl">' + x.l + '</span>' +
      '<span class="arr">↗</span>' +
      '</a>'
    ).join('') || '<div style="padding:24px 8px;color:var(--fg-dim);font-size:13px">No matches. Try a CVE, vendor, or actor.</div>';
  }
  document.addEventListener('keydown', e=>{
    if ((e.metaKey||e.ctrlKey) && e.key.toLowerCase()==='k'){ e.preventDefault(); openSearch(); }
    if (e.key === 'Escape') closeSearch();
  });
  document.addEventListener('input', e=>{
    if (e.target && e.target.id === 'cd-search-input') renderSearch(e.target.value);
  });
  // Wire any [data-action="search"] trigger
  document.addEventListener('click', e=>{
    const t = e.target.closest('[data-action="search"]');
    if (t){ e.preventDefault(); openSearch(); }
  });

  /* ---------- Toast ---------- */
  function toast(msg){
    let t = document.getElementById('cd-toast');
    if (!t){
      t = document.createElement('div');
      t.id = 'cd-toast'; t.className = 'toast';
      document.body.appendChild(t);
    }
    t.innerHTML = '<span class="ok">✓</span> ' + msg;
    t.classList.add('show');
    clearTimeout(t._timer);
    t._timer = setTimeout(()=>t.classList.remove('show'), 3200);
  }
  window.cdToast = toast;

  /* ---------- Subscribe forms ---------- */
  // Any form with [data-form="subscribe"] gets handled inline (demo: shows toast).
  // In production swap the body of submitHandler for fetch() to your provider.
  document.addEventListener('submit', e=>{
    const f = e.target.closest('[data-form="subscribe"]');
    if (!f) return;
    e.preventDefault();
    const input = f.querySelector('input[type="email"]');
    const email = (input && input.value || '').trim();
    if (!email || !/.+@.+\..+/.test(email)) { toast('Enter a valid email address.'); return; }
    if (input) input.value = '';
    toast('Subscribed — confirmation sent to ' + email);
  });

  // Generic [data-form="contact"] handler
  document.addEventListener('submit', e=>{
    const f = e.target.closest('[data-form="contact"]');
    if (!f) return;
    e.preventDefault();
    toast('Message received. The editorial desk will respond within 24h.');
    f.reset();
  });

  /* ---------- Filter chips (wire page) ---------- */
  // Markup: container [data-filter-group] with buttons [data-filter="x"], rows [data-cats="a b c"]
  document.addEventListener('click', e=>{
    const c = e.target.closest('[data-filter]');
    if (!c) return;
    const group = c.closest('[data-filter-group]');
    if (!group) return;
    const tag = c.dataset.filter;
    group.querySelectorAll('[data-filter]').forEach(x=>x.classList.toggle('on', x===c));
    document.querySelectorAll('[data-cats]').forEach(row=>{
      const cats = row.dataset.cats.split(/\s+/);
      row.style.display = (tag==='all' || cats.includes(tag)) ? '' : 'none';
    });
    // hide empty day-heads
    document.querySelectorAll('[data-day]').forEach(day=>{
      const rows = day.parentElement.querySelectorAll('[data-cats]');
      const visible = [...rows].some(r => r.style.display !== 'none');
      day.style.display = visible ? '' : 'none';
    });
  });

  /* ---------- Mobile nav drawer ---------- */
  window.cdMobileNav = function(open){
    let n = document.getElementById('cd-mobile-nav');
    if (open && !n){
      n = document.createElement('nav');
      n.id = 'cd-mobile-nav'; n.className = 'mobile-nav open';
      n.innerHTML = '\
        <button class="close" onclick="cdMobileNav(false)" aria-label="Close menu">×</button>\
        <a href="index.html">Home <span class="arr">→</span></a>\
        <a href="wire.html">The Wire <span class="arr">→</span></a>\
        <a href="cves.html">Vulnerabilities <span class="arr">→</span></a>\
        <a href="briefing.html">Briefings <span class="arr">→</span></a>\
        <a href="actor.html">Threat Actors <span class="arr">→</span></a>\
        <a href="subscribe.html">Subscribe <span class="arr">→</span></a>\
        <a href="about.html">About <span class="arr">→</span></a>\
        <a href="tip.html">Tip line <span class="arr">→</span></a>';
      document.body.appendChild(n);
    } else if (n){
      n.classList.toggle('open', !!open);
    }
  };

  /* ---------- Highlight current page in nav ---------- */
  function markCurrent(){
    const path = location.pathname.split('/').pop() || 'index.html';
    document.querySelectorAll('.nav a').forEach(a=>{
      const href = (a.getAttribute('href')||'').split('?')[0];
      if (href === path) a.setAttribute('aria-current','page');
    });
  }
  markCurrent();

  /* ---------- Live "threat ops console" updater (homepage) ---------- */
  // Drift the metrics every 8s so the console feels alive. Real production would
  // pull from a Worker proxy of NVD JSON / CISA KEV / your own pipeline.
  const driftTargets = document.querySelectorAll('[data-metric]');
  if (driftTargets.length){
    const base = new Map();
    driftTargets.forEach(el => base.set(el, parseFloat(el.textContent.replace(/[^\d.]/g,''))));
    setInterval(()=>{
      driftTargets.forEach(el=>{
        const b = base.get(el);
        if (isNaN(b)) return;
        const next = Math.max(0, Math.round(b + (Math.random()-.5) * Math.max(1, b*0.04)));
        // preserve any trailing unit span
        const unit = el.querySelector('span');
        el.firstChild && (el.firstChild.nodeValue = next.toString());
        if (unit) el.appendChild(unit);
      });
    }, 8000);
  }

  // Append a fresh feed line every ~15s into [data-live-feed]
  const FEED_SAMPLES = [
    {sev:'mid',  msg:'Recorded Future flags renewed scanning of Citrix NetScaler endpoints',  meta:'CVE-2023-3519'},
    {sev:'high', msg:'Mandiant attributes new wave of NetScaler intrusions to a China-nexus group', meta:'M-Trends 2025'},
    {sev:'low',  msg:'Cloudflare blocks record 5.6 Tbps DDoS aimed at telco infrastructure',   meta:'radar.cloudflare'},
    {sev:'mid',  msg:'Apple ships rapid-security response for WebKit nday in active exploit chain', meta:'HT214108'},
    {sev:'high', msg:'CISA issues emergency directive 25-02 covering Ivanti Connect Secure',   meta:'cisa.gov'},
    {sev:'crit', msg:'FortiManager FortiJump exploitation observed across financial sector', meta:'CVE-2024-47575'},
    {sev:'low',  msg:'Chrome stable channel rolls 134.0.6998 — 4 fixes, none critical',         meta:'chromereleases'}
  ];
  let feedIdx = 0;
  const feedEl = document.querySelector('[data-live-feed]');
  if (feedEl){
    setInterval(()=>{
      const item = FEED_SAMPLES[feedIdx++ % FEED_SAMPLES.length];
      const now = new Date();
      const hh = String(now.getUTCHours()).padStart(2,'0');
      const mm = String(now.getUTCMinutes()).padStart(2,'0');
      const ss = String(now.getUTCSeconds()).padStart(2,'0');
      const line = document.createElement('div');
      line.className = 'line';
      line.style.opacity = 0;
      line.innerHTML =
        '<span class="t">'+hh+':'+mm+':'+ss+'</span>' +
        '<span class="sev '+item.sev+'">'+item.sev.toUpperCase()+'</span>' +
        '<span class="msg">'+item.msg+'</span>' +
        '<span class="meta">'+item.meta+'</span>';
      feedEl.insertBefore(line, feedEl.firstChild);
      requestAnimationFrame(()=>{ line.style.transition='opacity .4s ease'; line.style.opacity=1; });
      // cap at 6
      while (feedEl.children.length > 6) feedEl.removeChild(feedEl.lastChild);
    }, 15000);
  }

  tickClock();

  /* ---------- Backfill timestamps (data-offset-sec on .console-feed .t) ---------- */
  function fillOffsets(){
    const now = Date.now();
    document.querySelectorAll('[data-offset-sec]').forEach(el=>{
      const sec = parseInt(el.dataset.offsetSec, 10);
      if (isNaN(sec)) return;
      const t = new Date(now - sec * 1000);
      const hh = String(t.getUTCHours()).padStart(2,'0');
      const mm = String(t.getUTCMinutes()).padStart(2,'0');
      const ss = String(t.getUTCSeconds()).padStart(2,'0');
      el.textContent = hh + ':' + mm + ':' + ss;
    });
    document.querySelectorAll('[data-offset-min]').forEach(el=>{
      const min = parseInt(el.dataset.offsetMin, 10);
      if (isNaN(min)) return;
      const t = new Date(now - min * 60 * 1000);
      const hh = String(t.getUTCHours()).padStart(2,'0');
      const mm = String(t.getUTCMinutes()).padStart(2,'0');
      el.textContent = hh + ':' + mm + ' UTC';
    });
  }
  setInterval(fillOffsets, 5000);
  fillOffsets();

})();

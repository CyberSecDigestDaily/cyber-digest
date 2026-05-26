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

  /* ─────────────────────────────────────────────────────────────
     Signal Ticker — data, vendor filter, click-through
     ───────────────────────────────────────────────────────────── */

  const TICKER_ITEMS = [
    // ── 2025 critical / exploited ──
    {sev:'crit', vendor:'microsoft',  label:'CVE-2025-29824 — Windows CLFS zero-day exploited by RansomEXX (CVSS 7.8)',          href:'cve.html'},
    {sev:'crit', vendor:'microsoft',  label:'CVE-2025-21418 — Windows AFD.sys privilege escalation zero-day · patch issued',     href:'cve.html'},
    {sev:'crit', vendor:'paloalto',   label:'CVE-2025-0108 — PAN-OS authentication bypass under active mass exploitation',        href:'cve.html'},
    {sev:'crit', vendor:'paloalto',   label:'CVE-2025-0111 — PAN-OS unauthenticated file read · chained with CVE-2025-0108',     href:'cve.html'},
    {sev:'crit', vendor:'ivanti',     label:'CVE-2025-0282 — Ivanti Connect Secure stack overflow (CVSS 9.0) · CISA ED 25-02',   href:'cve.html'},
    {sev:'crit', vendor:'sonicwall',  label:'CVE-2025-23006 — SonicWall SMA 100 pre-auth deserialization RCE (CVSS 9.8)',        href:'cve.html'},
    {sev:'crit', vendor:'fortinet',   label:'CVE-2025-24472 — FortiOS / FortiProxy auth bypass (CVSS 9.8) · PoC public',        href:'cve.html'},
    {sev:'crit', vendor:'vmware',     label:'CVE-2025-22224 — VMware ESXi VCMI heap overflow · zero-day exploited (CVSS 9.3)',   href:'cve.html'},
    {sev:'crit', vendor:'cisco',      label:'CVE-2025-20188 — Cisco IOS XE web UI hard-coded JWT (CVSS 10.0) · mass exploitation',href:'cve.html'},
    {sev:'crit', vendor:'apache',     label:'CVE-2025-24813 — Apache Tomcat deserialization RCE · PoC widely circulated',        href:'cve.html'},
    // ── 2025 high ──
    {sev:'high',  vendor:'apple',     label:'CVE-2025-24085 — Apple CoreMedia zero-day exploited in the wild · iOS 18.3.1',      href:'cve.html'},
    {sev:'high',  vendor:'apple',     label:'CVE-2025-24200 — iOS USB Restricted Mode bypass · active in-the-wild exploitation', href:'cve.html'},
    {sev:'high',  vendor:'google',    label:'CVE-2025-2783 — Chrome renderer zero-day exploited in espionage campaign',           href:'cve.html'},
    {sev:'high',  vendor:'microsoft', label:'CVE-2025-21333 — Windows Hyper-V NT Kernel Integration VSP elevation · zero-day',   href:'cve.html'},
    {sev:'high',  vendor:'atlassian', label:'CVE-2025-22150 — Atlassian Confluence Server RCE in macro renderer · patch now',    href:'cve.html'},
    {sev:'high',  vendor:'juniper',   label:'CVE-2025-21598 — Juniper Junos SRX out-of-bounds read · unauthenticated DoS',       href:'cve.html'},
    {sev:'high',  vendor:'checkpoint',label:'CVE-2025-23971 — Check Point VPN gateway pre-auth info disclosure · mass scanning', href:'cve.html'},
    {sev:'high',  vendor:'citrix',    label:'CVE-2025-5777 — Citrix NetScaler ADC auth bypass · exploitation attempts observed',  href:'cve.html'},
    {sev:'high',  vendor:'aws',       label:'AWS S3 credential harvesting campaign — exposed GitHub PATs used for lateral move',  href:'briefing.html'},
    {sev:'high',  vendor:'microsoft', label:'Salt Typhoon — ongoing ISP/telecom intrusions · CISA & NSA joint advisory issued',   href:'briefing.html'},
    // ── 2025 medium / patched ──
    {sev:'mid',   vendor:'crowdstrike',label:'CrowdStrike Falcon sensor configuration issue — partial sensor outages reported',   href:'briefing.html'},
    {sev:'mid',   vendor:'sentinelone',label:'SentinelOne advisory: management console SSRF in portal integration module',        href:'briefing.html'},
    {sev:'mid',   vendor:'linux',     label:'CVE-2025-0927 — Linux kernel NTFS3 heap buffer overflow · local privilege escalation',href:'cve.html'},
    {sev:'mid',   vendor:'android',   label:'CVE-2025-0072 — Android Qualcomm GPU use-after-free · zero-click exploitation',     href:'cve.html'},
    {sev:'low',   vendor:'microsoft', label:'Microsoft May 2025 Patch Tuesday — 72 CVEs, 5 zero-days, 4 critical RCE patches',   href:'briefing.html'},
    {sev:'low',   vendor:'google',    label:'Chrome 136 stable channel — 8 security fixes, 2 high severity, no active exploits', href:'briefing.html'},
    {sev:'low',   vendor:'apple',     label:'Apple iOS 18.5 / macOS 15.5 — 35 CVEs patched, including 2 previously exploited',  href:'briefing.html'},
  ];

  const VENDORS = [
    {key:'all',        label:'All'},
    {key:'microsoft',  label:'Microsoft'},
    {key:'aws',        label:'AWS'},
    {key:'paloalto',   label:'Palo Alto'},
    {key:'fortinet',   label:'Fortinet'},
    {key:'cisco',      label:'Cisco'},
    {key:'google',     label:'Google'},
    {key:'ivanti',     label:'Ivanti'},
    {key:'vmware',     label:'VMware'},
    {key:'apple',      label:'Apple'},
    {key:'citrix',     label:'Citrix'},
    {key:'sonicwall',  label:'SonicWall'},
    {key:'juniper',    label:'Juniper'},
    {key:'apache',     label:'Apache'},
    {key:'atlassian',  label:'Atlassian'},
    {key:'checkpoint', label:'Check Point'},
    {key:'crowdstrike',label:'CrowdStrike'},
    {key:'sentinelone',label:'SentinelOne'},
    {key:'linux',      label:'Linux'},
    {key:'android',    label:'Android'},
  ];

  function buildTickerHTML(vendor){
    const items = (vendor === 'all')
      ? TICKER_ITEMS
      : TICKER_ITEMS.filter(i => i.vendor === vendor);
    if (!items.length) return '<span style="color:var(--fg-dim);padding:0 24px">No items for this vendor.</span>';
    const both = [...items, ...items]; // double for seamless loop
    return both.map(i =>
      '<a class="ticker-item" href="' + i.href + '">' +
      '<span class="sev ' + i.sev + '">' + i.sev.toUpperCase() + '</span>' +
      i.label +
      '</a>'
    ).join('');
  }

  function renderTicker(vendor){
    const track = document.getElementById('cd-ticker-track');
    if (!track) return;
    track.innerHTML = buildTickerHTML(vendor);
    // Recalculate scroll duration based on item count
    const items = (vendor === 'all') ? TICKER_ITEMS : TICKER_ITEMS.filter(i => i.vendor === vendor);
    const dur = Math.max(18, items.length * 4);
    // Restart animation
    track.style.animation = 'none';
    void track.offsetHeight; // force reflow
    track.style.animation = 'scroll ' + dur + 's linear infinite';
  }

  function initTicker(){
    const filterEl = document.getElementById('cd-vendor-filter');
    if (!filterEl) return; // not homepage

    // Build vendor chips — only show vendors with data
    VENDORS.forEach(v => {
      if (v.key !== 'all' && !TICKER_ITEMS.some(i => i.vendor === v.key)) return;
      const btn = document.createElement('button');
      btn.className = 'ticker-vchip' + (v.key === 'all' ? ' on' : '');
      btn.dataset.vendor = v.key;
      btn.textContent = v.label;
      btn.addEventListener('click', () => {
        filterEl.querySelectorAll('.ticker-vchip').forEach(c => c.classList.remove('on'));
        btn.classList.add('on');
        renderTicker(v.key);
      });
      filterEl.appendChild(btn);
    });

    renderTicker('all');
  }

  initTicker();

  /* ─────────────────────────────────────────────────────────────
     Search modal (⌘K / Ctrl+K)
     ───────────────────────────────────────────────────────────── */
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

  /* ── Search index — 2025 data + vendors + actors ── */
  const SEARCH_INDEX = [
    // 2025 CVEs
    {t:'CVE',   l:'CVE-2025-29824 — Windows CLFS zero-day exploited by RansomEXX',          h:'cve.html'},
    {t:'CVE',   l:'CVE-2025-21418 — Windows AFD.sys privilege escalation zero-day',         h:'cve.html'},
    {t:'CVE',   l:'CVE-2025-21333 — Windows Hyper-V NT Kernel Integration VSP elevation',   h:'cve.html'},
    {t:'CVE',   l:'CVE-2025-0282 — Ivanti Connect Secure stack overflow (CVSS 9.0)',         h:'cve.html'},
    {t:'CVE',   l:'CVE-2025-0108 — Palo Alto PAN-OS authentication bypass (CVSS 9.8)',       h:'cve.html'},
    {t:'CVE',   l:'CVE-2025-0111 — PAN-OS unauthenticated file read chained with 0108',     h:'cve.html'},
    {t:'CVE',   l:'CVE-2025-23006 — SonicWall SMA 100 pre-auth RCE (CVSS 9.8)',             h:'cve.html'},
    {t:'CVE',   l:'CVE-2025-24085 — Apple CoreMedia zero-day exploited in the wild',         h:'cve.html'},
    {t:'CVE',   l:'CVE-2025-24200 — Apple iOS USB Restricted Mode bypass zero-day',          h:'cve.html'},
    {t:'CVE',   l:'CVE-2025-24472 — FortiOS / FortiProxy authentication bypass (CVSS 9.8)', h:'cve.html'},
    {t:'CVE',   l:'CVE-2025-20188 — Cisco IOS XE web UI hard-coded JWT (CVSS 10.0)',         h:'cve.html'},
    {t:'CVE',   l:'CVE-2025-2783 — Chrome renderer zero-day used in espionage campaign',     h:'cve.html'},
    {t:'CVE',   l:'CVE-2025-22224 — VMware ESXi VCMI heap overflow zero-day (CVSS 9.3)',     h:'cve.html'},
    {t:'CVE',   l:'CVE-2025-24813 — Apache Tomcat deserialization RCE',                      h:'cve.html'},
    {t:'CVE',   l:'CVE-2025-22150 — Atlassian Confluence Server RCE',                        h:'cve.html'},
    // Legacy CVEs still tracked
    {t:'CVE',   l:'CVE-2024-47575 — FortiManager missing authentication (FortiJump)',        h:'cve.html'},
    {t:'CVE',   l:'CVE-2024-3400 — Palo Alto PAN-OS GlobalProtect command injection',        h:'cves.html'},
    {t:'CVE',   l:'CVE-2024-21762 — FortiOS out-of-bounds write SSL VPN RCE',               h:'cves.html'},
    {t:'CVE',   l:'CVE-2024-21887 — Ivanti Connect Secure command injection',                h:'cves.html'},
    {t:'CVE',   l:'CVE-2024-37085 — VMware ESXi authentication bypass via AD group abuse',  h:'cves.html'},
    {t:'CVE',   l:'CVE-2024-6387 — OpenSSH regreSSHion unauthenticated RCE',                h:'cves.html'},
    {t:'CVE',   l:'CVE-2024-1709 — ConnectWise ScreenConnect auth bypass (CVSS 10.0)',      h:'cves.html'},
    // Actors
    {t:'Actor', l:'Volt Typhoon — China-nexus, US critical infrastructure (LOTL)',          h:'actor.html'},
    {t:'Actor', l:'Salt Typhoon — China-nexus, US telecommunications espionage',            h:'actor.html'},
    {t:'Actor', l:'Akira — eCrime ransomware, Rust variant, ESXi targeting',                h:'actor.html'},
    {t:'Actor', l:'RansomEXX — financially motivated ransomware operator (CLFS exploitation)',h:'actor.html'},
    {t:'Actor', l:'Lazarus Group — DPRK state-sponsored, financial & defense sector',       h:'actor.html'},
    {t:'Actor', l:'UNC5820 — suspected China-nexus FortiManager exploitation cluster',      h:'actor.html'},
    {t:'Actor', l:'Scattered Spider — social engineering, cloud-focused eCrime group',      h:'actor.html'},
    // Vendors
    {t:'Vendor',l:'Microsoft — Windows, Azure, M365, MSRC advisories',                     h:'cves.html'},
    {t:'Vendor',l:'Palo Alto Networks — PAN-OS, GlobalProtect, Cortex advisories',          h:'cves.html'},
    {t:'Vendor',l:'Fortinet — FortiOS, FortiManager, FortiGate PSIRT',                      h:'cves.html'},
    {t:'Vendor',l:'Ivanti — Connect Secure, Policy Secure, Cloud Service Appliance',        h:'cves.html'},
    {t:'Vendor',l:'Cisco — IOS XE, ASA, Firepower, Talos advisories',                       h:'cves.html'},
    {t:'Vendor',l:'VMware — ESXi, vCenter, Workstation vulnerabilities',                    h:'cves.html'},
    {t:'Vendor',l:'Google — Chrome, Android, Project Zero research',                        h:'cves.html'},
    {t:'Vendor',l:'Apple — iOS, macOS, Safari, WebKit zero-days',                           h:'cves.html'},
    {t:'Vendor',l:'SonicWall — SMA, NSA, TZ series vulnerabilities',                        h:'cves.html'},
    {t:'Vendor',l:'Citrix — NetScaler ADC / Gateway vulnerabilities',                       h:'cves.html'},
    {t:'Vendor',l:'AWS — cloud credential theft, S3 misconfiguration campaigns',            h:'briefing.html'},
    {t:'Vendor',l:'Apache — Tomcat, Log4j, Struts vulnerabilities',                         h:'cves.html'},
    {t:'Vendor',l:'Atlassian — Confluence, Jira Server RCE advisories',                     h:'cves.html'},
    {t:'Vendor',l:'Check Point — VPN gateway, firewall advisories',                         h:'cves.html'},
    {t:'Vendor',l:'Juniper — Junos SRX, EX series vulnerabilities',                         h:'cves.html'},
    {t:'Vendor',l:'CrowdStrike — Falcon sensor, threat intelligence',                       h:'briefing.html'},
    {t:'Vendor',l:'SentinelOne — Singularity platform, detection advisories',               h:'briefing.html'},
    // Briefings & Pages
    {t:'Brief', l:'Inside the Volt Typhoon resurgence (deep dive)',                          h:'briefing.html'},
    {t:'Brief', l:'Salt Typhoon ISP intrusions — CISA & NSA joint advisory',                h:'briefing.html'},
    {t:'Brief', l:'FortiJump: the FortiManager authentication bypass deep dive',             h:'briefing.html'},
    {t:'Page',  l:'The Wire — chronological security news feed',                             h:'wire.html'},
    {t:'Page',  l:'Vulnerabilities — CVE index & CISA KEV tracker',                         h:'cves.html'},
    {t:'Page',  l:'Threat Actors — APT, eCrime, hacktivist library',                        h:'actor.html'},
    {t:'Page',  l:'Subscribe — newsletter & pricing',                                        h:'subscribe.html'},
    {t:'Page',  l:'Tip line — secure submission (Signal, SecureDrop)',                       h:'tip.html'},
    {t:'Page',  l:'About — masthead & editorial standards',                                  h:'about.html'},
    {t:'Page',  l:'Legal — privacy policy, terms, disclosures',                              h:'legal.html'},
  ];

  function renderSearch(q){
    const results = document.getElementById('cd-search-results');
    if (!results) return;
    const heading = results.parentElement.querySelector('h6');
    const Q = q.trim().toLowerCase();
    const items = Q
      ? SEARCH_INDEX.filter(x => x.l.toLowerCase().includes(Q) || x.t.toLowerCase().includes(Q))
      : SEARCH_INDEX.slice(0, 7);
    if (heading) heading.textContent = Q ? items.length + ' result' + (items.length===1?'':'s') : 'Suggested';
    results.innerHTML = items.map(x =>
      '<a class="modal-result" href="' + x.h + '">' +
      '<span class="typ">' + x.t + '</span>' +
      '<span class="ttl">' + x.l + '</span>' +
      '<span class="arr">↗</span>' +
      '</a>'
    ).join('') || '<div style="padding:24px 8px;color:var(--fg-dim);font-size:13px">No matches. Try a CVE ID, vendor name, or actor.</div>';
  }

  document.addEventListener('keydown', e=>{
    if ((e.metaKey||e.ctrlKey) && e.key.toLowerCase()==='k'){ e.preventDefault(); openSearch(); }
    if (e.key === 'Escape') closeSearch();
  });
  document.addEventListener('input', e=>{
    if (e.target && e.target.id === 'cd-search-input') renderSearch(e.target.value);
  });
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

  document.addEventListener('submit', e=>{
    const f = e.target.closest('[data-form="contact"]');
    if (!f) return;
    e.preventDefault();
    toast('Message received. The editorial desk will respond within 24h.');
    f.reset();
  });

  /* ---------- Filter chips (wire / cves pages) ---------- */
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
    document.querySelectorAll('[data-day]').forEach(day=>{
      const rows = day.parentElement.querySelectorAll('[data-cats]');
      const visible = [...rows].some(r => r.style.display !== 'none');
      day.style.display = visible ? '' : 'none';
    });
  });

  /* ---------- Wire page: activate filter from URL ?cat= or ?filter= ---------- */
  (function activateURLFilter(){
    if (!location.search) return;
    var params = new URLSearchParams(location.search);
    var cat = params.get('cat') || params.get('filter');
    if (!cat) return;
    var chip = document.querySelector('[data-filter="' + cat.toLowerCase() + '"]');
    if (chip) {
      // Use setTimeout to let the DOM render first
      setTimeout(function(){ chip.click(); }, 0);
    }
  })();

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
  const driftTargets = document.querySelectorAll('[data-metric]');
  if (driftTargets.length){
    const base = new Map();
    driftTargets.forEach(el => base.set(el, parseFloat(el.textContent.replace(/[^\d.]/g,''))));
    setInterval(()=>{
      driftTargets.forEach(el=>{
        const b = base.get(el);
        if (isNaN(b)) return;
        const next = Math.max(0, Math.round(b + (Math.random()-.5) * Math.max(1, b*0.04)));
        const unit = el.querySelector('span');
        el.firstChild && (el.firstChild.nodeValue = next.toString());
        if (unit) el.appendChild(unit);
      });
    }, 8000);
  }

  // Append a fresh feed line every ~15s into [data-live-feed]
  const FEED_SAMPLES = [
    {sev:'mid',  msg:'Recorded Future flags renewed scanning of Citrix NetScaler endpoints',    meta:'CVE-2023-3519'},
    {sev:'high', msg:'Mandiant attributes NetScaler intrusions to China-nexus cluster UNC3236', meta:'M-Trends 2025'},
    {sev:'low',  msg:'Cloudflare blocks record 5.6 Tbps DDoS aimed at telco infrastructure',   meta:'radar.cloudflare'},
    {sev:'mid',  msg:'Apple ships rapid-security response for WebKit n-day in active exploit',  meta:'HT214308'},
    {sev:'high', msg:'CISA issues emergency directive 25-03 covering Ivanti Connect Secure',    meta:'cisa.gov'},
    {sev:'crit', msg:'VMware ESXi VCMI zero-day exploitation observed across financial sector', meta:'CVE-2025-22224'},
    {sev:'low',  msg:'Chrome 136 stable channel rolls — 8 fixes, 2 high severity',             meta:'chromereleases'},
    {sev:'high', msg:'Salt Typhoon actor maintains access to two additional US ISPs — NSA',     meta:'joint-advisory'},
    {sev:'crit', msg:'Cisco IOS XE mass exploitation wave — 1,200+ devices compromised',       meta:'CVE-2025-20188'},
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
      while (feedEl.children.length > 6) feedEl.removeChild(feedEl.lastChild);
    }, 15000);
  }

  tickClock();

  /* ---------- Backfill timestamps (data-offset-sec / data-offset-min) ---------- */
  function fillOffsets(){
    const now = Date.now();
    document.querySelectorAll('[data-offset-sec]').forEach(el=>{
      const sec = parseInt(el.dataset.offsetSec, 10);
      if (isNaN(sec)) return;
      const t = new Date(now - sec * 1000);
      el.textContent = String(t.getUTCHours()).padStart(2,'0') + ':' +
                       String(t.getUTCMinutes()).padStart(2,'0') + ':' +
                    
/* ─────────────────────────────────────────────────────────────
   Cyber Digest — shared client behavior
   No build step · No dependencies
   ───────────────────────────────────────────────────────────── */

(function(){
  'use strict';

  /* ═══════════════════════════════════════════════════════════
     1. THEME
  ═══════════════════════════════════════════════════════════ */
  const THEME_KEY = 'cd-theme';
  const root = document.documentElement;
  const stored = localStorage.getItem(THEME_KEY);
  const prefersLight = window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches;
  root.dataset.theme = stored || (prefersLight ? 'light' : 'dark');

  window.toggleTheme = function(){
    const next = root.dataset.theme === 'light' ? 'dark' : 'light';
    root.dataset.theme = next;
    localStorage.setItem(THEME_KEY, next);
  };

  /* ═══════════════════════════════════════════════════════════
     2. LIVE UTC CLOCK
  ═══════════════════════════════════════════════════════════ */
  function tickClock(){
    const now = new Date();
    const hh = String(now.getUTCHours()).padStart(2,'0');
    const mm = String(now.getUTCMinutes()).padStart(2,'0');
    const ss = String(now.getUTCSeconds()).padStart(2,'0');
    document.querySelectorAll('[data-clock]').forEach(el => el.textContent = hh+':'+mm+':'+ss+' UTC');
    document.querySelectorAll('[data-clock-short]').forEach(el => el.textContent = hh+':'+mm+' UTC');
  }
  setInterval(tickClock, 1000);
  tickClock();

  /* ═══════════════════════════════════════════════════════════
     3. RELATIVE TIMESTAMPS
  ═══════════════════════════════════════════════════════════ */
  function fmtRel(secs){
    if (secs < 60)    return Math.max(1, Math.round(secs)) + 's ago';
    if (secs < 3600)  return Math.round(secs / 60) + 'm ago';
    if (secs < 86400) return Math.round(secs / 3600) + 'h ago';
    return Math.round(secs / 86400) + 'd ago';
  }
  function tickRel(){
    const now = Date.now();
    document.querySelectorAll('time[data-rel]').forEach(el => {
      const when = Date.parse(el.dataset.rel);
      if (!isNaN(when)) el.textContent = fmtRel((now - when) / 1000);
    });
  }
  setInterval(tickRel, 30000);
  tickRel();

  /* ═══════════════════════════════════════════════════════════
     4. (offset timestamps removed — feed now uses real KEV dates)
  ═══════════════════════════════════════════════════════════ */

  /* ═══════════════════════════════════════════════════════════
     5. CVE HOVER TOOLTIP (follows mouse, works over animated ticker)
  ═══════════════════════════════════════════════════════════ */
  (function initTooltip(){
    // Inject tooltip styles
    const s = document.createElement('style');
    s.textContent = `
      .cve-float-tip {
        position:fixed;z-index:9999;pointer-events:none;
        background:var(--bg-elev-3);border:1px solid var(--hairline-2);
        padding:13px 16px;max-width:320px;font-size:13px;line-height:1.52;
        border-radius:var(--radius);box-shadow:0 8px 32px rgba(0,0,0,.6);
        color:var(--fg);display:none;font-family:var(--font-sans);
        transition:opacity .12s ease;
      }
      .cve-float-tip.visible { display:block }
      .tip-id {
        font-family:var(--font-mono);font-size:11px;color:var(--accent);
        letter-spacing:.10em;margin-bottom:5px;display:flex;align-items:center;gap:6px;
      }
      .tip-vendor { font-size:11px;color:var(--fg-dim);margin-bottom:6px }
      .tip-desc   { color:var(--fg-muted);font-size:12.5px }
      .tip-foot   {
        margin-top:9px;font-family:var(--font-mono);font-size:10.5px;
        color:var(--fg-dim);border-top:1px solid var(--hairline);padding-top:7px;
      }
      /* Pause ticker scroll on hover so items are clickable */
      .signal-bar:hover .ticker-track { animation-play-state:paused }
      .ticker-item {
        display:inline-flex;align-items:center;gap:8px;color:var(--fg-muted);
        padding:0 32px;white-space:nowrap;text-decoration:none;cursor:pointer;
        transition:color .2s;
      }
      .ticker-item:hover { color:var(--fg) }
      .ticker-id  { color:var(--fg);font-family:var(--font-mono);font-size:11.5px }
      .ticker-sep { color:var(--fg-dim);opacity:.4;margin:0 2px;user-select:none }
      .ticker-desc { color:var(--fg-muted) }
      .ticker-item:hover .ticker-desc { color:var(--fg) }
    `;
    document.head.appendChild(s);

    const tip = document.createElement('div');
    tip.className = 'cve-float-tip';
    tip.setAttribute('aria-hidden', 'true');
    document.body.appendChild(tip);

    let active = false;
    document.addEventListener('mouseover', e => {
      const t = e.target.closest('[data-cve-tip]');
      if (!t) return;
      tip.innerHTML = t.dataset.cveTip;
      tip.classList.add('visible');
      active = true;
    });
    document.addEventListener('mouseout', e => {
      if (e.target.closest('[data-cve-tip]')) {
        tip.classList.remove('visible');
        active = false;
      }
    });
    document.addEventListener('mousemove', e => {
      if (!active) return;
      let x = e.clientX + 16;
      let y = e.clientY + 20; // below cursor by default
      if (x + 340 > window.innerWidth) x = e.clientX - 350;
      if (y + tip.offsetHeight > window.innerHeight) y = e.clientY - tip.offsetHeight - 10; // flip above if near bottom
      tip.style.left = x + 'px';
      tip.style.top  = y + 'px';
    });
  })();

  /* ═══════════════════════════════════════════════════════════
     6. DATA LAYER — NVD + CISA KEV
  ═══════════════════════════════════════════════════════════ */
  const CACHE_TTL     = 5 * 60 * 1000; // 5 minutes (live ticker)
  const TICKER_REFRESH = 5 * 60 * 1000; // re-fetch every 5 min

  // Ticker state
  let tickerAllItems      = [];
  let tickerActiveVendors = new Set();

  function getCached(key){
    try {
      const raw = sessionStorage.getItem(key);
      if (!raw) return null;
      const obj = JSON.parse(raw);
      if (Date.now() - obj.ts > CACHE_TTL) return null;
      return obj.data;
    } catch { return null; }
  }
  function setCache(key, data){
    try { sessionStorage.setItem(key, JSON.stringify({ts: Date.now(), data})); } catch {}
  }

  function parseKEVJson(json){
    const all = json.vulnerabilities || [];
    const cutoff7d = new Date() - 7 * 864e5;
    const kev7d = all.filter(v => new Date(v.dateAdded) >= cutoff7d).length;
    const items = all
      .sort((a, b) => b.dateAdded.localeCompare(a.dateAdded))
      .slice(0, 25)
      .map(v => ({
        id:        v.cveID,
        vendor:    v.vendorProject,
        product:   v.product,
        name:      v.vulnerabilityName,
        desc:      v.shortDescription,
        dateAdded: v.dateAdded,
        severity:  'high',
        nvdUrl:    'https://nvd.nist.gov/vuln/detail/' + v.cveID,
        isKEV:     true
      }));
    return { items, kev7d };
  }

  async function fetchKEV(){
    const cached = getCached('cd_kev_v4');
    if (cached) return cached;

    // Try local snapshot first (committed daily by GitHub Action — same origin, no CORS)
    try {
      const lr = await fetch('/kev.json', {signal: AbortSignal.timeout ? AbortSignal.timeout(5000) : undefined});
      if (lr.ok){
        const result = parseKEVJson(await lr.json());
        setCache('cd_kev_v4', result);
        return result;
      }
    } catch {}

    // Fall back to CISA direct
    const r = await fetch(
      'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
      {signal: AbortSignal.timeout ? AbortSignal.timeout(12000) : undefined}
    );
    if (!r.ok) throw new Error('KEV ' + r.status);
    const result = parseKEVJson(await r.json());
    setCache('cd_kev_v4', result);
    return result;
  }

  /* ═══════════════════════════════════════════════════════════
     6b. DYNAMIC CVE GRID — live from CISA KEV
  ═══════════════════════════════════════════════════════════ */
  function populateCVEGrid(items){
    const grid = document.querySelector('[data-cve-grid]');
    if (!grid || !items.length) return;
    // Take top 6 most-recently-added KEV entries
    const top = items.slice(0, 6);
    grid.innerHTML = top.map(item => {
      const vendor  = item.vendor  || '';
      const product = item.product || '';
      const title   = vendor + (product ? ' \xb7 ' + product : '');
      const desc    = (item.name || item.desc || '').slice(0, 120);
      const added   = (item.dateAdded || '').slice(0, 7); // YYYY-MM
      const label   = added ? 'KEV ' + added : 'KEV';
      // 8 filled bars — all KEV entries are actively exploited
      const bars    = '<i class="bar on"></i>'.repeat(8) + '<i class="bar"></i><i class="bar"></i>';
      return '<a href="' + item.nvdUrl + '" target="_blank" rel="noopener" class="cve crit">' +
        '<div class="vendor">' + title + '</div>' +
        '<div class="id">' + item.id + ' <span class="kev" style="font-size:10px;padding:2px 5px;vertical-align:middle">KEV</span></div>' +
        '<h4>' + desc + (desc.length >= 120 ? '…' : '') + '</h4>' +
        '<div class="bars">' + bars + '</div>' +
        '<div class="foot"><span>' + label + '</span><span class="kev">EXPLOITED</span></div>' +
        '</a>';
    }).join('');
  }

  function updateConsoleMetrics(kev7d, nvd7d){
    const cveEl  = document.getElementById('console-cve7d');
    const cveSub = document.getElementById('console-cve7d-sub');
    const kevEl  = document.getElementById('console-kev7d');
    const kevSub = document.getElementById('console-kev7d-sub');
    if (cveEl  && nvd7d != null) cveEl.textContent  = nvd7d.toLocaleString();
    if (cveSub && nvd7d != null) cveSub.textContent = 'via NVD \xb7 7-day window';
    if (kevEl  && kev7d != null) kevEl.textContent  = kev7d;
    if (kevSub && kev7d != null) kevSub.textContent = 'CISA known exploited';
  }

  async function fetchNVD(){
    const cached = getCached('cd_nvd_v3');
    if (cached) return cached;
    // Filter to CVEs published in the last 90 days to avoid surfacing ancient entries
    const now   = new Date();
    const past  = new Date(now - 90 * 24 * 3600 * 1000);
    const fmt   = d => d.toISOString().slice(0, 10) + 'T00:00:00.000';
    const r = await fetch(
      'https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=20&noRejected' +
      '&pubStartDate=' + fmt(past) + '&pubEndDate=' + fmt(now),
      {signal: AbortSignal.timeout ? AbortSignal.timeout(8000) : undefined}
    );
    if (!r.ok) throw new Error('NVD ' + r.status);
    const json = await r.json();
    const items = (json.vulnerabilities || []).map(v => {
      const cve  = v.cve;
      const desc = ((cve.descriptions || []).find(d => d.lang === 'en') || {}).value || '';
      const m31  = ((cve.metrics || {}).cvssMetricV31 || [])[0];
      const m30  = ((cve.metrics || {}).cvssMetricV30 || [])[0];
      const m    = m31 || m30;
      return {
        id:        cve.id,
        desc:      desc,
        score:     m ? m.cvssData.baseScore : null,
        severity:  m ? m.cvssData.baseSeverity.toLowerCase() : 'medium',
        published: (cve.published || '').slice(0, 10),
        nvdUrl:    'https://nvd.nist.gov/vuln/detail/' + cve.id
      };
    });
    setCache('cd_nvd_v3', items);
    return items;
  }

  /* ═══════════════════════════════════════════════════════════
     7. SEVERITY HELPERS
  ═══════════════════════════════════════════════════════════ */
  function sevClass(sev){
    const s = (sev || '').toLowerCase();
    if (s === 'critical') return 'crit';
    if (s === 'high')     return 'high';
    if (s === 'medium')   return 'mid';
    return 'low';
  }
  function sevLabel(sev){
    const s = (sev || '').toLowerCase();
    if (s === 'critical') return 'CRIT';
    if (s === 'high')     return 'HIGH';
    if (s === 'medium')   return 'MED';
    return 'LOW';
  }
  function fmtDate(iso){
    if (!iso) return '—';
    const d = new Date(iso + (iso.length === 10 ? 'T00:00:00Z' : ''));
    return d.toLocaleDateString('en-GB', {day:'2-digit', month:'short', year:'numeric', timeZone:'UTC'});
  }

  function buildTip(item){
    const score  = item.score != null ? ' · CVSS ' + item.score : '';
    const vendor = item.vendor
      ? (item.product ? item.vendor + ' · ' + item.product : item.vendor)
      : '';
    const date   = item.dateAdded || item.published;
    const kev    = item.isKEV
      ? '<span style="color:var(--status-crit);font-size:10px;border:1px solid rgba(216,92,92,.4);padding:1px 6px;letter-spacing:.1em">EXPLOITED</span>'
      : '';
    return '<div class="tip-id">' + item.id + score + kev + '</div>' +
      (vendor ? '<div class="tip-vendor">' + vendor + '</div>' : '') +
      '<div class="tip-desc">' + (item.name || item.desc || '').slice(0, 160) + '</div>' +
      (date ? '<div class="tip-foot">Added ' + fmtDate(date) +
        ' · <a href="' + item.nvdUrl + '" target="_blank" rel="noopener" style="color:var(--accent)">NVD ↗</a>' +
      '</div>' : '');
  }

  /* ═══════════════════════════════════════════════════════════
     8. LIVE TICKER — real CVE data with click + hover + vendor filter
  ═══════════════════════════════════════════════════════════ */
  const TICKER_FALLBACK = [
    {id:'CVE-2025-22224', vendor:'VMware',    product:'ESXi VCMI',      desc:'Heap overflow zero-day exploited in wild',              severity:'critical', nvdUrl:'https://nvd.nist.gov/vuln/detail/CVE-2025-22224', isKEV:true},
    {id:'CVE-2025-21333', vendor:'Microsoft', product:'Hyper-V',        desc:'NT Kernel privilege escalation exploited as zero-day',  severity:'high',     nvdUrl:'https://nvd.nist.gov/vuln/detail/CVE-2025-21333', isKEV:true},
    {id:'CVE-2025-0282',  vendor:'Ivanti',    product:'Connect Secure', desc:'Stack-based buffer overflow — unauthenticated RCE',    severity:'critical', nvdUrl:'https://nvd.nist.gov/vuln/detail/CVE-2025-0282',  isKEV:true},
    {id:'CVE-2024-47575', vendor:'Fortinet',  product:'FortiManager',   desc:'Missing auth in fgfm daemon (FortiJump) — CVSS 9.8',   severity:'critical', nvdUrl:'https://nvd.nist.gov/vuln/detail/CVE-2024-47575', isKEV:true},
    {id:'CVE-2024-3400',  vendor:'Palo Alto', product:'PAN-OS',         desc:'GlobalProtect command injection CVSS 10.0',             severity:'critical', nvdUrl:'https://nvd.nist.gov/vuln/detail/CVE-2024-3400',  isKEV:true},
    {id:'CVE-2024-21762', vendor:'Fortinet',  product:'FortiOS SSL VPN',desc:'Out-of-bounds write — unauthenticated RCE CVSS 9.6',   severity:'critical', nvdUrl:'https://nvd.nist.gov/vuln/detail/CVE-2024-21762', isKEV:true},
    {id:'CVE-2024-6387',  vendor:'OpenSSH',   product:'sshd',           desc:'Signal handler race "regreSSHion" — unauthenticated RCE', severity:'critical', nvdUrl:'https://nvd.nist.gov/vuln/detail/CVE-2024-6387', isKEV:true},
    {id:'CVE-2024-37085', vendor:'VMware',    product:'ESXi',           desc:'AD auth bypass via ESX Admins group — used by Akira',  severity:'high',     nvdUrl:'https://nvd.nist.gov/vuln/detail/CVE-2024-37085', isKEV:true},
  ];

  function buildTickerItem(item){
    const cls  = sevClass(item.severity);
    const lbl  = sevLabel(item.severity);
    const text = (item.name || item.desc || '').slice(0, 80);
    const tip  = buildTip(item).replace(/"/g, '&quot;');
    return '<a class="ticker-item" href="' + item.nvdUrl + '" target="_blank" rel="noopener" data-cve-tip="' + tip + '">' +
      '<span class="sev ' + cls + '">' + lbl + '</span>' +
      '<span class="ticker-id">' + item.id + '</span>' +
      '<span class="ticker-sep">—</span>' +
      '<span class="ticker-desc">' + text + (text.length >= 80 ? '…' : '') + '</span>' +
      '</a>';
  }

  function populateTicker(items){
    const track = document.querySelector('[data-ticker-track]');
    if (!track || !items.length) return;
    const set  = items.slice(0, 12);
    // Need enough items to fill viewport for seamless loop; pad if few items
    const fill = set.length < 4 ? set.concat(set).concat(set) : set;
    const half = fill.map(buildTickerItem).join('');
    track.innerHTML = half + half; // duplicate for seamless loop
    // Adjust animation speed based on item count
    const dur = Math.max(30, fill.length * 6) + 's';
    track.style.animationDuration = dur;
  }

  // Apply active vendor filter to the full items array and re-render ticker
  function applyTickerFilter(){
    if (!tickerAllItems.length) return;
    const filtered = tickerActiveVendors.size === 0
      ? tickerAllItems
      : tickerAllItems.filter(i => tickerActiveVendors.has((i.vendor || '').toLowerCase()));
    populateTicker(filtered.length ? filtered : tickerAllItems);
  }

  // Build vendor filter chips from live data
  function buildTickerVendorBar(items){
    const bar = document.querySelector('[data-ticker-vendor-row]');
    if (!bar) return;
    const wrap = bar.closest('.ticker-vendor-bar');

    // Extract unique vendors, sorted by frequency in KEV data
    const vendorCount = {};
    items.forEach(i => { if (i.vendor) vendorCount[i.vendor] = (vendorCount[i.vendor] || 0) + 1; });
    const vendors = Object.entries(vendorCount)
      .sort((a, b) => b[1] - a[1])
      .map(([v]) => v)
      .slice(0, 10);

    if (!vendors.length){ if (wrap) wrap.style.display = 'none'; return; }

    bar.innerHTML = '<span class="tvb-label">Vendor</span>' +
      vendors.map(v =>
        '<button class="ticker-vchip" data-ticker-vendor="' + v.toLowerCase().replace(/"/g, '') + '">' + v + '</button>'
      ).join('') +
      '<button class="ticker-vchip" id="ticker-vchip-all" style="margin-left:auto">All</button>';

    if (wrap) wrap.style.display = '';

    bar.addEventListener('click', function(e){
      const chip = e.target.closest('[data-ticker-vendor]');
      const allBtn = e.target.closest('#ticker-vchip-all');
      if (allBtn){
        tickerActiveVendors.clear();
        bar.querySelectorAll('.ticker-vchip').forEach(c => c.classList.remove('on'));
        applyTickerFilter();
        return;
      }
      if (!chip) return;
      const v = chip.dataset.tickerVendor;
      if (tickerActiveVendors.has(v)){
        tickerActiveVendors.delete(v);
        chip.classList.remove('on');
      } else {
        tickerActiveVendors.add(v);
        chip.classList.add('on');
      }
      // Update All button state
      const allChip = bar.querySelector('#ticker-vchip-all');
      if (allChip) allChip.classList.toggle('on', tickerActiveVendors.size === 0);
      applyTickerFilter();
    });
  }

  // Render fallback immediately, swap in live data async
  tickerAllItems = TICKER_FALLBACK;
  populateTicker(TICKER_FALLBACK);

  async function loadTickerData(forceFresh){
    if (forceFresh){
      try { sessionStorage.removeItem('cd_kev_v4'); } catch {}
    }
    try {
      const kevData = await fetchKEV();
      const kev = kevData.items;
      if (kev && kev.length){
        tickerAllItems = kev;
        applyTickerFilter();
        if (!forceFresh) { consoleFeedAllItems = kev; populateConsoleFeed(kev); }
        buildTickerVendorBar(kev);
        populateCVEGrid(kev);
        // Show KEV count immediately; then try to get NVD 7d count
        updateConsoleMetrics(kevData.kev7d, null);
        try {
          const now = new Date(), ago = new Date(now - 7 * 864e5);
          const fmt = d => d.toISOString().slice(0, 19) + '.000';
          const nr  = await fetch(
            'https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=1' +
            '&pubStartDate=' + fmt(ago) + '&pubEndDate=' + fmt(now),
            {signal: AbortSignal.timeout ? AbortSignal.timeout(8000) : undefined}
          );
          const nj = await nr.json();
          updateConsoleMetrics(kevData.kev7d, nj.totalResults);
        } catch { /* KEV count already shown; NVD count stays blank */ }
      }
    } catch {
      try {
        const nvd = await fetchNVD();
        if (nvd && nvd.length){
          tickerAllItems = nvd;
          applyTickerFilter();
          buildTickerVendorBar(nvd);
          populateCVEGrid(nvd);
          if (!forceFresh) { consoleFeedAllItems = nvd; populateConsoleFeed(nvd); }
          updateConsoleMetrics(null, nvd.length);
        }
      } catch {}
    }
  }

  // Initial load
  loadTickerData(false);
  // Live refresh every 5 minutes
  setInterval(function(){ loadTickerData(true); }, TICKER_REFRESH);

  /* ═══════════════════════════════════════════════════════════
     9. CONSOLE FEED — live log on homepage
  ═══════════════════════════════════════════════════════════ */
  function populateConsoleFeed(items){
    const feedEl = document.querySelector('[data-live-feed]');
    if (!feedEl || !items.length) return;
    feedEl.innerHTML = '';
    items.slice(0, 6).forEach(item => {
      const cls    = sevClass(item.severity);
      const lbl    = sevLabel(item.severity);
      const vendor = item.vendor
        ? (item.product ? item.vendor + ' · ' + item.product : item.vendor) : '';
      const msg    = (item.name || item.desc || '').slice(0, 62);
      const date   = (item.dateAdded || item.published || '').slice(0, 10);
      const tip    = buildTip(item).replace(/"/g, '&quot;');
      const TECH_KW2 = { vpn:['vpn','connect secure','fortios','globalprotect','pulse'], hypervisor:['esxi','vcenter','vcmi','hyper-v','vsphere'], os:['windows','linux','kernel','nt kernel','android'], network:['fortimanager','fortigate','firewall','junos','nexus','router'] };
      const KIT_KW2  = { ransomware:['ransomware','lockbit','akira','blackcat','alphv','clop'], rat:['cobalt strike','remote access trojan'], loader:['loader','dropper','bumblebee'], rootkit:['rootkit','bootkit','uefi'] };
      const hay2 = ((item.name || '') + ' ' + (item.desc || '') + ' ' + (item.product || '')).toLowerCase();
      const feedTech   = Object.keys(TECH_KW2).find(k => TECH_KW2[k].some(kw => hay2.includes(kw))) || '';
      const feedKit    = Object.keys(KIT_KW2).find(k  => KIT_KW2[k].some(kw  => hay2.includes(kw)))  || '';
      const feedVendor = (item.vendor || '').toLowerCase().split(' ')[0];
      const line   = document.createElement('div');
      line.className = 'line';
      line.dataset.feedVendor = feedVendor;
      line.dataset.feedTech   = feedTech;
      line.dataset.feedKit    = feedKit;
      line.innerHTML =
        '<span class="t">' + (date || '') + '</span>' +
        '<span class="sev ' + cls + '">' + lbl + '</span>' +
        '<span class="msg">' + (vendor ? vendor + ' — ' : '') + msg + (msg.length >= 62 ? '…' : '') + '</span>' +
        '<span class="meta"><a href="' + item.nvdUrl + '" target="_blank" rel="noopener" data-cve-tip="' + tip + '" ' +
          'style="color:var(--fg-muted);border-bottom:1px solid var(--hairline-2)">' + item.id + '</a></span>';
      feedEl.appendChild(line);
    });
  }

  /* ═══════════════════════════════════════════════════════════
     9b. CONSOLE FEED FILTERS (vendor / kit / tech)
  ═══════════════════════════════════════════════════════════ */
  let consoleFeedAllItems  = [];
  let consoleFeedActiveVendors = new Set(); // empty = show all

  function applyConsoleFilters(){
    if (consoleFeedAllItems.length) {
      const filtered = consoleFeedAllItems.filter(item => {
        const v = (item.vendor || '').toLowerCase();
        return consoleFeedActiveVendors.size === 0 ||
          [...consoleFeedActiveVendors].some(sel => v.includes(sel));
      });
      populateConsoleFeed(filtered.length ? filtered : consoleFeedAllItems);
      return;
    }
    // Fallback: filter static HTML .line elements
    document.querySelectorAll('[data-live-feed] .line').forEach(line => {
      const lv = (line.dataset.feedVendor || '').toLowerCase();
      const ok = consoleFeedActiveVendors.size === 0 ||
        [...consoleFeedActiveVendors].some(sel => lv.includes(sel));
      line.style.display = ok ? '' : 'none';
    });
  }

  // Multi-select vendor chips — "All" clears selection; individual chips toggle
  document.querySelectorAll('.cf-chip[data-cf-vendor]').forEach(chip => {
    chip.addEventListener('click', () => {
      const v = chip.dataset.cfVendor;
      if (v === 'all'){
        consoleFeedActiveVendors.clear();
        document.querySelectorAll('.cf-chip[data-cf-vendor]').forEach(c => c.classList.remove('on'));
        chip.classList.add('on');
      } else {
        if (consoleFeedActiveVendors.has(v)){
          consoleFeedActiveVendors.delete(v);
          chip.classList.remove('on');
        } else {
          consoleFeedActiveVendors.add(v);
          chip.classList.add('on');
        }
        // If nothing selected, default back to All
        const allBtn = document.querySelector('.cf-chip[data-cf-vendor="all"]');
        if (consoleFeedActiveVendors.size === 0 && allBtn) allBtn.classList.add('on');
        else if (allBtn) allBtn.classList.remove('on');
      }
      applyConsoleFilters();
    });
  });

  /* ═══════════════════════════════════════════════════════════
     10. (metric drift removed — metrics now come from real API data)
  ═══════════════════════════════════════════════════════════ */

  /* ═══════════════════════════════════════════════════════════
     11. SEARCH MODAL (⌘K / Ctrl+K)
  ═══════════════════════════════════════════════════════════ */
  const SEARCH_INDEX = [
    {t:'CVE',   l:'CVE-2025-22224 — VMware ESXi VCMI heap overflow (zero-day, CVSS 9.3)',  h:'https://nvd.nist.gov/vuln/detail/CVE-2025-22224', ext:true},
    {t:'CVE',   l:'CVE-2025-0282 — Ivanti Connect Secure stack buffer overflow (RCE)',      h:'https://nvd.nist.gov/vuln/detail/CVE-2025-0282',  ext:true},
    {t:'CVE',   l:'CVE-2024-47575 — Fortinet FortiManager FortiJump (missing auth, 9.8)',   h:'https://nvd.nist.gov/vuln/detail/CVE-2024-47575', ext:true},
    {t:'CVE',   l:'CVE-2024-3400 — Palo Alto PAN-OS GlobalProtect command injection (10.0)',h:'https://nvd.nist.gov/vuln/detail/CVE-2024-3400',  ext:true},
    {t:'CVE',   l:'CVE-2024-21762 — Fortinet FortiOS SSL VPN out-of-bounds write (9.6)',    h:'https://nvd.nist.gov/vuln/detail/CVE-2024-21762', ext:true},
    {t:'CVE',   l:'CVE-2024-6387 — OpenSSH regreSSHion unauthenticated RCE',               h:'https://nvd.nist.gov/vuln/detail/CVE-2024-6387',  ext:true},
    {t:'CVE',   l:'CVE-2024-37085 — VMware ESXi AD auth bypass (Akira/Black Basta)',        h:'https://nvd.nist.gov/vuln/detail/CVE-2024-37085', ext:true},
    {t:'Actor', l:'Volt Typhoon — China-nexus, US critical infrastructure',                  h:'actor.html'},
    {t:'Actor', l:'Salt Typhoon — China-nexus, US telecommunications',                       h:'actor.html'},
    {t:'Actor', l:'Akira — eCrime ransomware affiliate group',                                h:'actor.html'},
    {t:'Actor', l:'Lazarus Group — DPRK, financial crime & espionage',                       h:'actor.html'},
    {t:'Page',  l:'The Wire — chronological threat news feed',                               h:'wire.html'},
    {t:'Page',  l:'Vulnerabilities — CVE index & CISA KEV tracker',                          h:'cves.html'},
    {t:'Page',  l:'Briefings — analyst-written intelligence reports',                         h:'briefing.html'},
    {t:'KEV',   l:'CISA Known Exploited Vulnerabilities catalog',                             h:'https://www.cisa.gov/known-exploited-vulnerabilities-catalog', ext:true},
    {t:'Source',l:'Krebs on Security — investigative security journalism',                    h:'https://krebsonsecurity.com/', ext:true},
    {t:'Source',l:'Google TAG — Threat Analysis Group research blog',                         h:'https://blog.google/threat-analysis-group/', ext:true},
    {t:'Source',l:'Mandiant / Google TI — threat intelligence blog',                          h:'https://cloud.google.com/blog/topics/threat-intelligence', ext:true},
  ];

  function openSearch(){
    let m = document.getElementById('cd-search-modal');
    if (!m){
      m = document.createElement('div');
      m.id = 'cd-search-modal';
      m.className = 'modal-backdrop';
      m.innerHTML =
        '<div class="modal" role="dialog" aria-modal="true">' +
          '<div class="modal-search">' +
            '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="color:var(--fg-dim)"><circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/></svg>' +
            '<input id="cd-search-input" placeholder="Search CVE, vendor, actor, briefing…" autocomplete="off" />' +
            '<span class="kbd">Esc</span>' +
          '</div>' +
          '<div class="modal-section"><h6>Suggested</h6><div class="modal-results" id="cd-search-results"></div></div>' +
          '<div class="modal-foot">' +
            '<span>CVEs → NVD · Sources open externally</span>' +
            '<span class="keys"><span><span class="k">↵</span> open</span><span><span class="k">↑↓</span> navigate</span><span><span class="k">Esc</span> close</span></span>' +
          '</div>' +
        '</div>';
      document.body.appendChild(m);
      m.addEventListener('click', e => { if (e.target === m) closeSearch(); });
    }
    renderSearch('');
    m.classList.add('open');
    setTimeout(() => { const inp = document.getElementById('cd-search-input'); if (inp) inp.focus(); }, 30);
    document.body.style.overflow = 'hidden';
  }

  function closeSearch(){
    const m = document.getElementById('cd-search-modal');
    if (m) m.classList.remove('open');
    document.body.style.overflow = '';
  }

  function renderSearch(q){
    const results = document.getElementById('cd-search-results');
    const heading = results && results.parentElement.querySelector('h6');
    if (!results) return;
    const Q = q.trim().toLowerCase();
    const items = Q
      ? SEARCH_INDEX.filter(x => x.l.toLowerCase().includes(Q) || x.t.toLowerCase().includes(Q))
      : SEARCH_INDEX.slice(0, 8);
    if (heading) heading.textContent = Q ? items.length + ' result' + (items.length === 1 ? '' : 's') : 'Suggested';
    results.innerHTML = items.map(x =>
      '<a class="modal-result" href="' + x.h + '"' + (x.ext ? ' target="_blank" rel="noopener"' : '') + '>' +
        '<span class="typ">' + x.t + '</span>' +
        '<span class="ttl">' + x.l + '</span>' +
        '<span class="arr">' + (x.ext ? '↗' : '→') + '</span>' +
      '</a>'
    ).join('') || '<div style="padding:24px 8px;color:var(--fg-dim);font-size:13px">No matches. Try a CVE ID, vendor, or actor name.</div>';
  }

  document.addEventListener('keydown', e => {
    if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k'){ e.preventDefault(); openSearch(); }
    if (e.key === 'Escape') closeSearch();
  });
  document.addEventListener('input', e => {
    if (e.target && e.target.id === 'cd-search-input') renderSearch(e.target.value);
  });
  document.addEventListener('click', e => {
    const t = e.target.closest('[data-action="search"]');
    if (t){ e.preventDefault(); openSearch(); }
  });

  /* ═══════════════════════════════════════════════════════════
     12. TOAST
  ═══════════════════════════════════════════════════════════ */
  function toast(msg){
    let t = document.getElementById('cd-toast');
    if (!t){
      t = document.createElement('div');
      t.id = 'cd-toast';
      t.className = 'toast';
      document.body.appendChild(t);
    }
    t.innerHTML = '<span class="ok">✓</span> ' + msg;
    t.classList.add('show');
    clearTimeout(t._timer);
    t._timer = setTimeout(() => t.classList.remove('show'), 3200);
  }

  /* ═══════════════════════════════════════════════════════════
     13. FORM HANDLERS
  ═══════════════════════════════════════════════════════════ */
  document.addEventListener('submit', e => {
    const f = e.target.closest('[data-form="subscribe"]');
    if (!f) return;
    e.preventDefault();
    const input = f.querySelector('input[type="email"]');
    const email = ((input && input.value) || '').trim();
    if (!email || !/.+@.+\..+/.test(email)){ toast('Enter a valid email address.'); return; }
    if (input) input.value = '';
    toast('Subscribed — check your inbox to confirm.');
  });
  document.addEventListener('submit', e => {
    const f = e.target.closest('[data-form="contact"]');
    if (!f) return;
    e.preventDefault();
    toast('Message received. The desk will respond within 24h.');
    f.reset();
  });

  /* ═══════════════════════════════════════════════════════════
     14. FILTER CHIPS — severity (single-select) + vendor (multi-select)
  ═══════════════════════════════════════════════════════════ */
  function applyTableFilters(){
    const sevChip      = document.querySelector('[data-filter-group] [data-filter].on');
    const sevTag       = sevChip ? sevChip.dataset.filter : 'all';
    const activeVendors = [...document.querySelectorAll('[data-vendor-filter].on')]
      .map(c => c.dataset.vendorFilter);

    let visCount = 0;
    document.querySelectorAll('[data-cats]').forEach(row => {
      const cats   = row.dataset.cats ? row.dataset.cats.split(/\s+/) : [];
      const vendor = (row.dataset.vendor || '').toLowerCase();
      const sevOk  = sevTag === 'all' || cats.includes(sevTag);
      const venOk  = activeVendors.length === 0 || activeVendors.includes(vendor);
      const show   = sevOk && venOk;
      row.style.display = show ? '' : 'none';
      if (show) visCount++;
    });

    document.querySelectorAll('[data-day]').forEach(day => {
      const rows    = day.parentElement.querySelectorAll('[data-cats]');
      const visible = [...rows].some(r => r.style.display !== 'none');
      day.style.display = visible ? '' : 'none';
    });

    const countEl = document.querySelector('[data-result-count]');
    if (countEl) countEl.textContent = visCount + ' CVE' + (visCount !== 1 ? 's' : '');
  }

  document.addEventListener('click', e => {
    const sevChip = e.target.closest('[data-filter]');
    if (sevChip){
      const group = sevChip.closest('[data-filter-group]');
      if (!group) return;
      group.querySelectorAll('[data-filter]').forEach(x => x.classList.toggle('on', x === sevChip));
      applyTableFilters();
      return;
    }
    const venChip = e.target.closest('[data-vendor-filter]');
    if (venChip){
      venChip.classList.toggle('on');
      applyTableFilters();
    }
  });

  /* ═══════════════════════════════════════════════════════════
     15. MOBILE NAV DRAWER
  ═══════════════════════════════════════════════════════════ */
  window.cdMobileNav = function(open){
    let n = document.getElementById('cd-mobile-nav');
    if (open && !n){
      n = document.createElement('nav');
      n.id = 'cd-mobile-nav';
      n.className = 'mobile-nav open';
      n.innerHTML =
        '<button class="close" onclick="cdMobileNav(false)" aria-label="Close menu">&times;</button>' +
        '<a href="index.html">Home <span class="arr">&rarr;</span></a>' +
        '<a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog" target="_blank" rel="noopener">CISA KEV <span class="arr">&rarr;</span></a>' +
        '<a href="https://nvd.nist.gov/" target="_blank" rel="noopener">NVD <span class="arr">&rarr;</span></a>';
      document.body.appendChild(n);
    } else if (n){
      n.classList.toggle('open', !!open);
    }
  };

  /* ═══════════════════════════════════════════════════════════
     17. THREAT ACTORS CONFIG
     Update this array to change tracked actors — renders dynamically.
     Sourced from MITRE ATT&CK / CISA advisories.
  ═══════════════════════════════════════════════════════════ */
  const ACTORS = [
    {
      name:   'Volt Typhoon',
      nation: 'China',
      sector: 'Critical infrastructure',
      url:    'https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-038a'
    },
    {
      name:   'APT28 / Fancy Bear',
      nation: 'Russia (GRU)',
      sector: 'Espionage',
      url:    'https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-108a'
    },
    {
      name:   'Lazarus Group',
      nation: 'North Korea',
      sector: 'Financial / espionage',
      url:    'https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-241a'
    },
    {
      name:   'Salt Typhoon',
      nation: 'China',
      sector: 'Telecom / ISP',
      url:    'https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-338a'
    },
    {
      name:   'RansomHub',
      nation: 'Crimeware',
      sector: 'Ransomware-as-a-service',
      url:    'https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-242a'
    },
  ];

  (function renderActors(){
    const el = document.querySelector('[data-actors-list]');
    if (!el) return;
    el.innerHTML = '<div class="ca-hdr">Top tracked threat actors</div>' +
      ACTORS.map(a =>
        '<a class="ca-item" href="' + a.url + '" target="_blank" rel="noopener noreferrer">' +
          a.name +
          '<span class="ca-tag">' + a.nation + ' &middot; ' + a.sector + '</span>' +
        '</a>'
      ).join('');
  })();

  /* ═══════════════════════════════════════════════════════════
     16. HIGHLIGHT CURRENT PAGE IN NAV
  ═══════════════════════════════════════════════════════════ */
  (function markCurrent(){
    const path = location.pathname.split('/').pop() || 'index.html';
    document.querySelectorAll('.nav a').forEach(a => {
      const href = (a.getAttribute('href') || '').split('?')[0];
      if (href === path) a.setAttribute('aria-current', 'page');
    });
  })();

})();

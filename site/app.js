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
  const CACHE_TTL      = 5 * 60 * 1000; // 5 minutes (live ticker)
  const TICKER_REFRESH = 5 * 60 * 1000; // re-fetch every 5 min
  const KEV_STALE_DAYS = 3;             // treat kev.json as stale if newest entry > 3 days old

  // Ticker state
  let tickerAllItems      = [];
  let lastKev7d           = null;       // persist last known kev7d across fetch paths

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

    let staleResult = null;

    // Try local snapshot first (committed daily by GitHub Action — same origin, no CORS)
    try {
      const lr = await fetch('/kev.json', {signal: AbortSignal.timeout ? AbortSignal.timeout(5000) : undefined});
      if (lr.ok){
        const json = await lr.json();
        const all  = json.vulnerabilities || [];
        // Staleness check: find most recently added entry
        const newest = all.reduce((m, v) => v.dateAdded > m ? v.dateAdded : m, '');
        const ageDays = newest ? (Date.now() - new Date(newest).getTime()) / 864e5 : 999;
        const result  = parseKEVJson(json);
        if (ageDays <= KEV_STALE_DAYS) {
          setCache('cd_kev_v4', result);
          return result;
        }
        // Data is stale — keep as fallback, try CISA direct below
        staleResult = result;
      }
    } catch {}

    // Try CISA direct (may be blocked by CORS in some browsers — if so we fall back to stale)
    try {
      const r = await fetch(
        'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
        {signal: AbortSignal.timeout ? AbortSignal.timeout(12000) : undefined}
      );
      if (r.ok) {
        const result = parseKEVJson(await r.json());
        setCache('cd_kev_v4', result);
        return result;
      }
    } catch {}

    // If CISA direct failed but we have a stale local snapshot, use it
    if (staleResult) {
      // Don't cache stale result — allow retry on next tick
      return staleResult;
    }

    throw new Error('KEV fetch failed — no local snapshot available');
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
    if (cveEl && nvd7d != null && nvd7d > 0) {
      cveEl.textContent = nvd7d.toLocaleString();
      const k = cveEl.closest('.metric') && cveEl.closest('.metric').querySelector('.k');
      if (k) k.textContent = 'New CVEs (7d)';
      if (cveSub) cveSub.textContent = 'via NVD \xb7 7-day window';
    }
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
        // Persist kev7d for use in fallback paths
        if (kevData.kev7d != null) lastKev7d = kevData.kev7d;
        tickerAllItems = kev;
        populateTicker(kev);
        if (!forceFresh) populateConsoleFeed(kev);
        populateCVEGrid(kev);
        // Show KEV count immediately; then try to get NVD 7d count
        updateConsoleMetrics(lastKev7d, null);
        try {
          const now = new Date(), ago = new Date(now - 7 * 864e5);
          const fmt = d => d.toISOString().slice(0, 19) + '.000';
          const nr  = await fetch(
            'https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=1' +
            '&pubStartDate=' + fmt(ago) + '&pubEndDate=' + fmt(now),
            {signal: AbortSignal.timeout ? AbortSignal.timeout(8000) : undefined}
          );
          const nj = await nr.json();
          updateConsoleMetrics(lastKev7d, nj.totalResults);
        } catch { /* KEV count already shown; NVD count stays as-is */ }
      }
    } catch {
      try {
        const nvd = await fetchNVD();
        if (nvd && nvd.length){
          tickerAllItems = nvd;
          populateTicker(nvd);
          populateCVEGrid(nvd);
          if (!forceFresh) populateConsoleFeed(nvd);
          // Use lastKev7d if we have it from a previous KEV fetch; otherwise show NVD count
          updateConsoleMetrics(lastKev7d, nvd.length);
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
    {t:'Actor', l:'Volt Typhoon — China-nexus, US critical infrastructure',                  h:'https://attack.mitre.org/groups/G1017/', ext:true},
    {t:'Actor', l:'Salt Typhoon — China-nexus, US telecommunications',                       h:'https://attack.mitre.org/groups/G1045/', ext:true},
    {t:'Actor', l:'Scattered Spider — eCrime, identity/social engineering',                  h:'https://attack.mitre.org/groups/G1015/', ext:true},
    {t:'Actor', l:'RansomHub — crimeware, ransomware-as-a-service',                          h:'https://attack.mitre.org/groups/G1075/', ext:true},
    {t:'Actor', l:'APT28 / Fancy Bear — Russia GRU, espionage',                              h:'https://attack.mitre.org/groups/G0007/', ext:true},
    {t:'Actor', l:'Lazarus Group — DPRK, financial crime & espionage',                       h:'https://attack.mitre.org/groups/G0032/', ext:true},
    {t:'Page',  l:'Vulnerabilities — CVE index & CISA KEV tracker',                          h:'cves.html'},
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
      url:    'https://attack.mitre.org/groups/G1017/'
    },
    {
      name:   'Salt Typhoon',
      nation: 'China (MSS)',
      sector: 'Telecom / ISP',
      url:    'https://attack.mitre.org/groups/G1045/'
    },
    {
      name:   'Scattered Spider',
      nation: 'eCrime',
      sector: 'Identity / social engineering',
      url:    'https://attack.mitre.org/groups/G1015/'
    },
    {
      name:   'RansomHub',
      nation: 'Crimeware',
      sector: 'Ransomware-as-a-service',
      url:    'https://attack.mitre.org/groups/G1075/'
    },
    {
      name:   'APT28 / Fancy Bear',
      nation: 'Russia (GRU)',
      sector: 'Espionage',
      url:    'https://attack.mitre.org/groups/G0007/'
    },
    {
      name:   'Lazarus Group',
      nation: 'North Korea',
      sector: 'Financial / espionage',
      url:    'https://attack.mitre.org/groups/G0032/'
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

  /* ═══════════════════════════════════════════════════════════
     18. EPSS — Exploit Prediction Scoring System (FIRST.org)
         Top CVEs by exploitability probability
  ═══════════════════════════════════════════════════════════ */
  async function fetchEPSS(){
    const cached = getCached('cd_epss_v2');
    if (cached) return cached;
    try {
      const r = await fetch(
        'https://api.first.org/data/v1/epss?order=!epss&limit=20',
        {signal: AbortSignal.timeout ? AbortSignal.timeout(8000) : undefined}
      );
      if (!r.ok) throw new Error('EPSS ' + r.status);
      const json = await r.json();
      const data = (json.data || []).map(e => ({
        cve:        e.cve,
        epss:       parseFloat(e.epss),
        percentile: parseFloat(e.percentile),
        date:       e.date
      }));
      setCache('cd_epss_v2', data);
      return data;
    } catch { return []; }
  }

  // Enrich CVE grid items with EPSS scores
  function applyEPSSToGrid(epssData){
    if (!epssData.length) return;
    const map = {};
    epssData.forEach(e => { map[e.cve] = e; });
    document.querySelectorAll('[data-cve-id]').forEach(el => {
      const e = map[el.dataset.cveId];
      if (!e) return;
      const pct = Math.round(e.percentile * 100);
      const existing = el.querySelector('.epss-badge');
      if (existing) return;
      const badge = document.createElement('span');
      badge.className = 'epss-badge';
      badge.title = 'EPSS: ' + (e.epss * 100).toFixed(2) + '% probability of exploitation (' + pct + 'th percentile)';
      badge.textContent = 'EPSS ' + (e.epss * 100).toFixed(1) + '%';
      el.appendChild(badge);
    });
  }

  /* ═══════════════════════════════════════════════════════════
     19. GITHUB SECURITY ADVISORY DATABASE
  ═══════════════════════════════════════════════════════════ */
  async function fetchGHAdvisories(){
    const cached = getCached('cd_gh_adv_v2');
    if (cached) return cached;
    try {
      const r = await fetch(
        'https://api.github.com/advisories?per_page=20&type=reviewed',
        {
          headers: {
            'Accept':             'application/vnd.github+json',
            'X-GitHub-Api-Version': '2022-11-28'
          },
          signal: AbortSignal.timeout ? AbortSignal.timeout(8000) : undefined
        }
      );
      if (!r.ok) throw new Error('GH advisory ' + r.status);
      const json = await r.json();
      const data = json.map(a => {
        const vuln = a.vulnerabilities && a.vulnerabilities[0];
        return {
          id:          a.ghsa_id,
          cve:         a.cve_id || '',
          severity:    (a.severity || 'unknown').toLowerCase(),
          summary:     a.summary || '',
          url:         a.html_url,
          published:   a.published_at || '',
          ecosystem:   vuln ? (vuln.package || {}).ecosystem || '' : '',
          pkg:         vuln ? (vuln.package || {}).name || '' : '',
          cvss:        a.cvss ? a.cvss.score : null
        };
      });
      setCache('cd_gh_adv_v2', data);
      return data;
    } catch { return []; }
  }

  /* ═══════════════════════════════════════════════════════════
     20. CIRCL CVE API — additional CVE source
  ═══════════════════════════════════════════════════════════ */
  async function fetchCIRCL(){
    const cached = getCached('cd_circl_v2');
    if (cached) return cached;
    try {
      const r = await fetch(
        'https://cve.circl.lu/api/last/30',
        {signal: AbortSignal.timeout ? AbortSignal.timeout(8000) : undefined}
      );
      if (!r.ok) throw new Error('CIRCL ' + r.status);
      const json = await r.json();
      const data = (json || []).map(v => ({
        id:        v.id || v.cveMetadata?.cveId || '',
        desc:      (v.containers?.cna?.descriptions || []).find(d => d.lang === 'en')?.value
                   || (v.cve_description || v.summary || ''),
        cvss:      v.cvss || null,
        published: v.Published || v.cveMetadata?.datePublished || '',
        nvdUrl:    'https://nvd.nist.gov/vuln/detail/' + (v.id || v.cveMetadata?.cveId || ''),
        severity:  v.cvss >= 9 ? 'critical' : v.cvss >= 7 ? 'high' : v.cvss >= 4 ? 'medium' : 'low'
      })).filter(v => v.id);
      setCache('cd_circl_v2', data);
      return data;
    } catch { return []; }
  }

  /* ═══════════════════════════════════════════════════════════
     21. DIGEST.JSON — daily aggregated news feed from GitHub Action
  ═══════════════════════════════════════════════════════════ */
  async function fetchDigestFeed(){
    const cached = getCached('cd_digest_v2');
    if (cached) return cached;
    // Prefer full digest.json; fall back to the lightweight feed.json snapshot
    // (committed daily) so the page still has data before the first pipeline run.
    for (const path of ['/digest.json', '/feed.json']){
      try {
        const r = await fetch(path, {signal: AbortSignal.timeout ? AbortSignal.timeout(5000) : undefined});
        if (!r.ok) continue;
        const json = await r.json();
        setCache('cd_digest_v2', json);
        return json;
      } catch { /* try next */ }
    }
    return null;
  }

  /* ═══════════════════════════════════════════════════════════
     22. THREAT FEED SECTION — renders digest news + advisories
  ═══════════════════════════════════════════════════════════ */
  function renderThreatFeed(digest){
    const el = document.querySelector('[data-threat-feed]');
    if (!el) return;
    // Accept digest.json (threats/news arrays) or feed.json (items array).
    const source = (digest && (digest.threats || digest.news))
      ? [...(digest.threats || []), ...(digest.news || [])]
      : (digest && digest.items) ? digest.items : [];
    const items = source
      .slice()
      .sort((a, b) => (b.published || '').localeCompare(a.published || ''))
      .slice(0, 12);
    if (!items.length) {
      el.innerHTML = '<div style="padding:20px 14px;font-family:var(--font-mono);font-size:11px;color:var(--fg-dim)">Feed updates with the daily digest — run pending.</div>';
      return;
    }
    el.innerHTML = items.map(item => {
      const age    = item.published ? fmtRel((Date.now() - new Date(item.published).getTime()) / 1000) : '';
      const catCls = item.category === 'threat' ? 'tag-threat' : 'tag-news';
      const catLbl = item.category === 'threat' ? 'Advisory' : 'News';
      return '<a class="tf-item" href="' + item.url + '" target="_blank" rel="noopener">' +
        '<div class="tf-meta">' +
          '<span class="tf-cat ' + catCls + '">' + catLbl + '</span>' +
          '<span class="tf-source">' + (item.source || '') + '</span>' +
          (age ? '<time class="tf-age" data-rel="' + item.published + '">' + age + '</time>' : '') +
        '</div>' +
        '<div class="tf-title">' + (item.title || '').slice(0, 120) + '</div>' +
        '</a>';
    }).join('');
    // Update section heading if digest has generated timestamp
    if (digest.generated) {
      const ts = document.querySelector('[data-digest-ts]');
      if (ts) ts.textContent = 'Updated ' + fmtRel((Date.now() - new Date(digest.generated).getTime()) / 1000);
    }
  }

  function renderGHAdvisories(advisories){
    const el = document.querySelector('[data-gh-feed]');
    if (!el || !advisories.length) return;
    el.innerHTML = advisories.slice(0, 8).map(a => {
      const cls   = sevClass(a.severity);
      const lbl   = sevLabel(a.severity);
      const score = a.cvss ? ' · ' + a.cvss : '';
      const pkg   = a.pkg ? a.ecosystem + '/' + a.pkg : a.ecosystem;
      const tip   = ('<div class="tip-id">' + (a.cve || a.id) + ' <span style="color:var(--fg-dim)">' + lbl + '</span></div>' +
        (pkg ? '<div class="tip-vendor">' + pkg + (score ? '  ·  CVSS' + score : '') + '</div>' : '') +
        '<div class="tip-desc">' + (a.summary || 'No summary available.') + '</div>').replace(/"/g, '&quot;');
      return '<a class="gh-adv-item" href="' + a.url + '" target="_blank" rel="noopener" data-cve-tip="' + tip + '">' +
        '<span class="sev ' + cls + '">' + lbl + '</span>' +
        '<span class="gh-adv-id">' + (a.cve || a.id) + '</span>' +
        (pkg ? '<span class="gh-adv-pkg">' + pkg + score + '</span>' : '') +
        '<span class="gh-adv-summary">' + (a.summary || '').slice(0, 80) + '</span>' +
        '</a>';
    }).join('');
  }

  function renderEPSSPanel(epssData){
    const el = document.querySelector('[data-epss-feed]');
    if (!el || !epssData.length) return;
    el.innerHTML = epssData.slice(0, 8).map(e => {
      const pct  = (e.epss * 100).toFixed(1);
      const bar  = Math.round(e.epss * 100);
      const risk = e.epss >= 0.7 ? 'crit' : e.epss >= 0.4 ? 'high' : e.epss >= 0.1 ? 'mid' : 'low';
      const band = risk === 'crit' ? 'Critical exploit likelihood'
                 : risk === 'high' ? 'High exploit likelihood'
                 : risk === 'mid'  ? 'Elevated exploit likelihood' : 'Lower exploit likelihood';
      const pctl = (e.percentile != null) ? (e.percentile * 100).toFixed(0) : null;
      const tip  = ('<div class="tip-id">' + e.cve + '</div>' +
        '<div class="tip-desc">' + band + ' — ' + pct + '% EPSS exploit probability' +
        (pctl ? ' (ranks in the top ' + Math.max(1, 100 - pctl) + '% of all CVEs)' : '') + '.</div>' +
        '<div class="tip-foot">Click for full NVD detail ↗</div>').replace(/"/g, '&quot;');
      return '<a class="epss-item" href="https://nvd.nist.gov/vuln/detail/' + e.cve + '" target="_blank" rel="noopener" data-cve-tip="' + tip + '">' +
        '<span class="epss-cve">' + e.cve + '</span>' +
        '<span class="epss-bar-wrap"><span class="epss-bar-fill ' + risk + '" style="width:' + Math.min(bar, 100) + '%"></span></span>' +
        '<span class="epss-pct sev ' + risk + '">' + pct + '%</span>' +
        '</a>';
    }).join('');
  }

  /* ═══════════════════════════════════════════════════════════
     23. SECONDARY DATA LOAD — runs after main KEV/NVD load
  ═══════════════════════════════════════════════════════════ */
  async function loadSecondaryData(){
    // Run all secondary fetches concurrently
    const [epss, ghAdv, digest] = await Promise.allSettled([
      fetchEPSS(),
      fetchGHAdvisories(),
      fetchDigestFeed()
    ]);

    if (epss.status === 'fulfilled' && epss.value.length){
      renderEPSSPanel(epss.value);
      applyEPSSToGrid(epss.value);
      // Update console metric if element exists
      const el = document.getElementById('console-epss-count');
      if (el) {
        const highRisk = epss.value.filter(e => e.epss >= 0.1).length;
        el.textContent = highRisk;
        const sub = document.getElementById('console-epss-sub');
        if (sub) sub.textContent = 'EPSS ≥ 10% exploit prob';
      }
    }

    if (ghAdv.status === 'fulfilled' && ghAdv.value.length){
      renderGHAdvisories(ghAdv.value);
      const el = document.getElementById('console-gh-count');
      if (el) {
        el.textContent = ghAdv.value.length;
        const sub = document.getElementById('console-gh-sub');
        if (sub) sub.textContent = 'GitHub GHSA advisories';
      }
    }

    const dg = (digest.status === 'fulfilled') ? digest.value : null;
    renderThreatFeed(dg); // handles null/empty with a friendly message
    if (dg) {
      // Threat-posture urgency banner — level + colour + message from the daily digest.
      const urg = dg.urgency;
      const urgWrap = document.getElementById('hero-urgency');
      if (urgWrap && urg && urg.level) {
        const lvlEl = document.getElementById('hero-urgency-level');
        const msgEl = document.getElementById('hero-urgency-msg');
        if (lvlEl) { lvlEl.textContent = urg.level; lvlEl.style.color = urg.colour || ''; }
        if (msgEl) msgEl.innerHTML = urg.message || '';  // message is generated by our own digest.py (trusted)
        urgWrap.hidden = false;
      }
      // Robust fill for the "New CVEs (7d)" tile — never show a bare 0 or blank.
      // Prefer the live NVD count (set above); else the daily-digest count; else
      // fall back to the full same-origin KEV catalog (always reliable, non-zero).
      (async () => {
        const cveEl = document.getElementById('console-cve7d');
        if (!cveEl) return;
        const sub = document.getElementById('console-cve7d-sub');
        const cur = cveEl.textContent.replace(/[,\s]/g, '');
        if (/^\d+$/.test(cur) && cur !== '0') return; // live NVD already gave a real number
        const st = (dg && dg.stats) || {};
        if (st.total_cves) {
          cveEl.textContent = Number(st.total_cves).toLocaleString();
          if (sub) sub.textContent = 'recent \xb7 via daily digest';
          return;
        }
        try {
          const r = await fetch('/kev.json', {signal: AbortSignal.timeout ? AbortSignal.timeout(6000) : undefined});
          if (!r.ok) return;
          const j = await r.json();
          const n = (j.vulnerabilities || []).length;
          if (!n) return;
          cveEl.textContent = n.toLocaleString();
          const k = cveEl.closest('.metric') && cveEl.closest('.metric').querySelector('.k');
          if (k) k.textContent = 'Tracked CVEs';
          if (sub) sub.textContent = 'exploited \xb7 CISA KEV';
        } catch {}
      })();
    }
  }

  // Kick off secondary data load after a short delay (let primary KEV/NVD finish first)
  setTimeout(loadSecondaryData, 1500);

  // Inject CSS for new panels
  (function injectPanelStyles(){
    const s = document.createElement('style');
    s.textContent = `
      /* ── EPSS badge on CVE cards ── */
      .epss-badge {
        display:inline-block;margin-left:8px;
        font-family:var(--font-mono);font-size:9px;letter-spacing:.08em;
        padding:2px 6px;border:1px solid rgba(214,168,106,.5);
        color:var(--status-mid);background:rgba(214,168,106,.07);
        vertical-align:middle;
      }
      /* ── EPSS panel ── */
      .epss-item {
        display:grid;grid-template-columns:1fr 60px 52px;align-items:center;gap:10px;
        padding:8px 14px;border-bottom:1px solid var(--hairline);
        font-family:var(--font-mono);font-size:11px;color:var(--fg-muted);
        text-decoration:none;transition:background .12s;
      }
      .epss-item:last-child{ border-bottom:0 }
      .epss-item:hover{ background:var(--bg-elev-2) }
      .epss-cve{ color:var(--fg);font-size:11.5px }
      .epss-bar-wrap{ height:4px;background:var(--bg-elev-3);border-radius:2px;overflow:hidden }
      .epss-bar-fill{ height:100%;border-radius:2px;transition:width .4s var(--ease) }
      .epss-bar-fill.crit{ background:var(--status-crit) }
      .epss-bar-fill.high{ background:var(--status-high) }
      .epss-bar-fill.mid { background:var(--status-mid) }
      .epss-bar-fill.low { background:var(--status-ok) }
      .epss-pct{ font-size:10px;text-align:right }
      /* ── GitHub Advisory feed ── */
      .gh-adv-item {
        display:grid;grid-template-columns:50px 1fr 1fr;align-items:center;gap:10px;
        padding:8px 14px;border-bottom:1px solid var(--hairline);
        font-family:var(--font-mono);font-size:11px;color:var(--fg-muted);
        text-decoration:none;transition:background .12s;
      }
      .gh-adv-item:last-child{ border-bottom:0 }
      .gh-adv-item:hover{ background:var(--bg-elev-2) }
      .gh-adv-id{ color:var(--fg);font-size:11px }
      .gh-adv-pkg{ color:var(--accent);font-size:10.5px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap }
      .gh-adv-summary{ color:var(--fg-muted);font-size:11px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;display:none }
      /* ── Threat feed ── */
      .tf-item {
        display:flex;flex-direction:column;gap:5px;
        padding:12px 14px;border-bottom:1px solid var(--hairline);
        text-decoration:none;color:inherit;transition:background .12s;
      }
      .tf-item:last-child{ border-bottom:0 }
      .tf-item:hover{ background:var(--bg-elev-1) }
      .tf-meta{ display:flex;align-items:center;gap:8px;font-family:var(--font-mono);font-size:10px }
      .tf-cat{ padding:1px 6px;letter-spacing:.1em;text-transform:uppercase }
      .tf-cat.tag-threat{ color:var(--status-crit);border:1px solid rgba(216,92,92,.3) }
      .tf-cat.tag-news{ color:var(--accent);border:1px solid rgba(108,142,255,.3) }
      .tf-source{ color:var(--fg-dim) }
      .tf-age{ color:var(--fg-faint);margin-left:auto }
      .tf-title{ font-size:13.5px;color:var(--fg);line-height:1.4;letter-spacing:-.005em }
      .tf-item:hover .tf-title{ color:#fff }
      /* ── Multi-source section wrapper ── */
      .intel-panels {
        display:grid;grid-template-columns:1fr 1fr 1fr;gap:1px;
        background:var(--hairline);border:1px solid var(--hairline);
        margin-top:40px;
      }
      .intel-panel {
        background:var(--bg);overflow:hidden;
      }
      .intel-panel-head {
        display:flex;align-items:center;justify-content:space-between;
        padding:12px 14px 10px;border-bottom:1px solid var(--hairline);
        font-family:var(--font-mono);font-size:10px;letter-spacing:.12em;
        text-transform:uppercase;color:var(--fg-dim);
      }
      .intel-panel-head a {
        color:var(--accent);font-size:9.5px;letter-spacing:.1em;
        border-bottom:1px solid rgba(108,142,255,.3);
      }
      .intel-panel-head a:hover{ border-bottom-color:var(--accent) }
      @media (max-width:1100px){ .intel-panels{ grid-template-columns:1fr } }
    `;
    document.head.appendChild(s);
  })();

  /* ═══════════════════════════════════════════════════════════
     24. CVES PAGE — dynamic CVE index (cves.html)
     Renders the table from digest.json, rebuilds vendor chips from
     live data, populates stats, refreshes hourly. Static rows in the
     HTML act as a no-JS / fetch-failure fallback.
  /* ═══════════════════════════════════════════════════════════
     CVEs PAGE — full KEV catalog + NVD digest merge, live filter/sort
  ═══════════════════════════════════════════════════════════ */
  function initCvesPage(){
    const tbody = document.querySelector('[data-cve-tbody]');
    if (!tbody) return;

    const esc  = s => (s == null ? '' : String(s)).replace(/[&<>"]/g,
      c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
    const slug = v => (v || '').toLowerCase().replace(/[^a-z0-9]+/g, '').slice(0, 24);
    const TO = ms => (typeof AbortSignal !== 'undefined' && AbortSignal.timeout) ? AbortSignal.timeout(ms) : undefined;

    const band = c => (c >= 9 ? 'crit' : c >= 7 ? 'high' : c >= 4 ? 'mid' : 'low');
    // Effective severity: CVSS when known, else blended from exploited/ransomware/EPSS so
    // every row (incl. KEV entries with no CVSS) is filterable & sortable.
    const sevOf = r => r.cvss != null ? band(r.cvss)
      : r.ransomware ? 'crit'
      : (r.epss != null && r.epss >= 0.5) ? 'crit'
      : (r.kev || (r.epss != null && r.epss >= 0.1)) ? 'high'
      : (r.epss != null && r.epss >= 0.01) ? 'mid' : 'low';
    const sevRank = {crit:4, high:3, mid:2, low:1};

    const state = { sev:'all', status:'all', time:'all', sort:'date-desc', vendors:new Set(), q:'' };
    let ALL = [], vendorFilter = '', vendorExpanded = false;

    const parseKEV = json => (json.vulnerabilities || []).map(v => ({
      id:        v.cveID,
      vendor:    v.vendorProject || '',
      product:   v.product || '',
      title:     v.vulnerabilityName || v.shortDescription || '',
      dateAdded: (v.dateAdded || '').slice(0, 10),
      ransomware:(v.knownRansomwareCampaignUse || '').toLowerCase() === 'known',
      kev:true, cvss:null, epss:null,
      url:'https://nvd.nist.gov/vuln/detail/' + v.cveID
    })).filter(r => r.id && r.id.indexOf('CVE-') === 0);

    // Same-origin snapshot only — CISA's feed has no CORS header, so a direct
    // browser fetch always fails; the pipeline mirrors the full catalog to /kev.json.
    async function loadKEV(){
      try {
        const r = await fetch('/kev.json', {signal: TO(8000)});
        if (r.ok) return parseKEV(await r.json());
      } catch {}
      return [];
    }

    function fromDigest(digest){
      if (!digest || !Array.isArray(digest.cves)) return [];
      return digest.cves.filter(c => c.id && c.id.indexOf('CVE-') === 0).map(c => ({
        id:c.id, vendor:c.vendor || '', product:c.product || '',
        title:(c.desc || '').slice(0, 200),
        dateAdded:(c.published || '').slice(0, 10),
        ransomware:false, kev:!!(c.kev || c.exploited),
        cvss:(c.cvss != null && c.cvss > 0) ? c.cvss : null,
        epss:(c.epss && c.epss.epss != null) ? c.epss.epss : null,
        url:c.nvdUrl || ('https://nvd.nist.gov/vuln/detail/' + c.id)
      }));
    }

    function merge(kevRows, nvdRows){
      const map = new Map();
      kevRows.forEach(r => map.set(r.id.toUpperCase(), r));
      nvdRows.forEach(n => {
        const ex = map.get(n.id.toUpperCase());
        if (ex){ if (ex.cvss == null) ex.cvss = n.cvss; if (ex.epss == null) ex.epss = n.epss;
                 if (!ex.vendor) ex.vendor = n.vendor; if (!ex.title) ex.title = n.title; }
        else map.set(n.id.toUpperCase(), n);
      });
      return [...map.values()];
    }

    async function enrichEPSS(rows){
      const ids = rows.filter(r => r.epss == null).map(r => r.id);
      const CHUNK = 80, MAX = 1200;
      for (let i = 0; i < ids.length && i < MAX; i += CHUNK){
        const batch = ids.slice(i, i + CHUNK);
        try {
          const r = await fetch('https://api.first.org/data/v1/epss?cve=' + batch.join(',') + '&limit=' + CHUNK, {signal: TO(8000)});
          if (!r.ok) continue;
          const j = await r.json();
          const m = {}; (j.data || []).forEach(e => { m[e.cve] = parseFloat(e.epss); });
          rows.forEach(row => { if (row.epss == null && m[row.id] != null) row.epss = m[row.id]; });
        } catch {}
      }
    }

    function filtered(){
      const now = Date.now();
      const days = {'7d':7,'30d':30,'90d':90,'1y':365}[state.time];
      const q = state.q.toLowerCase();
      let rows = ALL.filter(r => {
        if (state.sev !== 'all' && sevOf(r) !== state.sev) return false;
        if (state.status === 'kev'    && !r.kev) return false;
        if (state.status === 'ransom' && !r.ransomware) return false;
        if (state.vendors.size && !state.vendors.has(slug(r.vendor))) return false;
        if (days){ if (!r.dateAdded) return false; if ((now - new Date(r.dateAdded).getTime()) / 864e5 > days) return false; }
        if (q && (r.id + ' ' + r.vendor + ' ' + r.product + ' ' + r.title).toLowerCase().indexOf(q) === -1) return false;
        return true;
      });
      const eff = r => r.cvss != null ? r.cvss : ({crit:9.5,high:7.5,mid:5,low:2}[sevOf(r)]);
      const cmp = {
        'date-desc': (a,b) => (b.dateAdded || '').localeCompare(a.dateAdded || ''),
        'date-asc':  (a,b) => (a.dateAdded || '').localeCompare(b.dateAdded || ''),
        'sev-desc':  (a,b) => (sevRank[sevOf(b)] - sevRank[sevOf(a)]) || (eff(b) - eff(a)),
        'epss-desc': (a,b) => (b.epss == null ? -1 : b.epss) - (a.epss == null ? -1 : a.epss),
        'vendor-asc':(a,b) => (a.vendor || '').localeCompare(b.vendor || '')
      }[state.sort];
      return cmp ? rows.sort(cmp) : rows;
    }

    function renderRows(rows){
      if (!rows.length){
        tbody.innerHTML = '<tr><td colspan="7" style="padding:48px 16px;text-align:center;color:var(--fg-dim);font-family:var(--font-mono);font-size:13px">No CVEs match these filters.</td></tr>';
        return;
      }
      tbody.innerHTML = rows.slice(0, 600).map(r => {
        const sc    = sevOf(r);
        const label = r.cvss != null ? r.cvss.toFixed(1)
          : (sc === 'crit' ? 'CRIT' : sc === 'high' ? 'HIGH' : sc === 'mid' ? 'MED' : 'LOW');
        const score = '<span class="pill ' + sc + '">' + label + '</span>';
        const epss  = r.epss != null ? ' <span class="epss-tag">EPSS ' + (r.epss * 100).toFixed(0) + '%</span>' : '';
        const status = r.ransomware ? '<span class="badge badge-ransom">Ransomware</span>'
          : (r.kev ? '<span class="badge">Exploited</span>' : '<span class="badge badge-muted">Not known</span>');
        const vp = r.vendor ? (r.product ? esc(r.vendor) + ' · ' + esc(r.product) : esc(r.vendor)) : '—';
        const t  = (r.title || '');
        return '<tr onclick="window.open(\'' + r.url + '\',\'_blank\',\'noopener\')">' +
          '<td class="id"><a href="' + r.url + '" target="_blank" rel="noopener">' + esc(r.id) + '</a></td>' +
          '<td class="vendor">' + vp + '</td>' +
          '<td class="title">' + esc(t.slice(0, 150)) + (t.length > 150 ? '…' : '') + epss + '</td>' +
          '<td class="score">' + score + '</td>' +
          '<td class="kev">' + status + '</td>' +
          '<td class="added">' + esc(r.dateAdded || '—') + '</td>' +
          '<td class="refs"><a href="' + r.url + '" target="_blank" rel="noopener">NVD</a></td>' +
        '</tr>';
      }).join('');
    }

    function buildVendorChips(){
      const wrap = document.querySelector('[data-vendor-chips]');
      if (!wrap) return;
      const count = {};
      ALL.forEach(r => { const v = r.vendor; if (!v) return; const s = slug(v); if (!s) return; (count[s] = count[s] || {n:0, label:v}).n++; });
      let entries = Object.entries(count).sort((a,b) => b[1].n - a[1].n);
      const f = vendorFilter.toLowerCase();
      if (f) entries = entries.filter(([s,o]) => o.label.toLowerCase().indexOf(f) !== -1);
      const sel = entries.filter(([s]) => state.vendors.has(s));
      const others = entries.filter(([s]) => !state.vendors.has(s));
      const LIMIT = 12;
      const shown = (vendorExpanded || f) ? others : others.slice(0, LIMIT);
      const chip = ([s,o]) => '<button class="chip" data-vendor="' + s + '" aria-pressed="' + (state.vendors.has(s) ? 'true' : 'false') + '">' +
        esc(o.label) + ' <span class="chip-n">' + o.n + '</span></button>';
      let html = sel.map(chip).join('') + shown.map(chip).join('');
      const hidden = others.length - shown.length;
      if (hidden > 0) html += '<button class="chip chip-more" data-vendor-more>+' + hidden + ' more</button>';
      else if (vendorExpanded && others.length > LIMIT) html += '<button class="chip chip-more" data-vendor-more>show less</button>';
      wrap.innerHTML = html || '<span style="color:var(--fg-dim);font-size:12px;font-family:var(--font-mono)">No vendors match.</span>';
    }

    function stats(){
      const now = Date.now();
      const within = n => ALL.filter(r => r.dateAdded && (now - new Date(r.dateAdded).getTime()) / 864e5 <= n).length;
      const set = (sel, val) => { const el = document.querySelector(sel); if (el) el.textContent = val; };
      set('[data-stat-total]',   ALL.length.toLocaleString());
      set('[data-stat-kev]',     ALL.filter(r => r.kev).length.toLocaleString());
      set('[data-stat-7d]',      within(7));
      set('[data-stat-ransom]',  ALL.filter(r => r.ransomware).length.toLocaleString());
      set('[data-stat-epss]',    ALL.filter(r => r.epss != null && r.epss >= 0.1).length.toLocaleString());
      set('[data-stat-vendors]', new Set(ALL.map(r => slug(r.vendor)).filter(Boolean)).size.toLocaleString());
    }

    function update(){
      const rows = filtered();
      renderRows(rows);
      const c = document.querySelector('[data-result-count]');
      if (c) c.textContent = rows.length.toLocaleString() + ' CVE' + (rows.length !== 1 ? 's' : '');
    }

    function wire(){
      const tb = document.querySelector('[data-cve-toolbar]');
      if (tb){
        tb.addEventListener('click', e => {
          const press = (g, el) => tb.querySelectorAll('[' + g + ']').forEach(x => x.setAttribute('aria-pressed', x === el));
          const sev = e.target.closest('[data-sev]');
          if (sev){ state.sev = sev.dataset.sev; press('data-sev', sev); return update(); }
          const st = e.target.closest('[data-status]');
          if (st){ state.status = st.dataset.status; press('data-status', st); return update(); }
          const tm = e.target.closest('[data-time]');
          if (tm){ state.time = tm.dataset.time; press('data-time', tm); return update(); }
          const more = e.target.closest('[data-vendor-more]');
          if (more){ vendorExpanded = !vendorExpanded; return buildVendorChips(); }
          const ven = e.target.closest('[data-vendor]');
          if (ven){
            const s = ven.dataset.vendor;
            if (state.vendors.has(s)) state.vendors.delete(s); else state.vendors.add(s);
            buildVendorChips(); return update();
          }
        });
      }
      const sortSel = document.querySelector('[data-sort]');
      if (sortSel) sortSel.addEventListener('change', () => { state.sort = sortSel.value; update(); });
      const search = document.querySelector('[data-cve-search]');
      if (search) search.addEventListener('input', () => { state.q = search.value.trim(); update(); });
      const vs = document.querySelector('[data-vendor-search]');
      if (vs) vs.addEventListener('input', () => { vendorFilter = vs.value.trim(); buildVendorChips(); });
    }

    function renderIOCPanel(digest){
      const el = document.querySelector('[data-ioc-panel]');
      if (!el) return;
      const iocs = (digest && digest.threatfox) || [];
      if (!iocs.length){
        el.innerHTML = '<p style="color:var(--fg-dim);font-size:13px;font-family:var(--font-mono)">IOC feed updates with the daily digest — run pending.</p>';
        return;
      }
      const rows = iocs.slice(0, 40).map(i => {
        const ioc  = esc((i.ioc || '').slice(0, 60));
        const conf = (i.confidence != null) ? i.confidence + '%' : '—';
        return '<tr><td class="id" style="max-width:280px;overflow:hidden;text-overflow:ellipsis">' + ioc + '</td>' +
          '<td class="vendor">' + esc(i.ioc_type || '') + '</td>' +
          '<td class="vendor">' + esc(i.malware || i.threat_type || '') + '</td>' +
          '<td class="added">' + esc((i.first_seen || '').slice(0, 10)) + '</td>' +
          '<td class="score"><span class="pill mid">' + conf + '</span></td></tr>';
      }).join('');
      el.innerHTML = '<div class="cve-table-wrap" style="margin:0"><table class="cve-table"><thead><tr>' +
        '<th>Indicator</th><th class="vendor-h">Type</th><th class="vendor-h">Malware / Threat</th>' +
        '<th class="added-h">First seen</th><th>Confidence</th></tr></thead><tbody>' + rows + '</tbody></table></div>';
    }

    async function load(){
      try { sessionStorage.removeItem('cd_digest_v2'); } catch {}
      const [kev, digest] = await Promise.all([ loadKEV(), fetchDigestFeed().catch(() => null) ]);
      const merged = merge(kev, fromDigest(digest));
      renderIOCPanel(digest);
      if (!merged.length) return;
      ALL = merged;
      buildVendorChips();
      stats();
      update();
      enrichEPSS(ALL).then(() => { stats(); update(); });
    }

    wire();
    load();
    setInterval(load, 60 * 60 * 1000);
  }
  initCvesPage();

})();

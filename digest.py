#!/usr/bin/env python3
"""
Cyber Digest — daily intelligence pipeline
Fetches: CISA KEV, NVD CVEs, EPSS scores, GitHub Advisories, ThreatFox IOCs,
         OSV vulns, RSS threat feeds, security news
Outputs: digest.json + site/feed.json (both committed to repo)

Required env vars (set as GitHub Actions secrets):
  NVD_API_KEY        — optional but recommended (higher rate limits)

Optional env vars:
  GMAIL_USER         — sender address
  GMAIL_APP_PASSWORD — Google App Password
  EMAIL_TO           — recipient(s), comma-separated
  DISCORD_WEBHOOK    — Discord notification URL
"""

import os, json, re, time, urllib.request, urllib.parse, feedparser
from datetime import datetime, timedelta, timezone

# ── CONFIG ────────────────────────────────────────────────────────────────────
NVD_API_KEY     = os.environ.get("NVD_API_KEY", "")
GMAIL_USER      = os.environ.get("GMAIL_USER", "")
GMAIL_PASS      = os.environ.get("GMAIL_APP_PASSWORD", "")
EMAIL_TO        = os.environ.get("EMAIL_TO", "")
DISCORD_WEBHOOK = os.environ.get("DISCORD_WEBHOOK", "")

CVE_LOOKBACK_HOURS = 48
MAX_CVES           = 50
MAX_KEV            = 50
MAX_PER_FEED       = 8

# ── RSS FEEDS ─────────────────────────────────────────────────────────────────
THREAT_FEEDS = [
    ("CISA Advisories",       "https://www.cisa.gov/feeds/hns.xml"),
    ("CISA ICS",              "https://www.cisa.gov/uscert/ics/advisories/advisories.xml"),
    ("Microsoft Security",    "https://api.msrc.microsoft.com/update-guide/rss"),
    ("Cisco PSIRT",           "https://tools.cisco.com/security/center/psirt_rss.xml"),
    ("Talos Intelligence",    "https://blog.talosintelligence.com/rss/"),
    ("Unit 42",               "https://unit42.paloaltonetworks.com/feed/"),
    ("Red Hat Security",      "https://access.redhat.com/security/security-updates/vulnerabilities.atom"),
    ("Fortinet PSIRT",        "https://www.fortiguard.com/rss/ir.xml"),
    ("Google Project Zero",   "https://googleprojectzero.blogspot.com/feeds/posts/default"),
    ("Google TAG",            "https://blog.google/threat-analysis-group/rss/"),
    ("Mandiant Blog",         "https://www.mandiant.com/resources/blog/rss.xml"),
    ("Rapid7 Blog",           "https://www.rapid7.com/blog/feed/"),
    ("Tenable Blog",          "https://www.tenable.com/blog/feed"),
    ("Qualys Blog",           "https://blog.qualys.com/feed"),
    ("Secureworks CTU",       "https://www.secureworks.com/rss?feed=research"),
    ("WithSecure Labs",       "https://labs.withsecure.com/publications/feed"),
    ("Checkpoint Research",   "https://research.checkpoint.com/feed/"),
    ("SentinelOne Blog",      "https://www.sentinelone.com/blog/feed/"),
    ("CrowdStrike Blog",      "https://www.crowdstrike.com/blog/feed/"),
    ("Elastic Security",      "https://www.elastic.co/security-labs/rss/feed.xml"),
]

NEWS_FEEDS = [
    ("Bleeping Computer",    "https://www.bleepingcomputer.com/feed/"),
    ("The Hacker News",      "https://feeds.feedburner.com/TheHackersNews"),
    ("The Record",           "https://therecord.media/feed"),
    ("SecurityWeek",         "https://feeds.feedburner.com/Securityweek"),
    ("Dark Reading",         "https://www.darkreading.com/rss.xml"),
    ("Krebs on Security",    "https://krebsonsecurity.com/feed/"),
    ("SANS ISC Diary",       "https://isc.sans.edu/rssfeed.xml"),
    ("Ars Technica Security","https://feeds.arstechnica.com/arstechnica/security"),
    ("Wired Security",       "https://www.wired.com/feed/category/security/latest/rss"),
    ("SC Magazine",          "https://www.scmagazine.com/feed"),
    ("Infosecurity Magazine","https://www.infosecurity-magazine.com/rss/news/"),
    ("Naked Security",       "https://nakedsecurity.sophos.com/feed/"),
    ("Risky Business",       "https://risky.biz/feeds/risky-business/"),
    ("CERT-EU",              "https://cert.europa.eu/publications/threat-intelligence/rss.xml"),
    ("NCSC UK",              "https://www.ncsc.gov.uk/api/1/services/v1/all-rss-feed.xml"),
]

# ── SEVERITY ──────────────────────────────────────────────────────────────────
def cvss_severity(score: float) -> str:
    if score >= 9.0: return "CRITICAL"
    if score >= 7.0: return "HIGH"
    if score >= 4.0: return "MEDIUM"
    if score >  0.0: return "LOW"
    return "NONE"

VENDOR_DOMAINS = {
    "microsoft.com": "Microsoft", "msrc.microsoft.com": "Microsoft",
    "cisco.com": "Cisco", "talosintelligence.com": "Cisco",
    "redhat.com": "Red Hat", "oracle.com": "Oracle",
    "adobe.com": "Adobe", "apple.com": "Apple", "google.com": "Google",
    "mozilla.org": "Mozilla", "paloaltonetworks.com": "Palo Alto Networks",
    "fortinet.com": "Fortinet", "vmware.com": "VMware", "broadcom.com": "Broadcom",
    "ivanti.com": "Ivanti", "juniper.net": "Juniper", "checkpoint.com": "Check Point",
    "f5.com": "F5", "citrix.com": "Citrix", "atlassian.com": "Atlassian",
    "apache.org": "Apache", "wordpress.org": "WordPress", "gitlab.com": "GitLab",
    "sap.com": "SAP", "nginx.org": "NGINX", "elastic.co": "Elastic",
    "splunk.com": "Splunk", "solarwinds.com": "SolarWinds",
    "rapid7.com": "Rapid7", "tenable.com": "Tenable", "qualys.com": "Qualys",
    "sonicwall.com": "SonicWall", "watchguard.com": "WatchGuard",
    "netscout.com": "NetScout", "progress.com": "Progress Software",
    "moveit.com": "MOVEit", "ivanti.com": "Ivanti",
}

def vendor_from_refs(refs: list) -> str:
    for ref in refs:
        url = ref.get("url", "").lower()
        for domain, vendor in VENDOR_DOMAINS.items():
            if domain in url:
                return vendor
    return ""

def cpe_fields(cve: dict) -> dict:
    vendors, products = set(), set()
    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for m in node.get("cpeMatch", []):
                parts = m.get("criteria", "").split(":")
                if len(parts) >= 5:
                    if parts[3] not in ("*", "-"):
                        vendors.add(parts[3].replace("_", " ").title())
                    if parts[4] not in ("*", "-"):
                        products.add(parts[4].replace("_", " ").title())
    return {
        "vendor":  ", ".join(sorted(vendors)[:2]),
        "product": ", ".join(sorted(products)[:3]),
    }

# ── FETCH NVD CVEs ────────────────────────────────────────────────────────────
def fetch_nvd_cves() -> list:
    now   = datetime.now(timezone.utc)
    start = now - timedelta(hours=CVE_LOOKBACK_HOURS)
    fmt   = "%Y-%m-%dT%H:%M:%S.000"
    params = {
        "pubStartDate":   start.strftime(fmt),
        "pubEndDate":     now.strftime(fmt),
        "resultsPerPage": MAX_CVES,
    }
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(url, headers={"User-Agent": "CyberDigest/2.0"})
    if NVD_API_KEY:
        req.add_header("apiKey", NVD_API_KEY)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = json.loads(resp.read())
    except Exception as e:
        print(f"[NVD] fetch error: {e}")
        return []

    cves = []
    for item in raw.get("vulnerabilities", []):
        cve  = item.get("cve", {})
        cid  = cve.get("id", "N/A")
        refs = cve.get("references", [])
        desc = next(
            (d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"),
            "No description available."
        )
        metrics = cve.get("metrics", {})
        score, vector = 0.0, ""
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key, [])
            if entries:
                score  = entries[0].get("cvssData", {}).get("baseScore", 0.0)
                vector = entries[0].get("cvssData", {}).get("vectorString", "")
                break

        fields = cpe_fields(cve)
        if not fields["vendor"]:
            fields["vendor"] = vendor_from_refs(refs)

        cves.append({
            "id":          cid,
            "desc":        desc,
            "cvss":        round(score, 1),
            "vector":      vector,
            "severity":    cvss_severity(score),
            "vendor":      fields["vendor"],
            "product":     fields["product"],
            "exploited":   any("exploit-db.com" in r.get("url","").lower() for r in refs),
            "kev":         False,
            "epss":        None,   # enriched below
            "published":   cve.get("published",""),
            "nvdUrl":      "https://nvd.nist.gov/vuln/detail/" + cid,
        })
    print(f"[NVD] {len(cves)} CVEs fetched")
    return cves

# ── FETCH CISA KEV ────────────────────────────────────────────────────────────
def fetch_kev() -> list:
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "CyberDigest/2.0"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read())
        vulns = data.get("vulnerabilities", [])
        vulns.sort(key=lambda x: x.get("dateAdded",""), reverse=True)
        print(f"[KEV] {len(vulns)} total entries; returning top {MAX_KEV}")
        return vulns[:MAX_KEV]
    except Exception as e:
        print(f"[KEV] fetch error: {e}")
        return []

# ── FETCH EPSS SCORES ─────────────────────────────────────────────────────────
def fetch_epss(cve_ids: list) -> dict:
    """Fetch EPSS scores from FIRST.org for a list of CVE IDs."""
    if not cve_ids:
        return {}
    # EPSS API accepts up to 30 CVEs per request
    chunks = [cve_ids[i:i+30] for i in range(0, min(len(cve_ids), 90), 30)]
    result = {}
    for chunk in chunks:
        try:
            params = "&".join("cve=" + c for c in chunk)
            url    = "https://api.first.org/data/v1/epss?" + params
            req    = urllib.request.Request(url, headers={"User-Agent": "CyberDigest/2.0"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read())
            for e in data.get("data", []):
                result[e["cve"]] = {
                    "epss":       float(e.get("epss", 0)),
                    "percentile": float(e.get("percentile", 0)),
                }
            time.sleep(0.3)
        except Exception as ex:
            print(f"[EPSS] chunk error: {ex}")
    print(f"[EPSS] {len(result)} scores fetched")
    return result

# ── FETCH GITHUB ADVISORY DATABASE ───────────────────────────────────────────
def fetch_gh_advisories() -> list:
    url = "https://api.github.com/advisories?per_page=30&type=reviewed"
    req = urllib.request.Request(url, headers={
        "Accept":               "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent":           "CyberDigest/2.0",
    })
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
        advisories = []
        for a in data:
            vuln = a.get("vulnerabilities", [{}])[0] if a.get("vulnerabilities") else {}
            advisories.append({
                "id":          a.get("ghsa_id", ""),
                "cve":         a.get("cve_id", ""),
                "severity":    a.get("severity", "unknown"),
                "summary":     a.get("summary", ""),
                "url":         a.get("html_url", ""),
                "published":   a.get("published_at", ""),
                "ecosystem":   (vuln.get("package") or {}).get("ecosystem", ""),
                "pkg":         (vuln.get("package") or {}).get("name", ""),
                "cvss_score":  (a.get("cvss") or {}).get("score"),
            })
        print(f"[GH] {len(advisories)} advisories fetched")
        return advisories
    except Exception as e:
        print(f"[GH] fetch error: {e}")
        return []

# ── FETCH THREATFOX IOCs ──────────────────────────────────────────────────────
def fetch_threatfox_iocs() -> list:
    """Fetch recent IOCs from abuse.ch ThreatFox."""
    url     = "https://threatfox-api.abuse.ch/api/v1/"
    payload = json.dumps({"query": "get_iocs", "days": 1}).encode()
    req     = urllib.request.Request(url, data=payload, headers={
        "Content-Type": "application/json",
        "User-Agent":   "CyberDigest/2.0",
    })
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
        iocs = []
        for item in (data.get("data") or [])[:30]:
            iocs.append({
                "id":          item.get("id", ""),
                "ioc":         item.get("ioc", ""),
                "ioc_type":    item.get("ioc_type", ""),
                "threat_type": item.get("threat_type", ""),
                "malware":     item.get("malware", ""),
                "confidence":  item.get("confidence_level", 0),
                "first_seen":  item.get("first_seen", ""),
                "tags":        item.get("tags") or [],
            })
        print(f"[ThreatFox] {len(iocs)} IOCs fetched")
        return iocs
    except Exception as e:
        print(f"[ThreatFox] fetch error: {e}")
        return []

# ── FETCH MALWAREBAZAAR RECENT SAMPLES ───────────────────────────────────────
def fetch_malwarebazaar() -> list:
    """Fetch recent malware samples from MalwareBazaar."""
    url     = "https://mb-api.abuse.ch/api/v1/"
    payload = urllib.parse.urlencode({"query": "get_recent", "selector": "time"}).encode()
    req     = urllib.request.Request(url, data=payload, headers={
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent":   "CyberDigest/2.0",
    })
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
        samples = []
        for item in (data.get("data") or [])[:20]:
            samples.append({
                "sha256":     item.get("sha256_hash", ""),
                "file_name":  item.get("file_name", ""),
                "file_type":  item.get("file_type", ""),
                "signature":  item.get("signature", ""),
                "first_seen": item.get("first_seen", ""),
                "tags":       item.get("tags") or [],
                "url":        "https://bazaar.abuse.ch/sample/" + item.get("sha256_hash", ""),
            })
        print(f"[MalwareBazaar] {len(samples)} samples fetched")
        return samples
    except Exception as e:
        print(f"[MalwareBazaar] fetch error: {e}")
        return []

# ── FETCH FEODO TRACKER C2 ────────────────────────────────────────────────────
def fetch_feodo_c2() -> list:
    """Fetch active botnet C2 servers from Feodo Tracker."""
    url = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
    req = urllib.request.Request(url, headers={"User-Agent": "CyberDigest/2.0"})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
        # Return top 20 most recently active
        entries = sorted(data, key=lambda x: x.get("last_online", ""), reverse=True)[:20]
        result  = [{
            "ip":         e.get("ip_address", ""),
            "port":       e.get("port", ""),
            "malware":    e.get("malware", ""),
            "first_seen": e.get("first_seen", ""),
            "last_seen":  e.get("last_online", ""),
            "country":    e.get("country", ""),
            "asn":        e.get("as_number", ""),
        } for e in entries]
        print(f"[Feodo] {len(result)} C2 entries fetched")
        return result
    except Exception as e:
        print(f"[Feodo] fetch error: {e}")
        return []

# ── FETCH OSV.DEV RECENT VULNS ───────────────────────────────────────────────
def fetch_osv_recent() -> list:
    """Fetch recent vulnerabilities from OSV.dev."""
    # Query modified in last 24h for critical/high
    url     = "https://api.osv.dev/v1/querybatch"
    payload = json.dumps({"queries": [{"package": {"ecosystem": "PyPI"}},
                                       {"package": {"ecosystem": "npm"}},
                                       {"package": {"ecosystem": "Go"}}]}).encode()
    # Use the list endpoint instead for simplicity
    list_url = "https://api.osv.dev/v1/vulns?page_size=20"
    req = urllib.request.Request(list_url, headers={"User-Agent": "CyberDigest/2.0"})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
        items = []
        for v in (data.get("vulns") or [])[:20]:
            items.append({
                "id":        v.get("id", ""),
                "summary":   v.get("summary", ""),
                "published": v.get("published", ""),
                "modified":  v.get("modified", ""),
                "cves":      [a["name"] for a in v.get("aliases", []) if a.get("name","").startswith("CVE-")],
                "url":       "https://osv.dev/vulnerability/" + v.get("id", ""),
            })
        print(f"[OSV] {len(items)} vulns fetched")
        return items
    except Exception as e:
        print(f"[OSV] fetch error: {e}")
        return []

# ── FETCH RSS FEEDS ───────────────────────────────────────────────────────────
def fetch_feeds(feed_list: list, category: str) -> list:
    items = []
    for name, url in feed_list:
        try:
            feed  = feedparser.parse(url)
            count = 0
            for entry in feed.entries:
                if count >= MAX_PER_FEED:
                    break
                published = ""
                if hasattr(entry, "published_parsed") and entry.published_parsed:
                    published = datetime(*entry.published_parsed[:6], tzinfo=timezone.utc).isoformat()
                elif hasattr(entry, "updated_parsed") and entry.updated_parsed:
                    published = datetime(*entry.updated_parsed[:6], tzinfo=timezone.utc).isoformat()
                items.append({
                    "title":     getattr(entry, "title", ""),
                    "url":       getattr(entry, "link",  ""),
                    "source":    name,
                    "category":  category,
                    "published": published,
                    "summary":   re.sub(r'<[^>]+>', '', getattr(entry, "summary", ""))[:300],
                })
                count += 1
            print(f"[RSS] {name}: {count} items")
        except Exception as e:
            print(f"[RSS] {name} error: {e}")
        time.sleep(0.4)
    items.sort(key=lambda x: x.get("published", ""), reverse=True)
    return items

# ── URGENCY SIGNAL ────────────────────────────────────────────────────────────
def calc_urgency(cves: list, kev: list) -> dict:
    crits  = [c for c in cves if c["severity"] == "CRITICAL"]
    kev_7d = [k for k in kev if k.get("dateAdded","") >= (datetime.now(timezone.utc) - timedelta(days=7)).strftime("%Y-%m-%d")]

    if crits and kev_7d:
        return {"level": "CRITICAL", "colour": "#D94F4F",
                "message": f"<strong>{len(crits)} critical CVE(s)</strong> and <strong>{len(kev_7d)} new KEV addition(s)</strong> in the last 7 days. Review immediately."}
    if crits:
        return {"level": "HIGH", "colour": "#D07A25",
                "message": f"<strong>{len(crits)} critical CVE(s)</strong> published in the last {CVE_LOOKBACK_HOURS}h. Review before standup."}
    if kev_7d:
        return {"level": "ELEVATED", "colour": "#C4A820",
                "message": f"<strong>{len(kev_7d)} new CISA KEV addition(s)</strong> this week. Patch validation recommended."}
    return {"level": "NORMAL", "colour": "#3DA57D",
            "message": "No critical CVEs or new KEV additions in the current window. Routine monitoring."}

# ── EMAIL (optional) ──────────────────────────────────────────────────────────
def send_email(digest: dict) -> None:
    if not all([GMAIL_USER, GMAIL_PASS, EMAIL_TO]):
        print("[email] credentials not set — skipping")
        return
    import smtplib, ssl
    from email.mime.multipart import MIMEMultipart
    from email.mime.text import MIMEText

    crits = [c for c in digest["cves"] if c["severity"] == "CRITICAL"]
    kev   = digest["kev"][:5]

    lines = [
        f"Cyber Digest — {datetime.now(timezone.utc).strftime('%d %b %Y %H:%M UTC')}",
        f"Urgency: {digest['urgency']['level']}",
        "",
        f"Critical CVEs ({len(crits)}):",
    ]
    for c in crits[:5]:
        epss_str = f" | EPSS {c['epss']['epss']*100:.1f}%" if c.get("epss") else ""
        lines.append(f"  {c['id']} | CVSS {c['cvss']}{epss_str} | {c['vendor']} {c['product']}")
        lines.append(f"  {c['desc'][:120]}…")
    lines += ["", f"KEV additions (top {len(kev)}):"]
    for k in kev:
        lines.append(f"  {k.get('cveID','?')} | {k.get('vendorProject','')} {k.get('product','')} | Added {k.get('dateAdded','')}")
    lines += ["", f"ThreatFox IOCs (24h): {len(digest.get('threatfox', []))}"]
    lines += ["", "—", "https://cyber-digest.pages.dev/"]

    msg = MIMEMultipart()
    msg["Subject"] = f"[Cyber Digest] {digest['urgency']['level']} — {datetime.now(timezone.utc).strftime('%d %b %Y')}"
    msg["From"]    = GMAIL_USER
    msg["To"]      = EMAIL_TO
    msg.attach(MIMEText("\n".join(lines), "plain"))

    try:
        ctx = ssl.create_default_context()
        with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=ctx) as s:
            s.login(GMAIL_USER, GMAIL_PASS)
            s.sendmail(GMAIL_USER, EMAIL_TO.split(","), msg.as_string())
        print("[email] sent ok")
    except Exception as e:
        print(f"[email] error: {e}")

# ── DISCORD (optional) ────────────────────────────────────────────────────────
def send_discord(digest: dict) -> None:
    if not DISCORD_WEBHOOK:
        return
    crits   = len([c for c in digest["cves"] if c["severity"] == "CRITICAL"])
    ioc_cnt = len(digest.get("threatfox", []))
    msg     = (f"**Cyber Digest** | {digest['urgency']['level']} | "
               f"{crits} critical CVEs | {len(digest['kev'])} KEV | "
               f"{ioc_cnt} ThreatFox IOCs (24h)")
    try:
        payload = json.dumps({"content": msg}).encode()
        req = urllib.request.Request(DISCORD_WEBHOOK, data=payload,
                                     headers={"Content-Type": "application/json"}, method="POST")
        urllib.request.urlopen(req, timeout=10)
        print("[discord] sent")
    except Exception as e:
        print(f"[discord] error: {e}")

# ── MAIN ──────────────────────────────────────────────────────────────────────
def main():
    print("=== Cyber Digest pipeline v2 starting ===")

    # Primary vulnerability data
    cves    = fetch_nvd_cves()
    kev     = fetch_kev()

    # Mark CVEs that appear in KEV
    kev_ids = {k.get("cveID","").upper() for k in kev}
    for c in cves:
        if c["id"].upper() in kev_ids:
            c["kev"]      = True
            c["exploited"] = True

    # Enrich CVEs with EPSS scores
    cve_ids = [c["id"] for c in cves]
    epss_map = fetch_epss(cve_ids)
    for c in cves:
        c["epss"] = epss_map.get(c["id"])

    # Additional data sources
    gh_advisories = fetch_gh_advisories()
    threatfox     = fetch_threatfox_iocs()
    malwarebazaar = fetch_malwarebazaar()
    feodo_c2      = fetch_feodo_c2()
    osv_vulns     = fetch_osv_recent()

    # RSS feeds
    threats = fetch_feeds(THREAT_FEEDS, "threat")
    news    = fetch_feeds(NEWS_FEEDS,   "news")

    # Urgency signal
    urgency = calc_urgency(cves, kev)

    # KEV 7-day count
    cutoff_7d = (datetime.now(timezone.utc) - timedelta(days=7)).strftime("%Y-%m-%d")
    kev_7d_count = sum(1 for k in kev if k.get("dateAdded","") >= cutoff_7d)

    digest = {
        "generated":      datetime.now(timezone.utc).isoformat(),
        "urgency":        urgency,
        "cves":           cves,
        "kev":            kev,
        "kev_7d":         kev_7d_count,
        "gh_advisories":  gh_advisories,
        "threatfox":      threatfox,
        "malwarebazaar":  malwarebazaar,
        "feodo_c2":       feodo_c2,
        "osv_vulns":      osv_vulns,
        "threats":        threats,
        "news":           news,
        "stats": {
            "total_cves":    len(cves),
            "critical":      len([c for c in cves if c["severity"] == "CRITICAL"]),
            "high":          len([c for c in cves if c["severity"] == "HIGH"]),
            "exploited":     len([c for c in cves if c["exploited"]]),
            "kev_total":     len(kev),
            "kev_7d":        kev_7d_count,
            "gh_advisories": len(gh_advisories),
            "threatfox_iocs": len(threatfox),
            "epss_enriched": len(epss_map),
        }
    }

    # Write full digest.json
    with open("digest.json", "w") as f:
        json.dump(digest, f, indent=2)
    print(f"[OK] digest.json written")

    # Write site/feed.json — lightweight feed for homepage consumption
    # Combines threats + news, sorted by published date, top 50 items
    feed_items = sorted(
        threats + news,
        key=lambda x: x.get("published", ""),
        reverse=True
    )[:50]
    feed = {
        "generated": digest["generated"],
        "urgency":   urgency,
        "kev_7d":    kev_7d_count,
        "items":     feed_items,
        "stats":     digest["stats"],
    }
    import pathlib
    pathlib.Path("site").mkdir(exist_ok=True)
    with open("site/feed.json", "w") as f:
        json.dump(feed, f, indent=2)
    print(f"[OK] site/feed.json written — {len(feed_items)} items")

    print(f"Summary: {len(cves)} CVEs | {len(kev)} KEV | {len(gh_advisories)} GHSA | "
          f"{len(threatfox)} ThreatFox IOCs | {len(threats)+len(news)} feed items")

    # Notifications
    send_email(digest)
    send_discord(digest)

    print("=== Done ===")

if __name__ == "__main__":
    main()

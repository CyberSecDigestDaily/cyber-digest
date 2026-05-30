#!/usr/bin/env python3
"""
Cyber Digest — daily intelligence pipeline
Fetches: CISA KEV, NVD CVEs, threat advisories, security news
Outputs: digest.json (committed to repo → Cloudflare Pages auto-deploys)

Required env vars (set as GitHub Actions secrets):
  NVD_API_KEY        — optional but recommended (higher rate limits)

Optional env vars (email digest — skip if not needed):
  GMAIL_USER         — sender address
  GMAIL_APP_PASSWORD — Google App Password
  EMAIL_TO           — recipient(s), comma-separated
  DISCORD_WEBHOOK    — optional Discord notification URL
"""

import os, json, re, time, urllib.request, urllib.parse, feedparser
from datetime import datetime, timedelta, timezone

# ── CONFIG ────────────────────────────────────────────────────────────────────
NVD_API_KEY     = os.environ.get("NVD_API_KEY", "")
GMAIL_USER      = os.environ.get("GMAIL_USER", "")
GMAIL_PASS      = os.environ.get("GMAIL_APP_PASSWORD", "")
EMAIL_TO        = os.environ.get("EMAIL_TO", "")
DISCORD_WEBHOOK = os.environ.get("DISCORD_WEBHOOK", "")

CVE_LOOKBACK_HOURS = 48   # fetch CVEs published in last 48h
MAX_CVES           = 50
MAX_KEV            = 30
MAX_PER_FEED       = 8

# ── RSS FEEDS ─────────────────────────────────────────────────────────────────
THREAT_FEEDS = [
    ("CISA Advisories",    "https://www.cisa.gov/feeds/hns.xml"),
    ("CISA ICS",           "https://www.cisa.gov/uscert/ics/advisories/advisories.xml"),
    ("Microsoft Security", "https://api.msrc.microsoft.com/update-guide/rss"),
    ("Cisco PSIRT",        "https://tools.cisco.com/security/center/psirt_rss.xml"),
    ("Talos Intelligence", "https://blog.talosintelligence.com/rss/"),
    ("Unit 42",            "https://unit42.paloaltonetworks.com/feed/"),
    ("Red Hat Security",   "https://access.redhat.com/security/security-updates/vulnerabilities.atom"),
]

NEWS_FEEDS = [
    ("Bleeping Computer",  "https://www.bleepingcomputer.com/feed/"),
    ("The Hacker News",    "https://feeds.feedburner.com/TheHackersNews"),
    ("The Record",         "https://therecord.media/feed"),
    ("SecurityWeek",       "https://feeds.feedburner.com/Securityweek"),
    ("Dark Reading",       "https://www.darkreading.com/rss.xml"),
    ("Krebs on Security",  "https://krebsonsecurity.com/feed/"),
    ("SANS ISC Diary",     "https://isc.sans.edu/rssfeed.xml"),
    ("Mandiant Blog",      "https://www.mandiant.com/resources/blog/rss.xml"),
    ("Google Project Zero","https://googleprojectzero.blogspot.com/feeds/posts/default"),
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
    req = urllib.request.Request(url)
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
            "kev":         False,  # patched below after CISA KEV fetch
            "published":   cve.get("published",""),
        })
    print(f"[NVD] {len(cves)} CVEs fetched")
    return cves

# ── FETCH CISA KEV ────────────────────────────────────────────────────────────
def fetch_kev() -> list:
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    try:
        with urllib.request.urlopen(url, timeout=30) as resp:
            data = json.loads(resp.read())
        vulns = data.get("vulnerabilities", [])
        # Sort by dateAdded descending, take most recent
        vulns.sort(key=lambda x: x.get("dateAdded",""), reverse=True)
        print(f"[KEV] {len(vulns)} total entries; returning top {MAX_KEV}")
        return vulns[:MAX_KEV]
    except Exception as e:
        print(f"[KEV] fetch error: {e}")
        return []

# ── FETCH RSS FEEDS ───────────────────────────────────────────────────────────
def fetch_feeds(feed_list: list, category: str) -> list:
    items = []
    for name, url in feed_list:
        try:
            feed = feedparser.parse(url)
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
    # Sort by published date descending
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
    highs = [c for c in digest["cves"] if c["severity"] == "HIGH"]
    kev   = digest["kev"][:5]

    lines = [
        f"Cyber Digest — {datetime.now(timezone.utc).strftime('%d %b %Y %H:%M UTC')}",
        f"Urgency: {digest['urgency']['level']}",
        "",
        f"Critical CVEs ({len(crits)}):",
    ]
    for c in crits[:5]:
        lines.append(f"  {c['id']} | CVSS {c['cvss']} | {c['vendor']} {c['product']}")
        lines.append(f"  {c['desc'][:120]}…")
    lines += ["", f"KEV additions (top {len(kev)}):"]
    for k in kev:
        lines.append(f"  {k.get('cveID','?')} | {k.get('vendorProject','')} {k.get('product','')} | Added {k.get('dateAdded','')}")
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
    crits = len([c for c in digest["cves"] if c["severity"] == "CRITICAL"])
    msg   = f"**Cyber Digest** | {digest['urgency']['level']} | {crits} critical CVEs | {len(digest['kev'])} KEV entries"
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
    print("=== Cyber Digest pipeline starting ===")

    cves    = fetch_nvd_cves()
    kev     = fetch_kev()
    threats = fetch_feeds(THREAT_FEEDS, "threat")
    news    = fetch_feeds(NEWS_FEEDS,   "news")

    # Mark CVEs that appear in KEV
    kev_ids = {k.get("cveID","").upper() for k in kev}
    for c in cves:
        if c["id"].upper() in kev_ids:
            c["kev"] = True
            c["exploited"] = True

    urgency = calc_urgency(cves, kev)

    digest = {
        "generated": datetime.now(timezone.utc).isoformat(),
        "urgency":   urgency,
        "cves":      cves,
        "kev":       kev,
        "threats":   threats,
        "news":      news,
        "stats": {
            "total_cves": len(cves),
            "critical":   len([c for c in cves if c["severity"] == "CRITICAL"]),
            "high":       len([c for c in cves if c["severity"] == "HIGH"]),
            "exploited":  len([c for c in cves if c["exploited"]]),
            "kev_total":  len(kev),
        }
    }

    # Write output
    with open("digest.json", "w") as f:
        json.dump(digest, f, indent=2)
    print(f"[OK] digest.json written — {len(cves)} CVEs, {len(kev)} KEV, {len(news)} news items")

    # Optional notifications
    send_email(digest)
    send_discord(digest)

    print("=== Done ===")

if __name__ == "__main__":
    main()

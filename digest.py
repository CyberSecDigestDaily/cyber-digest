#!/usr/bin/env python3
"""
Daily Cyber Digest v2
Fetches CVEs from NVD, CISA KEV, threat advisories, breaking news, and blog posts.
Outputs digest.json for the web dashboard; emails summary + PDF.
"""

import os
import smtplib
import ssl
import json
import re
import feedparser
import urllib.request
import urllib.parse
from datetime import datetime, timedelta, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders

# ── Config ────────────────────────────────────────────────────────────────────
GMAIL_USER      = os.environ["GMAIL_USER"]
GMAIL_PASSWORD  = os.environ["GMAIL_APP_PASSWORD"]
EMAIL_TO        = os.environ["EMAIL_TO"]
EMAIL_FROM      = os.environ["EMAIL_FROM"]
NVD_API_KEY     = os.environ.get("NVD_API_KEY", "")
DISCORD_WEBHOOK = os.getenv("DISCORD_RELAY_URL")

CVSS_MIN  = 0.0
MAX_CVES  = 30
MAX_ITEMS = 10  # per RSS feed

# ── RSS feeds by category ─────────────────────────────────────────────────────
THREAT_FEEDS = [
    ("CISA Advisories", "https://www.cisa.gov/feeds/hns.xml"),
    ("CISA ICS",        "https://www.cisa.gov/uscert/ics/advisories/advisories.xml"),
    ("Microsoft Security", "https://api.msrc.microsoft.com/update-guide/rss"),
    ("Cisco PSIRT",     "https://tools.cisco.com/security/center/psirt_rss.xml"),
    ("Red Hat Security","https://access.redhat.com/security/security-updates/vulnerabilities.atom"),
]

NEWS_FEEDS = [
    ("Bleeping Computer",  "https://www.bleepingcomputer.com/feed/"),
    ("The Hacker News",    "https://feeds.feedburner.com/TheHackersNews"),
    ("Dark Reading",       "https://www.darkreading.com/rss.xml"),
    ("SecurityWeek",       "https://feeds.feedburner.com/Securityweek"),
]

BLOG_FEEDS = [
    ("Krebs on Security",  "https://krebsonsecurity.com/feed/"),
    ("SANS ISC Diary",     "https://isc.sans.edu/rssfeed.xml"),
    ("Schneier on Security","https://www.schneier.com/feed/atom"),
]

SEVERITY_COLOUR = {
    "CRITICAL": "#D94F4F",
    "HIGH":     "#D07A25",
    "MEDIUM":   "#C4A820",
    "LOW":      "#3DA57D",
    "NONE":     "#57616F",
}

# Reference URL domain → vendor name (fallback when CPE data is absent)
VENDOR_DOMAINS = {
    "microsoft.com":         "Microsoft",
    "msrc.microsoft.com":    "Microsoft",
    "cisco.com":             "Cisco",
    "talosintelligence.com": "Cisco",
    "redhat.com":            "Red Hat",
    "oracle.com":            "Oracle",
    "adobe.com":             "Adobe",
    "apple.com":             "Apple",
    "google.com":            "Google",
    "mozilla.org":           "Mozilla",
    "paloaltonetworks.com":  "Palo Alto Networks",
    "fortinet.com":          "Fortinet",
    "vmware.com":            "VMware",
    "broadcom.com":          "Broadcom",
    "solarwinds.com":        "SolarWinds",
    "ivanti.com":            "Ivanti",
    "juniper.net":           "Juniper",
    "checkpoint.com":        "Check Point",
    "f5.com":                "F5",
    "citrix.com":            "Citrix",
    "atlassian.com":         "Atlassian",
    "apache.org":            "Apache",
    "wordpress.org":         "WordPress",
    "gitlab.com":            "GitLab",
    "sap.com":               "SAP",
    "ibm.com":               "IBM",
    "dell.com":              "Dell",
    "hp.com":                "HP",
    "nginx.org":             "NGINX",
    "nodejs.org":            "Node.js",
    "python.org":            "Python",
    "php.net":               "PHP",
    "openssl.org":           "OpenSSL",
    "jenkins.io":            "Jenkins",
    "elastic.co":            "Elastic",
    "splunk.com":            "Splunk",
    "crowdstrike.com":       "CrowdStrike",
    "sentinelone.com":       "SentinelOne",
}

# ── Helpers ───────────────────────────────────────────────────────────────────
def cvss_to_severity(score: float) -> str:
    if score >= 9.0: return "CRITICAL"
    if score >= 7.0: return "HIGH"
    if score >= 4.0: return "MEDIUM"
    if score > 0.0:  return "LOW"
    return "NONE"

def _parse_date(s: str) -> datetime:
    try:
        return datetime.strptime(s, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except ValueError:
        return datetime.min.replace(tzinfo=timezone.utc)

def extract_vendor_from_refs(refs: list) -> str:
    """Infer vendor name from NVD reference URLs when CPE data is absent."""
    for ref in refs:
        url = ref.get("url", "").lower()
        for domain, vendor in VENDOR_DOMAINS.items():
            if domain in url:
                return vendor
    return ""

def extract_product_from_desc(desc: str) -> str:
    """
    Extract product/software name from CVE description text when CPE data is unavailable.
    Uses patterns common in NVD write-ups: 'in <Product> before/through/version/prior'
    and 'vulnerability in <Product> allows/permits/enables'.
    """
    if not desc:
        return ""

    # Ordered by reliability — most specific first
    patterns = [
        # "in the XYZ service/component/application/module version/before/through..."
        r'\bin\s+(?:the\s+)?([A-Z][A-Za-z0-9][A-Za-z0-9\s\-\_\/\.]{1,45}?)\s+(?:service|component|application|module|plugin|extension|driver|library|package|software)\b',
        # "in XYZ before/through/prior to/version X.Y"
        r'\bin\s+([A-Z][A-Za-z0-9][A-Za-z0-9\s\-\_\/\.]{1,40}?)\s+(?:before|through|prior\s+to|up\s+to|version)\s+[\d]',
        # "vulnerability in (the) XYZ allows/permits/enables/does not"
        r'\bvulnerability\s+in\s+(?:the\s+)?([A-Z][A-Za-z0-9][A-Za-z0-9\s\-\_\/\.]{1,40}?)(?:\s+(?:allows|permits|enables|does\s+not|could|can)|[\.,])',
        # "XYZ contains/has a vulnerability"
        r'\b([A-Z][A-Za-z0-9][A-Za-z0-9\s\-\_\/\.]{1,40}?)\s+(?:contains|has)\s+(?:a|an)\s+(?:vulnerability|flaw|weakness|issue|bug)',
    ]

    stop_words = {'the', 'an', 'a', 'this', 'that', 'some', 'certain', 'multiple', 'various', 'affected'}

    for pat in patterns:
        m = re.search(pat, desc)
        if m:
            product = m.group(1).strip().rstrip('.,; ')
            # Sanity checks
            if (3 <= len(product) <= 50 and
                product.lower() not in stop_words and
                not product[0].isdigit()):
                return product

    return ""

def extract_cpe_fields(cve: dict) -> dict:
    """
    Parse CPE strings from NVD configurations.
    CPE 2.3 format: cpe:2.3:TYPE:VENDOR:PRODUCT:VERSION:...
    TYPE: a=application, o=os, h=hardware
    Returns dict with vendor, product, cpe_type.
    """
    configs  = cve.get("configurations", [])
    vendors  = set()
    products = set()
    types    = set()

    for config in configs:
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                parts = match.get("criteria", "").split(":")
                if len(parts) >= 5:
                    type_code = parts[2]
                    vendor    = parts[3]
                    product   = parts[4]
                    if vendor  and vendor  not in ("*", "-"):
                        vendors.add(vendor.replace("_", " ").title())
                    if product and product not in ("*", "-"):
                        products.add(product.replace("_", " ").title())
                    if type_code == "h":
                        types.add("hardware")
                    elif type_code == "o":
                        types.add("os")
                    else:
                        types.add("software")

    cpe_type = (
        "hardware" if "hardware" in types else
        "os"       if "os"       in types else
        "software"
    )
    return {
        "vendor":   ", ".join(sorted(vendors)[:2]),
        "product":  ", ".join(sorted(products)[:3]),
        "cpe_type": cpe_type,
    }

# ── Data fetchers ─────────────────────────────────────────────────────────────
def fetch_nvd_cves(hours: int = 24) -> list:
    now   = datetime.now(timezone.utc)
    start = now - timedelta(hours=hours)
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
            data = json.loads(resp.read())
    except Exception as e:
        print(f"NVD fetch error: {e}")
        return []

    cves = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cid = cve.get("id", "N/A")
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

        if score < CVSS_MIN:
            continue

        fields = extract_cpe_fields(cve)

        # Cascade of vendor fallbacks
        if not fields["vendor"]:
            fields["vendor"] = extract_vendor_from_refs(cve.get("references", []))

        # Cascade of product fallbacks: CPE → vendor → description extraction
        product = (
            fields["product"] or
            fields["vendor"]  or
            extract_product_from_desc(desc) or
            "Unknown"
        )

        cves.append({
            "id":       cid,
            "score":    score,
            "severity": cvss_to_severity(score),
            "vector":   vector,
            "vendor":   fields["vendor"] or "Unknown",
            "product":  product,
            "type":     fields["cpe_type"],
            "desc":     desc,
            "exploited": bool(cve.get("cisaExploitAdd")),
            "cisaDue":  cve.get("cisaActionDue", ""),
            "cisaName": cve.get("cisaVulnerabilityName", ""),
        })

    # Sort: exploited first, then CVSS descending
    cves.sort(key=lambda x: (x["exploited"], x["score"]), reverse=True)
    return cves

def fetch_cisa_kev(days: int = 7) -> list:
    url    = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    try:
        with urllib.request.urlopen(url, timeout=30) as resp:
            data = json.loads(resp.read())
    except Exception as e:
        print(f"CISA KEV fetch error: {e}")
        return []
    recent = [
        v for v in data.get("vulnerabilities", [])
        if _parse_date(v.get("dateAdded", "")) >= cutoff
    ]
    recent.sort(key=lambda x: x.get("dateAdded", ""), reverse=True)
    return recent

def _fetch_feed_items(feeds: list, hours: int = 24) -> list:
    """Generic RSS/Atom fetcher. Returns items published within `hours` window."""
    items  = []
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
    for source, url in feeds:
        try:
            feed = feedparser.parse(url)
            for entry in feed.entries[:MAX_ITEMS]:
                published = entry.get("published_parsed") or entry.get("updated_parsed")
                if published:
                    dt = datetime(*published[:6], tzinfo=timezone.utc)
                    if dt < cutoff:
                        continue
                title   = entry.get("title", "No title")
                link    = entry.get("link", "#")
                summary = re.sub(r"<[^>]+>", "", entry.get("summary", ""))[:400]
                items.append({"source": source, "title": title, "link": link, "summary": summary})
        except Exception as e:
            print(f"RSS error ({source}): {e}")
    return items

def fetch_threat_advisories() -> list:
    return _fetch_feed_items(THREAT_FEEDS, hours=24)

def fetch_breaking_news() -> list:
    return _fetch_feed_items(NEWS_FEEDS, hours=24)

def fetch_blog_posts() -> list:
    return _fetch_feed_items(BLOG_FEEDS, hours=48)

# ── Urgency logic ─────────────────────────────────────────────────────────────
def get_urgency(cves: list, kev: list) -> dict:
    critical  = len([c for c in cves if c["severity"] == "CRITICAL"])
    high      = len([c for c in cves if c["severity"] == "HIGH"])
    kev_count = len(kev)

    if critical >= 2 or kev_count >= 3:
        level   = "🔴 HIGH PRIORITY"
        colour  = "#D94F4F"
        message = (
            f"Today's digest needs your attention. There are <strong>{critical} CRITICAL</strong> "
            f"and <strong>{high} HIGH</strong> severity CVEs, plus <strong>{kev_count}</strong> "
            f"actively exploited vulnerabilities on the CISA Known Exploited list."
        )
        discord_msg = (
            f"🔴 **Heads up — important security news today!**\n\n"
            f"There are **{high} serious** and **{critical} critical** software vulnerabilities published today, "
            f"plus **{kev_count}** already being actively exploited.\n\n"
            f"**What this means for you:** Make sure updates and patches are being applied."
        )
    elif critical == 1 or high >= 3 or kev_count >= 1:
        level   = "🟡 WORTH REVIEWING"
        colour  = "#C4A820"
        message = (
            f"Some notable activity today — <strong>{critical} CRITICAL</strong>, "
            f"<strong>{high} HIGH</strong> severity CVEs, and <strong>{kev_count}</strong> "
            f"CISA KEV additions. Worth a look when you get a chance."
        )
        discord_msg = (
            f"🟡 **Some security news worth knowing about today**\n\n"
            f"There are **{high} moderate to serious** software vulnerabilities published today"
            f"{f' and **{kev_count}** already being exploited' if kev_count else ''}.\n\n"
            f"**What this means for you:** Nothing urgent, but keep devices and apps up to date."
        )
    else:
        level   = "🟢 ROUTINE"
        colour  = "#3DA57D"
        message = (
            f"Quiet day. No critical vulnerabilities and nothing new on the CISA KEV list. "
            f"<strong>{high} HIGH</strong> severity CVEs to note."
        )
        discord_msg = (
            f"🟢 **All quiet on the security front today**\n\n"
            f"Nothing critical to worry about. **{high} lower-level** vulnerabilities published. "
            f"No action needed beyond normal patch hygiene."
        )

    return {"level": level, "colour": colour, "message": message, "discord": discord_msg}

# ── JSON artifact (web dashboard) ────────────────────────────────────────────
def write_json_artifact(cves: list, kev: list, threats: list, news: list, blogs: list):
    urgency = get_urgency(cves, kev)
    payload = {
        "generated": datetime.now(timezone.utc).isoformat(),
        "urgency": {
            "level":   urgency["level"],
            "colour":  urgency["colour"],
            "message": urgency["message"],
        },
        "stats": {
            "critical": len([c for c in cves if c["severity"] == "CRITICAL"]),
            "high":     len([c for c in cves if c["severity"] == "HIGH"]),
            "medium":   len([c for c in cves if c["severity"] == "MEDIUM"]),
            "low":      len([c for c in cves if c["severity"] == "LOW"]),
            "exploited":len([c for c in cves if c.get("exploited")]),
            "kev":      len(kev),
            "threats":  len(threats),
            "news":     len(news),
            "blogs":    len(blogs),
        },
        "cves":    cves,
        "kev":     kev,
        "threats": threats,
        "news":    news,
        "blogs":   blogs,
    }
    with open("digest.json", "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
    print(
        f"✓ digest.json written "
        f"({len(cves)} CVEs, {len(kev)} KEV, {len(threats)} threats, "
        f"{len(news)} news, {len(blogs)} blogs)"
    )

# ── Email HTML ────────────────────────────────────────────────────────────────
def build_email_body(cves: list, kev: list, threats: list, news: list) -> str:
    today    = datetime.now().strftime("%A, %d %B %Y")
    urgency  = get_urgency(cves, kev)
    critical = len([c for c in cves if c["severity"] == "CRITICAL"])
    high     = len([c for c in cves if c["severity"] == "HIGH"])
    medium   = len([c for c in cves if c["severity"] == "MEDIUM"])
    exploited= len([c for c in cves if c.get("exploited")])

    top_cves = ""
    for c in cves[:5]:
        colour  = SEVERITY_COLOUR.get(c["severity"], "#57616F")
        nvd_url = f"https://nvd.nist.gov/vuln/detail/{c['id']}"
        xflag   = " 🔥" if c.get("exploited") else ""
        top_cves += f"""
<tr>
  <td style="padding:6px 10px;font-family:monospace;font-size:13px">
    <a href="{nvd_url}" style="color:#5B9BD5;text-decoration:none">{c['id']}{xflag}</a>
  </td>
  <td style="padding:6px 10px;text-align:center;font-weight:bold;color:{colour};font-size:13px">{c['score']:.1f}</td>
  <td style="padding:6px 10px;text-align:center">
    <span style="background:{colour};color:#fff;padding:1px 7px;border-radius:3px;font-size:11px;font-weight:bold">{c['severity']}</span>
  </td>
  <td style="padding:6px 10px;font-size:12px;color:#8A95A6">{c['vendor']}</td>
  <td style="padding:6px 10px;font-size:11px;color:#57616F">{c['type']}</td>
</tr>"""

    threat_items = ""
    for t in threats[:4]:
        threat_items += f"""
<tr>
  <td style="padding:5px 10px;font-size:12px;color:#8A95A6">{t['source']}</td>
  <td style="padding:5px 10px;font-size:13px">
    <a href="{t['link']}" style="color:#D48A1A;text-decoration:none">{t['title']}</a>
  </td>
</tr>"""

    news_items = ""
    for n in news[:3]:
        news_items += f"""
<tr>
  <td style="padding:5px 10px;font-size:12px;color:#8A95A6">{n['source']}</td>
  <td style="padding:5px 10px;font-size:13px">
    <a href="{n['link']}" style="color:#5B9BD5;text-decoration:none">{n['title']}</a>
  </td>
</tr>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background:#111317;font-family:Arial,Helvetica,sans-serif;color:#E0E3E9">
<div style="max-width:700px;margin:0 auto;padding:20px">
  <div style="background:#181C22;border:1px solid #252C38;border-radius:8px;padding:22px;margin-bottom:14px">
    <h1 style="margin:0 0 4px;font-size:20px;color:#FFFFFF">Cyber Digest</h1>
    <p style="margin:0;color:#57616F;font-size:13px">{today}</p>
  </div>
  <div style="background:{urgency['colour']}18;border-left:4px solid {urgency['colour']};border-radius:0 8px 8px 0;padding:14px 18px;margin-bottom:14px">
    <div style="font-size:13px;font-weight:bold;color:{urgency['colour']};margin-bottom:5px;text-transform:uppercase;letter-spacing:0.5px">{urgency['level']}</div>
    <div style="font-size:13px;line-height:1.6;color:#E0E3E9">{urgency['message']}</div>
  </div>
  <div style="display:flex;gap:8px;margin-bottom:14px;flex-wrap:wrap">
    <div style="background:#181C22;border:1px solid #252C38;border-radius:6px;padding:10px 16px;flex:1;text-align:center;min-width:70px">
      <div style="font-size:24px;font-weight:bold;color:#D94F4F">{critical}</div>
      <div style="font-size:9px;color:#57616F;text-transform:uppercase;letter-spacing:0.5px">Critical</div>
    </div>
    <div style="background:#181C22;border:1px solid #252C38;border-radius:6px;padding:10px 16px;flex:1;text-align:center;min-width:70px">
      <div style="font-size:24px;font-weight:bold;color:#D07A25">{high}</div>
      <div style="font-size:9px;color:#57616F;text-transform:uppercase;letter-spacing:0.5px">High</div>
    </div>
    <div style="background:#181C22;border:1px solid #252C38;border-radius:6px;padding:10px 16px;flex:1;text-align:center;min-width:70px">
      <div style="font-size:24px;font-weight:bold;color:#C4A820">{medium}</div>
      <div style="font-size:9px;color:#57616F;text-transform:uppercase;letter-spacing:0.5px">Medium</div>
    </div>
    <div style="background:#181C22;border:1px solid #252C38;border-radius:6px;padding:10px 16px;flex:1;text-align:center;min-width:70px">
      <div style="font-size:24px;font-weight:bold;color:#D94F4F">{exploited}</div>
      <div style="font-size:9px;color:#57616F;text-transform:uppercase;letter-spacing:0.5px">Exploited</div>
    </div>
    <div style="background:#181C22;border:1px solid #252C38;border-radius:6px;padding:10px 16px;flex:1;text-align:center;min-width:70px">
      <div style="font-size:24px;font-weight:bold;color:#D48A1A">{len(kev)}</div>
      <div style="font-size:9px;color:#57616F;text-transform:uppercase;letter-spacing:0.5px">CISA KEV</div>
    </div>
    <div style="background:#181C22;border:1px solid #252C38;border-radius:6px;padding:10px 16px;flex:1;text-align:center;min-width:70px">
      <div style="font-size:24px;font-weight:bold;color:#D48A1A">{len(threats)}</div>
      <div style="font-size:9px;color:#57616F;text-transform:uppercase;letter-spacing:0.5px">Advisories</div>
    </div>
  </div>
  <div style="background:#181C22;border:1px solid #252C38;border-radius:8px;padding:16px;margin-bottom:14px">
    <h2 style="margin:0 0 12px;font-size:14px;color:#D94F4F;text-transform:uppercase;letter-spacing:0.4px">Top CVEs Today</h2>
    <table width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse">
      <thead>
        <tr style="color:#57616F;font-size:10px;text-transform:uppercase;letter-spacing:0.4px">
          <th style="padding:4px 10px;text-align:left">CVE</th>
          <th style="padding:4px 10px;text-align:center">CVSS</th>
          <th style="padding:4px 10px;text-align:center">Severity</th>
          <th style="padding:4px 10px;text-align:left">Vendor</th>
          <th style="padding:4px 10px;text-align:left">Type</th>
        </tr>
      </thead>
      <tbody>{top_cves}</tbody>
    </table>
    <p style="margin:10px 0 0;font-size:11px;color:#57616F">🔥 = actively exploited · Full list in PDF</p>
  </div>
  {'<div style="background:#181C22;border:1px solid #252C38;border-radius:8px;padding:16px;margin-bottom:14px"><h2 style="margin:0 0 12px;font-size:14px;color:#D48A1A;text-transform:uppercase;letter-spacing:0.4px">Threat Advisories</h2><table width="100%" cellpadding="0" cellspacing="0"><tbody>' + threat_items + '</tbody></table></div>' if threat_items else ''}
  <div style="background:#181C22;border:1px solid #252C38;border-radius:8px;padding:16px;margin-bottom:14px">
    <h2 style="margin:0 0 12px;font-size:14px;color:#3DA57D;text-transform:uppercase;letter-spacing:0.4px">Top Headlines</h2>
    <table width="100%" cellpadding="0" cellspacing="0"><tbody>{news_items}</tbody></table>
  </div>
  <div style="background:#181C22;border-radius:8px;padding:14px;text-align:center;margin-bottom:14px">
    <p style="margin:0;font-size:13px;color:#8A95A6">
      Full digest attached as PDF — all CVE details, KEV, advisories, news &amp; analysis.
    </p>
  </div>
  <p style="font-size:10px;color:#2C3340;text-align:center">
    Sources: NVD · CISA KEV · MSRC · Cisco PSIRT · Red Hat · Bleeping Computer · The Hacker News · Krebs · Dark Reading · SecurityWeek · SANS ISC · Schneier<br>
    Delivered automatically via GitHub Actions · UTC
  </p>
</div>
</body>
</html>"""

# ── PDF HTML ──────────────────────────────────────────────────────────────────
def build_pdf_html(cves: list, kev: list, threats: list, news: list, blogs: list) -> str:
    today    = datetime.now().strftime("%A, %d %B %Y")
    urgency  = get_urgency(cves, kev)
    critical = len([c for c in cves if c["severity"] == "CRITICAL"])
    high     = len([c for c in cves if c["severity"] == "HIGH"])
    medium   = len([c for c in cves if c["severity"] == "MEDIUM"])
    exploited= len([c for c in cves if c.get("exploited")])

    cover = f"""
<div class="page cover-page">
  <div class="cover-header">
    <div class="cover-title">Cyber Digest</div>
    <div class="cover-date">{today}</div>
    <div class="cover-sub">Automated threat intelligence briefing</div>
  </div>
  <div class="urgency-banner" style="border-color:{urgency['colour']};background:{urgency['colour']}18">
    <div class="urgency-level" style="color:{urgency['colour']}">{urgency['level']}</div>
    <div class="urgency-text">{urgency['message']}</div>
  </div>
  <div class="stats-row">
    <div class="stat-box"><div class="stat-num" style="color:#D94F4F">{critical}</div><div class="stat-label">CRITICAL</div></div>
    <div class="stat-box"><div class="stat-num" style="color:#D07A25">{high}</div><div class="stat-label">HIGH</div></div>
    <div class="stat-box"><div class="stat-num" style="color:#C4A820">{medium}</div><div class="stat-label">MEDIUM</div></div>
    <div class="stat-box"><div class="stat-num" style="color:#D94F4F">{exploited}</div><div class="stat-label">EXPLOITED</div></div>
    <div class="stat-box"><div class="stat-num" style="color:#D48A1A">{len(kev)}</div><div class="stat-label">CISA KEV</div></div>
    <div class="stat-box"><div class="stat-num" style="color:#D48A1A">{len(threats)}</div><div class="stat-label">ADVISORIES</div></div>
    <div class="stat-box"><div class="stat-num" style="color:#5B9BD5">{len(news)}</div><div class="stat-label">NEWS</div></div>
  </div>
  <div class="toc">
    <div class="toc-title">Contents</div>
    <div class="toc-item"><span class="toc-num">1</span> CVE Summary Table</div>
    <div class="toc-item"><span class="toc-num">2</span> CVE Detail (top 20 by CVSS)</div>
    <div class="toc-item"><span class="toc-num">3</span> CISA Known Exploited Vulnerabilities</div>
    <div class="toc-item"><span class="toc-num">4</span> Threat Advisories</div>
    <div class="toc-item"><span class="toc-num">5</span> Breaking News</div>
    <div class="toc-item"><span class="toc-num">6</span> Analysis &amp; Blogs</div>
  </div>
  <div class="cover-footer">
    Sources: NVD (NIST) · CISA KEV · MSRC · Cisco PSIRT · Red Hat Security · CISA ICS ·
    Bleeping Computer · The Hacker News · Dark Reading · SecurityWeek ·
    Krebs on Security · SANS ISC Diary · Schneier on Security
  </div>
</div>"""

    rows = ""
    for c in cves:
        colour     = SEVERITY_COLOUR.get(c["severity"], "#57616F")
        xflag      = " 🔥" if c.get("exploited") else ""
        rows += f"""
<tr>
  <td class="mono" style="color:#5B9BD5">{c['id']}{xflag}</td>
  <td class="center bold" style="color:{colour}">{c['score']:.1f}</td>
  <td class="center"><span class="badge" style="background:{colour}">{c['severity']}</span></td>
  <td>{c['vendor']}</td>
  <td style="color:#57616F;font-size:10px">{c['type']}</td>
</tr>"""

    cve_table_page = f"""
<div class="page">
  <div class="section-header" style="border-color:#D94F4F">
    <span class="section-num">1</span>
    <span class="section-title" style="color:#D94F4F">CVE Summary — Last 24 Hours</span>
    <span class="section-count">{len(cves)} total · 🔥 = actively exploited</span>
  </div>
  <table class="data-table">
    <thead><tr>
      <th>CVE ID</th><th class="center">CVSS</th><th class="center">Severity</th><th>Vendor</th><th>Type</th>
    </tr></thead>
    <tbody>{rows if rows else '<tr><td colspan="5" class="empty">No new CVEs in the last 24 hours.</td></tr>'}</tbody>
  </table>
</div>"""

    cve_cards = ""
    for c in cves[:20]:
        colour      = SEVERITY_COLOUR.get(c["severity"], "#57616F")
        desc        = c["desc"][:600] + ("…" if len(c["desc"]) > 600 else "")
        xbadge      = '<span class="badge" style="background:#D94F4F">🔥 EXPLOITED</span>' if c.get("exploited") else ""
        cve_cards += f"""
<div class="cve-card" style="border-left-color:{colour}">
  <div class="cve-card-header">
    <span class="cve-id">{c['id']}</span>
    <span class="badge" style="background:{colour}">{c['severity']}</span>
    <span class="cve-score" style="color:{colour}">{c['score']:.1f}</span>
    {xbadge}
  </div>
  <div class="cve-affected">Vendor: {c['vendor']} · Product: {c['product']} · Type: {c['type']}</div>
  <div class="cve-desc">{desc}</div>
  {f'<div class="kev-action"><strong>CISA due:</strong> {c["cisaDue"]}</div>' if c.get("cisaDue") else ""}
</div>"""

    cve_detail_page = f"""
<div class="page">
  <div class="section-header" style="border-color:#D07A25">
    <span class="section-num">2</span>
    <span class="section-title" style="color:#D07A25">CVE Detail</span>
    <span class="section-count">Top {min(20, len(cves))} by CVSS score</span>
  </div>
  {cve_cards if cve_cards else '<p class="empty">No CVE details available.</p>'}
</div>"""

    kev_cards = ""
    for v in kev[:10]:
        kev_cards += f"""
<div class="cve-card" style="border-left-color:#D94F4F">
  <div class="cve-card-header">
    <span class="cve-id" style="color:#D94F4F">{v.get('cveID','N/A')}</span>
    <span class="badge" style="background:#D94F4F">ACTIVELY EXPLOITED</span>
  </div>
  <div class="kev-meta">
    <strong>Vendor:</strong> {v.get('vendorProject','')} &nbsp;·&nbsp;
    <strong>Added:</strong> {v.get('dateAdded','')} &nbsp;·&nbsp;
    <strong>Due:</strong> <span style="color:#D48A1A;font-weight:bold">{v.get('dueDate','N/A')}</span>
  </div>
  <div class="kev-name">{v.get('vulnerabilityName','')}</div>
  <div class="cve-desc">{v.get('shortDescription','')[:400]}</div>
  {f'<div class="kev-action"><strong>Required action:</strong> {v.get("requiredAction","")[:250]}</div>' if v.get("requiredAction") else ""}
</div>"""

    kev_page = f"""
<div class="page">
  <div class="section-header" style="border-color:#D94F4F">
    <span class="section-num">3</span>
    <span class="section-title" style="color:#D94F4F">CISA Known Exploited Vulnerabilities</span>
    <span class="section-count">Last 7 days · {len(kev)} entries</span>
  </div>
  {kev_cards if kev_cards else '<p class="empty">No new CISA KEV additions in the last 7 days.</p>'}
</div>"""

    def feed_page(items, num, title, colour, source_label, trunc=300):
        html = ""
        for t in items[:20]:
            html += f"""
<div class="news-item">
  <div class="news-source">{t['source']}</div>
  <div class="news-title" style="color:{colour}">{t['title']}</div>
  {"<div class='news-summary'>" + t['summary'][:trunc] + ("…" if len(t['summary']) > trunc else "") + "</div>" if t['summary'] else ""}
</div>"""
        return f"""
<div class="page">
  <div class="section-header" style="border-color:{colour}">
    <span class="section-num">{num}</span>
    <span class="section-title" style="color:{colour}">{title}</span>
    <span class="section-count">{source_label} · {len(items)} items</span>
  </div>
  {html if html else f'<p class="empty">No items.</p>'}
</div>"""

    threats_page = feed_page(threats, "4", "Threat Advisories",  "#D48A1A", "CISA · MSRC · Cisco PSIRT · Red Hat")
    news_page    = feed_page(news,    "5", "Breaking News",       "#3DA57D", "Last 24 hours")
    blogs_page   = feed_page(blogs,   "6", "Analysis &amp; Blogs","#8B7FD4", "Last 48 hours")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<style>
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{ background: #111317; font-family: Arial, Helvetica, sans-serif; font-size: 12px; color: #E0E3E9; line-height: 1.5; }}
@page {{ margin: 1.8cm 1.5cm; size: A4; }}
.page {{ page-break-after: always; padding-bottom: 20px; }}
.page:last-child {{ page-break-after: avoid; }}
.cover-page {{ display: flex; flex-direction: column; min-height: 90vh; }}
.cover-header {{ background: #181C22; border: 1px solid #252C38; border-radius: 10px; padding: 36px; margin-bottom: 20px; }}
.cover-title {{ font-size: 26px; font-weight: bold; color: #fff; margin-bottom: 6px; }}
.cover-date {{ font-size: 15px; color: #8A95A6; margin-bottom: 4px; }}
.cover-sub {{ font-size: 11px; color: #57616F; }}
.cover-footer {{ margin-top: auto; font-size: 10px; color: #2C3340; text-align: center; padding-top: 20px; }}
.urgency-banner {{ border-left: 4px solid; border-radius: 0 8px 8px 0; padding: 14px 18px; margin-bottom: 20px; }}
.urgency-level {{ font-size: 13px; font-weight: bold; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 5px; }}
.urgency-text {{ font-size: 12px; color: #E0E3E9; line-height: 1.6; }}
.urgency-text strong {{ color: #fff; }}
.stats-row {{ display: flex; gap: 8px; margin-bottom: 20px; flex-wrap: wrap; }}
.stat-box {{ flex: 1; min-width: 70px; background: #181C22; border: 1px solid #252C38; border-radius: 8px; padding: 12px 8px; text-align: center; }}
.stat-num {{ font-size: 24px; font-weight: bold; }}
.stat-label {{ font-size: 9px; color: #57616F; text-transform: uppercase; margin-top: 2px; letter-spacing: 0.5px; }}
.toc {{ background: #181C22; border: 1px solid #252C38; border-radius: 8px; padding: 18px 22px; margin-bottom: 20px; }}
.toc-title {{ font-size: 13px; font-weight: bold; color: #fff; margin-bottom: 12px; }}
.toc-item {{ padding: 6px 0; border-bottom: 1px solid #252C38; font-size: 12px; color: #8A95A6; }}
.toc-item:last-child {{ border-bottom: none; }}
.toc-num {{ display: inline-block; background: #252C38; color: #5B9BD5; border-radius: 3px; padding: 1px 7px; margin-right: 10px; font-weight: bold; font-size: 10px; }}
.section-header {{ border-left: 4px solid; padding: 10px 14px; margin-bottom: 16px; background: #181C22; border-radius: 0 6px 6px 0; display: flex; align-items: center; gap: 10px; }}
.section-num {{ background: #252C38; color: #5B9BD5; border-radius: 3px; padding: 2px 8px; font-weight: bold; font-size: 10px; }}
.section-title {{ font-size: 15px; font-weight: bold; flex: 1; }}
.section-count {{ font-size: 10px; color: #57616F; }}
.data-table {{ width: 100%; border-collapse: collapse; font-size: 11px; background: #181C22; }}
.data-table thead tr {{ background: #1D2229; }}
.data-table th {{ padding: 8px 8px; text-align: left; color: #57616F; font-size: 9px; text-transform: uppercase; letter-spacing: 0.4px; }}
.data-table td {{ padding: 7px 8px; border-bottom: 1px solid #1E2530; color: #E0E3E9; }}
.data-table tr:last-child td {{ border-bottom: none; }}
.mono {{ font-family: monospace; }}
.center {{ text-align: center; }}
.bold {{ font-weight: bold; }}
.badge {{ color: #fff; padding: 2px 7px; border-radius: 3px; font-size: 10px; font-weight: bold; white-space: nowrap; }}
.empty {{ color: #57616F; font-style: italic; padding: 12px 0; }}
.cve-card {{ border-left: 3px solid; padding: 10px 14px; margin: 10px 0; background: #181C22; border-radius: 0 6px 6px 0; page-break-inside: avoid; }}
.cve-card-header {{ margin-bottom: 4px; display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }}
.cve-id {{ font-family: monospace; font-weight: bold; font-size: 13px; color: #5B9BD5; }}
.cve-score {{ font-weight: bold; font-size: 13px; }}
.cve-affected {{ color: #8A95A6; font-size: 10px; margin-bottom: 4px; }}
.cve-desc {{ color: #E0E3E9; font-size: 11px; line-height: 1.5; }}
.kev-meta {{ color: #8A95A6; font-size: 10px; margin-bottom: 3px; }}
.kev-name {{ color: #E8E8E8; font-weight: bold; font-size: 12px; margin-bottom: 4px; }}
.kev-action {{ color: #8A95A6; font-size: 10px; margin-top: 5px; }}
.news-item {{ border-bottom: 1px solid #1E2530; padding: 9px 0; page-break-inside: avoid; }}
.news-item:last-child {{ border-bottom: none; }}
.news-source {{ font-size: 9px; color: #57616F; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 2px; }}
.news-title {{ font-size: 12px; font-weight: 500; margin-bottom: 3px; }}
.news-summary {{ color: #8A95A6; font-size: 10px; line-height: 1.4; }}
</style>
</head>
<body>
{cover}
{cve_table_page}
{cve_detail_page}
{kev_page}
{threats_page}
{news_page}
{blogs_page}
</body>
</html>"""

# ── PDF generation ────────────────────────────────────────────────────────────
def generate_pdf(html: str) -> bytes:
    from weasyprint import HTML
    return HTML(string=html).write_pdf()

# ── Discord ───────────────────────────────────────────────────────────────────
def send_discord(message: str):
    if not DISCORD_WEBHOOK:
        return
    import requests
    auth_token = os.environ.get("DISCORD_AUTH_TOKEN", "")
    try:
        resp = requests.post(
            DISCORD_WEBHOOK,
            json={"content": message},
            headers={"Content-Type": "application/json", "X-Auth-Token": auth_token},
            timeout=10,
        )
        if resp.status_code in (200, 204):
            print(f"✓ Discord notification sent ({resp.status_code})")
        else:
            print(f"Discord error: {resp.status_code} — {resp.text}")
    except Exception as e:
        print(f"Discord error: {e}")

# ── Send email ────────────────────────────────────────────────────────────────
def send_email(email_html: str, pdf_bytes: bytes, cve_count: int):
    today    = datetime.now().strftime("%d %b %Y")
    filename = f"cyber-digest-{datetime.now().strftime('%Y-%m-%d')}.pdf"
    msg = MIMEMultipart("mixed")
    msg["Subject"] = f"Cyber Digest {today} — {cve_count} CVEs"
    msg["From"]    = EMAIL_FROM
    msg["To"]      = EMAIL_TO
    msg.attach(MIMEText(email_html, "html"))
    part = MIMEBase("application", "octet-stream")
    part.set_payload(pdf_bytes)
    encoders.encode_base64(part)
    part.add_header("Content-Disposition", f'attachment; filename="{filename}"')
    msg.attach(part)
    ctx = ssl.create_default_context()
    with smtplib.SMTP("smtp-relay.brevo.com", 587) as server:
        server.ehlo()
        server.starttls(context=ctx)
        server.ehlo()
        server.login(GMAIL_USER, GMAIL_PASSWORD)
        server.sendmail(EMAIL_FROM, EMAIL_TO, msg.as_string())
    print("✓ Email sent successfully.")

# ── Main ──────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("Fetching CVEs from NVD...")
    cves = fetch_nvd_cves(hours=24)
    print(f"  → {len(cves)} CVEs (CVSS >= {CVSS_MIN}), {len([c for c in cves if c['exploited']])} exploited")

    print("Fetching CISA Known Exploited Vulnerabilities...")
    kev = fetch_cisa_kev(days=7)
    print(f"  → {len(kev)} KEV entries")

    print("Fetching threat advisories...")
    threats = fetch_threat_advisories()
    print(f"  → {len(threats)} advisory items")

    print("Fetching breaking news...")
    news = fetch_breaking_news()
    print(f"  → {len(news)} news items")

    print("Fetching blog posts...")
    blogs = fetch_blog_posts()
    print(f"  → {len(blogs)} blog posts")

    print("Writing JSON artifact...")
    write_json_artifact(cves, kev, threats, news, blogs)

    print("Building email...")
    email_html = build_email_body(cves, kev, threats, news)

    print("Building PDF...")
    pdf_html   = build_pdf_html(cves, kev, threats, news, blogs)
    pdf_bytes  = generate_pdf(pdf_html)
    print(f"  → PDF generated ({len(pdf_bytes)//1024} KB)")

    print("Sending email...")
    send_email(email_html, pdf_bytes, len(cves))

    if DISCORD_WEBHOOK:
        print("Sending Discord notification...")
        urgency = get_urgency(cves, kev)
        send_discord(urgency["discord"])

import urllib.request
import urllib.error
import json
import datetime
import csv
import io
import os

# ── Config ────────────────────────────────────────────────────────────────────
MAX_IPS        = 20   # How many malicious IPs to include in full report
MAX_DOMAINS    = 20   # How many malicious domains to include
MAX_HASHES     = 20   # How many malware hashes to include
MAX_PHISHING   = 20   # How many phishing URLs to include

OUTPUT_MD      = "IOC-DAILY.md"
OUTPUT_TWEET   = "X-POST.txt"

# ── Helpers ───────────────────────────────────────────────────────────────────
def fetch_url(url, timeout=30):
    """Fetch a URL and return the response body as a string."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "IOC-Daily-Bot/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="ignore")
    except Exception as e:
        print(f"  [!] Failed to fetch {url}: {e}")
        return None

def fetch_json(url, timeout=30):
    """Fetch a URL and return parsed JSON."""
    raw = fetch_url(url, timeout)
    if raw:
        try:
            return json.loads(raw)
        except Exception as e:
            print(f"  [!] JSON parse error for {url}: {e}")
    return None

# ── Source 1: Malicious IPs — abuse.ch Feodo Tracker ─────────────────────────
def fetch_malicious_ips():
    print("  Fetching malicious IPs from abuse.ch Feodo Tracker...")
    url = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
    data = fetch_json(url)
    results = []
    if data and isinstance(data, list):
        for entry in data[:MAX_IPS]:
            results.append({
                "ip":      entry.get("ip_address", "N/A"),
                "port":    entry.get("port", "N/A"),
                "malware": entry.get("malware", "N/A"),
                "country": entry.get("country", "N/A"),
                "status":  entry.get("status", "N/A"),
            })
    print(f"  [+] Got {len(results)} malicious IPs")
    return results

# ── Source 2: Malicious Domains — URLhaus ─────────────────────────────────────
def fetch_malicious_domains():
    print("  Fetching malicious domains from URLhaus...")
    url = "https://urlhaus-api.abuse.ch/v1/urls/recent/"
    data = fetch_json(url)
    results = []
    if data and data.get("query_status") == "ok":
        for entry in data.get("urls", [])[:MAX_DOMAINS]:
            host = entry.get("host", "N/A")
            # Filter to domains only (no IPs)
            if host and not host.replace(".", "").isdigit():
                results.append({
                    "domain":  host,
                    "url":     entry.get("url", "N/A"),
                    "threat":  entry.get("threat", "N/A"),
                    "status":  entry.get("url_status", "N/A"),
                    "tags":    ", ".join(entry.get("tags", []) or []),
                })
    print(f"  [+] Got {len(results)} malicious domains")
    return results

# ── Source 3: Malware Hashes — MalwareBazaar ─────────────────────────────────
def fetch_malware_hashes():
    print("  Fetching malware hashes from MalwareBazaar...")
    url = "https://mb-api.abuse.ch/api/v1/"
    data_bytes = f"query=get_recent&selector=time".encode()
    try:
        req = urllib.request.Request(
            url,
            data=data_bytes,
            headers={
                "User-Agent": "IOC-Daily-Bot/1.0",
                "Content-Type": "application/x-www-form-urlencoded"
            }
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read().decode("utf-8", errors="ignore")
            data = json.loads(raw)
    except Exception as e:
        print(f"  [!] MalwareBazaar fetch failed: {e}")
        return []

    results = []
    if data and data.get("query_status") == "ok":
        for entry in data.get("data", [])[:MAX_HASHES]:
            results.append({
                "sha256":    entry.get("sha256_hash", "N/A"),
                "md5":       entry.get("md5_hash", "N/A"),
                "file_type": entry.get("file_type", "N/A"),
                "malware":   entry.get("signature", "N/A") or "Unknown",
                "tags":      ", ".join(entry.get("tags", []) or []),
            })
    print(f"  [+] Got {len(results)} malware hashes")
    return results

# ── Source 4: Phishing URLs — OpenPhish ──────────────────────────────────────
def fetch_phishing_urls():
    print("  Fetching phishing URLs from OpenPhish...")
    url = "https://openphish.com/feed.txt"
    raw = fetch_url(url)
    results = []
    if raw:
        lines = [line.strip() for line in raw.splitlines() if line.strip()]
        for line in lines[:MAX_PHISHING]:
            results.append({"url": line})
    print(f"  [+] Got {len(results)} phishing URLs")
    return results

# ── Build Markdown Report ─────────────────────────────────────────────────────
def build_markdown(ips, domains, hashes, phishing):
    now     = datetime.datetime.utcnow()
    today   = now.strftime("%B %d, %Y")
    updated = now.strftime("%B %d, %Y at %H:%M UTC")

    lines = []
    lines.append("# 🛡️ Daily IOC List\n")
    lines.append(f"> **Date:** {today}  ")
    lines.append(f"> **Updated:** {updated}  ")
    lines.append("> **Sources:** abuse.ch Feodo Tracker | URLhaus | MalwareBazaar | OpenPhish\n")
    lines.append("---\n")

    # Summary table
    lines.append("## 📊 Summary\n")
    lines.append("| IOC Type | Count |")
    lines.append("|---|---|")
    lines.append(f"| 🔴 Malicious IPs | {len(ips)} |")
    lines.append(f"| 🌐 Malicious Domains | {len(domains)} |")
    lines.append(f"| 🦠 Malware Hashes | {len(hashes)} |")
    lines.append(f"| 🎣 Phishing URLs | {len(phishing)} |")
    lines.append(f"| **Total IOCs** | **{len(ips)+len(domains)+len(hashes)+len(phishing)}** |")
    lines.append("")
    lines.append("---\n")

    # Malicious IPs
    lines.append("## 🔴 Malicious IPs\n")
    if ips:
        lines.append("| IP Address | Port | Malware | Country | Status |")
        lines.append("|---|---|---|---|---|")
        for e in ips:
            lines.append(f"| `{e['ip']}` | {e['port']} | {e['malware']} | {e['country']} | {e['status']} |")
    else:
        lines.append("_No data retrieved._")
    lines.append("\n---\n")

    # Malicious Domains
    lines.append("## 🌐 Malicious Domains\n")
    if domains:
        lines.append("| Domain | Threat | Status | Tags |")
        lines.append("|---|---|---|---|")
        for e in domains:
            lines.append(f"| `{e['domain']}` | {e['threat']} | {e['status']} | {e['tags'] or 'N/A'} |")
    else:
        lines.append("_No data retrieved._")
    lines.append("\n---\n")

    # Malware Hashes
    lines.append("## 🦠 Malware Hashes\n")
    if hashes:
        lines.append("| SHA256 | MD5 | File Type | Malware | Tags |")
        lines.append("|---|---|---|---|---|")
        for e in hashes:
            lines.append(f"| `{e['sha256'][:16]}...` | `{e['md5'][:12]}...` | {e['file_type']} | {e['malware']} | {e['tags'] or 'N/A'} |")
    else:
        lines.append("_No data retrieved._")
    lines.append("\n---\n")

    # Phishing URLs
    lines.append("## 🎣 Phishing URLs\n")
    if phishing:
        lines.append("| URL |")
        lines.append("|---|")
        for e in phishing:
            lines.append(f"| `{e['url']}` |")
    else:
        lines.append("_No data retrieved._")
    lines.append("\n---\n")

    lines.append("_This report is auto-generated from public threat intelligence feeds. Always verify IOCs before taking action._")
    return "\n".join(lines)

# ── Build X/Twitter Post ──────────────────────────────────────────────────────
def build_x_post(ips, domains, hashes, phishing):
    today = datetime.datetime.utcnow().strftime("%Y-%m-%d")
    total = len(ips) + len(domains) + len(hashes) + len(phishing)

    # Sample top entries for the post
    top_ip     = ips[0]["ip"]      if ips      else "N/A"
    top_domain = domains[0]["domain"] if domains else "N/A"
    top_malware = hashes[0]["malware"] if hashes else "N/A"

    post = f"""🛡️ Daily IOC Report — {today}

📊 {total} Indicators of Compromise collected from public threat feeds:
🔴 Malicious IPs: {len(ips)}
🌐 Malicious Domains: {len(domains)}
🦠 Malware Hashes: {len(hashes)}
🎣 Phishing URLs: {len(phishing)}

🔍 Top indicators:
• IP: {top_ip}
• Domain: {top_domain}
• Malware: {top_malware}

📄 Full IOC list on GitHub 👇
[PASTE YOUR GITHUB LINK HERE]

#ThreatIntel #CyberSecurity #IOC #Infosec #BlueTeam"""

    return post

# ── Main ──────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 50)
    print("  IOC Daily List Generator")
    print("=" * 50)
    print()

    print("[1/4] Fetching Malicious IPs...")
    ips = fetch_malicious_ips()

    print("[2/4] Fetching Malicious Domains...")
    domains = fetch_malicious_domains()

    print("[3/4] Fetching Malware Hashes...")
    hashes = fetch_malware_hashes()

    print("[4/4] Fetching Phishing URLs...")
    phishing = fetch_phishing_urls()

    print()
    print("Generating reports...")

    # Write markdown report
    md = build_markdown(ips, domains, hashes, phishing)
    with open(OUTPUT_MD, "w", encoding="utf-8") as f:
        f.write(md)
    print(f"  [+] {OUTPUT_MD} written")

    # Write X/Twitter post
    post = build_x_post(ips, domains, hashes, phishing)
    with open(OUTPUT_TWEET, "w", encoding="utf-8") as f:
        f.write(post)
    print(f"  [+] {OUTPUT_TWEET} written")

    print()
    print("=" * 50)
    print("  Done! Next steps:")
    print(f"  1. Commit {OUTPUT_MD} to your GitHub repo")
    print(f"  2. Copy {OUTPUT_TWEET} and paste it into X")
    print("=" * 50)
    print()
    print("--- X POST PREVIEW ---")
    print(post)

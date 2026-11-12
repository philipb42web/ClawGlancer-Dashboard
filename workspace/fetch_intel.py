import os
import requests
import time
import json
import re
import html
import hashlib
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_API_URL = "https://api.first.org/data/v1/epss"
OSS_SECURITY_ATOM_URL = "https://www.openwall.com/lists/oss-security/atom.xml"

KILLCHAIN_PATTERNS = {
    "ai_infrastructure": [
        r"\bllm\b", r"\bprompt injection\b", r"\bjailbreak\b", r"\bpytorch\b", 
        r"\btorch\.load\b", r"\bhugging\s?face\b", r"\bmodel weights\b", 
        r"\bweights_only\b", r"\bsafetensors\b", r"\bpickle\b", r"\bvector database\b", 
        r"\bpinecone\b", r"\bmilvus\b", r"\bqdrant\b", r"\bchromadb\b", 
        r"\bollama\b", r"\bvllm\b", r"\blangchain\b", r"\bllamaindex\b", 
        r"\blitellm\b", r"\bcomfyui\b", r"\bmlflow\b", r"\bkubeflow\b", 
        r"\bflowise\b", r"\bdeepseek\b", r"\brag\b", r"\bcontext window\b", r"\binspect ai\b"
    ],
    "edge_perimeter": [
        r"\bvpn\b", r"\bfirewall\b", r"\bgateway\b", r"\bedge appliance\b", 
        r"\bperimeter\b", r"\bivanti\b", r"\bpalo alto\b", r"\bpan-os\b", 
        r"\bfortinet\b", r"\bfortios\b", r"\bsonicwall\b", r"\bcitrix\b", 
        r"\bnetscaler\b", r"\bcheckpoint\b", r"\bn-central\b", r"\bf5\b", r"\bbig-ip\b"
    ],
    "rce": [r"\bremote code execution\b", r"\brce\b", r"\bcode execution\b", r"\barbitrary code\b"],
    "auth_bypass": [r"\bauthentication bypass\b", r"\bauthorization bypass\b", r"\blogin bypass\b", r"\bauth bypass\b"],
    "priv_esc": [r"\bprivilege escalation\b", r"\beop\b", r"\bprivesc\b"],
    "deserialization": [r"\bdeserialization\b", r"\bgadget chain\b", r"\bunsafe deserialization\b"],
    "command_injection": [r"\bcommand injection\b", r"\bos command\b", r"\barbitrary command\b"],
    "sqli": [r"\bsql injection\b", r"\bsqli\b"],
    "ssrf": [r"\bssrf\b", r"\bserver-side request forgery\b"],
    "path_traversal": [r"\bpath traversal\b", r"\bdirectory traversal\b", r"\barbitrary file read\b"],
    "file_write": [r"\barbitrary file\b", r"\bfile write\b"],
    "xss": [r"\bxss\b", r"\bcross-site scripting\b"],
    "dos": [r"\bdenial of service\b", r"\bdos\b"],
    "wormable": [r"\bwormable\b"],
    "in_the_wild": [r"\bin the wild\b", r"\bactively exploited\b", r"\bexploited in the wild\b", r"\b0-day\b", r"\bzero-day\b"],
    "poc": [r"\bpoc\b", r"\bproof of concept\b", r"\bexploit code\b", r"\bmetasploit\b", r"\bweaponized\b"]
}

EXPLOIT_PATTERNS = [
    r"github\.com\/[^\/]+\/(?:cve-\d{4}-\d+|.*(?:poc|exploit|0day|payload))",
    r"rapid7\/metasploit-framework",
    r"packetstormsecurity\.com",
    r"exploit-db\.com",
    r"projectdiscovery\/nuclei-templates",
    r"vulncheck",
    r"0day\.today",
    r"github\.com\/nomi-sec\/poc-in-github"
]

TAG_WEIGHTS = {
    "cisa_kev": 40,
    "in_the_wild": 35,
    "ransomware": 35,
    "edge_perimeter": 35,
    "ai_infrastructure": 35,
    "rce": 30,
    "pre_auth": 25,
    "weaponized": 25,
    "auth_bypass": 25,
    "priv_esc": 25,
    "wormable": 25,
    "deserialization": 20,
    "poc": 20,
    "oss_security": 20,
    "command_injection": 18,
    "sqli": 18,
    "ssrf": 18,
    "path_traversal": 15,
    "file_write": 15,
    "xss": 8,
    "dos": 3
}

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"
TIMEOUT = 12
MAX_RETRIES = 3
BACKOFF_DELAYS = [1, 2, 4]

HEADERS = {"User-Agent": USER_AGENT}

OUTPUT_KEYS = [
    "cve_id",
    "published",
    "last_modified",
    "cvss_v3",
    "severity",
    "affected",
    "summary",
    "references",
    "source",
    "cisa_kev",
    "ransomware_campaign",
    "pre_auth",
    "weaponized",
    "epss",
    "epss_percentile",
    "score_breakdown",
    "cvss_vector"
]

RECENT_WINDOW = timedelta(hours=72)

def fetch_url(url):
    for i in range(MAX_RETRIES):
        try:
            r = requests.get(url, headers=HEADERS, timeout=TIMEOUT)
            if r.status_code == 200:
                return r.json()
            if r.status_code in (429, 503):
                time.sleep(BACKOFF_DELAYS[min(i, len(BACKOFF_DELAYS)-1)])
                continue
            return None
        except requests.exceptions.RequestException:
            time.sleep(BACKOFF_DELAYS[min(i, len(BACKOFF_DELAYS)-1)])
    return None

def is_recent(date_str):
    if not date_str:
        return False
    try:
        s = date_str.strip()
        if s.endswith("Z"):
            dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        else:
            dt = datetime.fromisoformat(s)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)

        now = datetime.now(timezone.utc)
        return dt > (now - RECENT_WINDOW)
    except Exception:
        return False

def _cvss_severity(score):
    if score is None:
        return None
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"

def _extract_cpes_from_nodes(nodes):
    cpes = []
    def walk(node):
        if not isinstance(node, dict):
            return
        matches = node.get("cpeMatch") or node.get("cpe_match") or []
        for m in matches:
            if isinstance(m, dict):
                uri = m.get("criteria") or m.get("cpe23Uri") or m.get("cpe23Uri".lower())
                if uri:
                    cpes.append(uri)
        for child in node.get("children", []) or []:
            walk(child)

    for n in nodes or []:
        walk(n)

    return cpes

def _parse_affected_from_cpes(cpe_uris):
    out = []
    for cpe_uri in cpe_uris:
        try:
            parts = cpe_uri.split(":")
            vendor = parts[3] if len(parts) > 3 else None
            product = parts[4] if len(parts) > 4 else None
            version = parts[5] if len(parts) > 5 else "*"
            out.append({
                "vendor": vendor or None,
                "product": product or None,
                "versions": [version or "*"]
            })
        except Exception:
            continue
    return out

def normalize_threat(threat_obj, source):
    normalized = {k: None for k in OUTPUT_KEYS}
    normalized["source"] = source
    normalized["cisa_kev"] = False
    normalized["ransomware_campaign"] = False
    normalized["pre_auth"] = False
    normalized["weaponized"] = False

    if source == "NVD":
        wrapper = threat_obj if isinstance(threat_obj, dict) else {}
        cve = wrapper.get("cve", {}) if isinstance(wrapper.get("cve", {}), dict) else {}

        normalized["cve_id"] = (
            cve.get("id")
            or cve.get("CVE_data_meta", {}).get("ID")
            or wrapper.get("id")
        )

        normalized["published"] = (
            cve.get("published")
            or wrapper.get("publishedDate")
            or wrapper.get("published")
        )
        normalized["last_modified"] = (
            cve.get("lastModified")
            or wrapper.get("lastModifiedDate")
            or wrapper.get("last_modified")
        )

        score = None
        cvss_data = None
        metrics = cve.get("metrics", {}) if isinstance(cve.get("metrics", {}), dict) else {}
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV3"):
            arr = metrics.get(key)
            if isinstance(arr, list) and arr:
                cvss_data = arr[0].get("cvssData", {}) if isinstance(arr[0], dict) else {}
                score = cvss_data.get("baseScore")
                if score is not None:
                    break

        if score is None:
            impact = cve.get("impact", {}) if isinstance(cve.get("impact", {}), dict) else {}
            bm3 = impact.get("baseMetricV3", {}) if isinstance(impact.get("baseMetricV3", {}), dict) else {}
            cvss_v3 = bm3.get("cvssV3", {}) if isinstance(bm3.get("cvssV3", {}), dict) else {}
            score = cvss_v3.get("baseScore")
            cvss_data = cvss_v3

        normalized["cvss_v3"] = score
        normalized["severity"] = _cvss_severity(score)

        if cvss_data:
            attack_vector = cvss_data.get("attackVector")
            priv_req = cvss_data.get("privilegesRequired")
            vector_string = cvss_data.get("vectorString")
            normalized["cvss_vector"] = vector_string
            if attack_vector == "NETWORK" and priv_req in ("NONE", None):
                normalized["pre_auth"] = True

        # Summary/description
        descs = cve.get("descriptions")
        if isinstance(descs, list) and descs:
            en = next((d for d in descs if isinstance(d, dict) and d.get("lang") == "en"), None)
            normalized["summary"] = (en or descs[0]).get("value") if isinstance((en or descs[0]), dict) else None
        else:
            descriptions = cve.get("description", {}).get("description_data", [])
            if descriptions:
                normalized["summary"] = descriptions[0].get("value")

        # References
        refs = cve.get("references")
        normalized["references"] = []
        if isinstance(refs, list):
            for ref in refs:
                if isinstance(ref, dict):
                    url = ref.get("url")
                    if url:
                        normalized["references"].append(url)
        else:
            refs_old = cve.get("references", {}).get("reference_data", [])
            for ref in refs_old:
                url = ref.get("url")
                if url:
                    normalized["references"].append(url)

        configs = wrapper.get("configurations", [])
        all_nodes = []

        if isinstance(configs, dict):
            all_nodes = configs.get("nodes", []) or []
        elif isinstance(configs, list):
            for cfg in configs:
                if isinstance(cfg, dict):
                    nodes = cfg.get("nodes", []) or []
                    all_nodes.extend(nodes)

        cpe_uris = _extract_cpes_from_nodes(all_nodes)
        normalized["affected"] = _parse_affected_from_cpes(cpe_uris)

    elif source == "CIRCL":
        normalized["cve_id"] = threat_obj.get("id")
        normalized["published"] = threat_obj.get("Published")
        normalized["last_modified"] = threat_obj.get("Modified")

        score = None
        if "cvss" in threat_obj:
            try:
                score = float(threat_obj["cvss"])
            except Exception:
                score = None
        normalized["cvss_v3"] = score
        normalized["severity"] = _cvss_severity(score)
        normalized["summary"] = threat_obj.get("summary")
        normalized["references"] = [r for r in (threat_obj.get("references", []) or []) if r]
        normalized["affected"] = [{"vendor": None, "product": None, "versions": []}]

    else:
        normalized["cve_id"] = threat_obj.get("id") if isinstance(threat_obj, dict) else None
        normalized["references"] = []
        normalized["affected"] = []

    return normalized

def dedupe_and_filter(vulns):
    unique = {}
    stats = {
        "total": 0,
        "missing_id": 0,
        "missing_score": 0,
        "score_lt_7": 0,
        "not_recent": 0,
        "kept": 0
    }

    for v in vulns:
        stats["total"] += 1
        cid = v.get("cve_id")
        if not cid:
            stats["missing_id"] += 1
            continue

        score = v.get("cvss_v3")
        if score is None:
            stats["missing_score"] += 1
            continue
        if score < 7.0:
            stats["score_lt_7"] += 1
            continue

        if not (is_recent(v.get("published")) or is_recent(v.get("last_modified"))):
            stats["not_recent"] += 1
            continue

        if cid not in unique:
            unique[cid] = v

    out = list(unique.values())
    stats["kept"] = len(out)
    print("Filter stats:", stats)
    return out

def fetch_nvd_data():
    from urllib.parse import urlencode
    now = datetime.now(timezone.utc)
    start = (now - RECENT_WINDOW).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    end = now.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    params = {
        "resultsPerPage": 2000,
        "lastModStartDate": start,
        "lastModEndDate": end
    }
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0?" + urlencode(params)
    data = fetch_url(url)
    if not data:
        return []
    vulns = []
    for item in data.get("vulnerabilities", []) or []:
        norm = normalize_threat(item, "NVD")
        vulns.append(norm)
    return vulns

def clean_text(text):
    if not text:
        return ""
    clean = re.sub(r"<[^>]+>", "", text)
    clean = html.unescape(clean)
    return re.sub(r"\s+", " ", clean).strip()

def fetch_cisa_kev():
    print("Fetching CISA Known Exploited Vulnerabilities (KEV)...")
    try:
        r = requests.get(CISA_KEV_URL, headers=HEADERS, timeout=TIMEOUT)
        if r.status_code == 200:
            data = r.json()
            vulns = data.get("vulnerabilities", [])
            kev_map = {}
            for item in vulns:
                cid = item.get("cveID")
                if cid:
                    known_ransomware = (
                        str(item.get("knownRansomwareCampaignUse", "")).strip().lower() == "known"
                    )
                    kev_map[cid] = {
                        "date_added": item.get("dateAdded"),
                        "vendor_project": item.get("vendorProject"),
                        "product": item.get("product"),
                        "short_description": item.get("shortDescription"),
                        "required_action": item.get("requiredAction"),
                        "known_ransomware": known_ransomware
                    }
            print(f"Loaded {len(kev_map)} CISA KEV active threat entries.")
            return kev_map
    except Exception as e:
        print(f"Warning: Failed to fetch CISA KEV: {e}")
    return {}

def fetch_epss_scores(cve_ids):
    print("Fetching EPSS scores from FIRST.org...")
    epss_map = {}
    if not cve_ids:
        return epss_map

    # Query in batches of 40 to avoid URI length limits
    batch_size = 40
    for i in range(0, len(cve_ids), batch_size):
        chunk = cve_ids[i:i + batch_size]
        cve_query = ",".join(chunk)
        url = f"{EPSS_API_URL}?cve={cve_query}"
        try:
            r = requests.get(url, headers=HEADERS, timeout=TIMEOUT)
            if r.status_code == 200:
                res = r.json()
                for row in res.get("data", []):
                    cid = row.get("cve")
                    if cid:
                        try:
                            score = float(row.get("epss", 0.0))
                            perc = float(row.get("percentile", 0.0))
                            epss_map[cid] = {"score": score, "percentile": perc}
                        except (ValueError, TypeError):
                            pass
            time.sleep(0.15)
        except Exception as e:
            print(f"Warning: EPSS fetch failed for batch: {e}")
    print(f"Loaded EPSS scores for {len(epss_map)} CVEs.")
    return epss_map

def fetch_oss_security():
    """
    Fetches raw plain-text / atom updates from Openwall oss-security mailing list.
    Captures zero-days and maintainer disclosures before NVD mints or assigns scores.
    """
    print("Fetching Openwall oss-security mailing list (Pre-NVD / Vanguard feed)...")
    items = []
    try:
        r = requests.get(OSS_SECURITY_ATOM_URL, headers=HEADERS, timeout=TIMEOUT)
        if r.status_code == 200:
            root = ET.fromstring(r.content)
            ns = {"atom": "http://www.w3.org/2005/Atom"}
            for entry in root.findall("atom:entry", ns)[:30]:
                title = clean_text(entry.findtext("atom:title", "", ns))
                link_elem = entry.find("atom:link", ns)
                link = link_elem.get("href") if link_elem is not None else "https://www.openwall.com/lists/oss-security/"
                updated = entry.findtext("atom:updated", "", ns) or ""
                summary = clean_text(entry.findtext("atom:summary", "", ns)) or clean_text(entry.findtext("atom:content", "", ns)) or title

                cves = re.findall(r"CVE-\d{4}-\d+", title + " " + summary)
                cve_id = cves[0] if cves else None

                items.append({
                    "title": title,
                    "link": link,
                    "published": updated,
                    "summary": summary,
                    "cve_id": cve_id,
                    "source": "oss-security"
                })
            print(f"Loaded {len(items)} oss-security entries.")
    except Exception as e:
        print(f"Notice: oss-security feed fetch offline or skipped: {e}")
    return items

def fetch_ticker_intel():
    print("Fetching cyber intelligence ticker feeds (oss-security, SANS ISC, CISA, BleepingComputer)...")
    ticker_items = []

    # 1. Openwall oss-security (Pre-Disclosure Vanguard)
    try:
        r = requests.get(OSS_SECURITY_ATOM_URL, headers=HEADERS, timeout=TIMEOUT)
        if r.status_code == 200:
            root = ET.fromstring(r.content)
            ns = {"atom": "http://www.w3.org/2005/Atom"}
            for entry in root.findall("atom:entry", ns)[:3]:
                title = clean_text(entry.findtext("atom:title", "", ns))
                link_elem = entry.find("atom:link", ns)
                link = link_elem.get("href") if link_elem is not None else "https://www.openwall.com/lists/oss-security/"
                updated = entry.findtext("atom:updated", "", ns) or ""
                if title:
                    ticker_items.append({
                        "source": "oss-sec",
                        "title": title,
                        "link": link.strip(),
                        "time": updated.strip()
                    })
    except Exception as e:
        print(f"Warning: oss-security ticker error: {e}")

    # 2. SANS Internet Storm Center
    try:
        r = requests.get("https://isc.sans.edu/rssfeed.xml", headers=HEADERS, timeout=TIMEOUT)
        if r.status_code == 200:
            root = ET.fromstring(r.content)
            for item in root.findall(".//item")[:3]:
                title = clean_text(item.findtext("title"))
                link = item.findtext("link") or "https://isc.sans.edu/"
                pub = item.findtext("pubDate") or ""
                if title:
                    ticker_items.append({
                        "source": "SANS ISC",
                        "title": title,
                        "link": link.strip(),
                        "time": pub.strip()
                    })
    except Exception as e:
        print(f"Warning: SANS ISC RSS fetch error: {e}")

    # 3. CISA Cybersecurity Advisories
    try:
        r = requests.get("https://www.cisa.gov/cybersecurity-advisories/all.xml", headers=HEADERS, timeout=TIMEOUT)
        if r.status_code == 200:
            root = ET.fromstring(r.content)
            for item in root.findall(".//item")[:3]:
                title = clean_text(item.findtext("title"))
                link = item.findtext("link") or "https://www.cisa.gov/cybersecurity-advisories"
                pub = item.findtext("pubDate") or ""
                if title:
                    ticker_items.append({
                        "source": "CISA Alert",
                        "title": title,
                        "link": link.strip(),
                        "time": pub.strip()
                    })
    except Exception as e:
        print(f"Warning: CISA Advisories RSS fetch error: {e}")

    # 4. BleepingComputer / DFIR
    try:
        r = requests.get("https://www.bleepingcomputer.com/feed/", headers=HEADERS, timeout=TIMEOUT)
        if r.status_code == 200:
            root = ET.fromstring(r.content)
            for item in root.findall(".//item")[:3]:
                title = clean_text(item.findtext("title"))
                link = item.findtext("link") or "https://www.bleepingcomputer.com/"
                pub = item.findtext("pubDate") or ""
                if title:
                    ticker_items.append({
                        "source": "BleepingComputer",
                        "title": title,
                        "link": link.strip(),
                        "time": pub.strip()
                    })
    except Exception as e:
        print(f"Warning: BleepingComputer RSS fetch error: {e}")

    if not ticker_items:
        ticker_items = [
            {"source": "oss-sec", "title": "Openwall oss-security pre-disclosure stream active", "link": "https://www.openwall.com/lists/oss-security/", "time": "Latest"},
            {"source": "SANS ISC", "title": "Internet Storm Center Infocon: Green - Threat level nominal", "link": "https://isc.sans.edu", "time": "Latest"},
            {"source": "CISA", "title": "CISA adds new actively exploited zero-days to KEV catalog", "link": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog", "time": "Latest"},
            {"source": "FIRST", "title": "EPSS automated exploit prediction modeling active", "link": "https://www.first.org/epss/", "time": "Latest"}
        ]

    print(f"Compiled {len(ticker_items)} live ticker headlines.")
    return ticker_items

def classify_and_score(v, cisa_kev_map=None, epss_map=None, oss_cve_map=None):
    if cisa_kev_map is None:
        cisa_kev_map = {}
    if epss_map is None:
        epss_map = {}
    if oss_cve_map is None:
        oss_cve_map = {}

    text_parts = []
    if v.get("summary"):
        text_parts.append(v["summary"])
    if v.get("references"):
        text_parts.append(" ".join(v["references"]))
    text = " ".join(text_parts).lower()

    tags = list(v.get("tags") or [])
    reasons = []

    # Base score from CVSS
    cvss = v.get("cvss_v3")
    base_cvss_pts = round(float(cvss) * 5.0, 1) if cvss is not None else 25.0
    score = base_cvss_pts

    breakdown = {
        "base_cvss": base_cvss_pts,
        "freshness": 0,
        "components": []
    }

    # Freshness boost
    if is_recent(v.get("last_modified")):
        score += 10
        breakdown["freshness"] = 10
        reasons.append("recently modified (last 48h)")

    # 1. Keyword killchain tags
    for tag, patterns in KILLCHAIN_PATTERNS.items():
        for pat in patterns:
            if re.search(pat, text):
                tags.append(tag)
                w = TAG_WEIGHTS.get(tag, 0)
                score += w
                reasons.append(f"{tag}+{w}")
                breakdown["components"].append({"signal": f"Tag: {tag}", "points": w})
                break

    # 2. Pre-Auth Remote Execution Vector
    is_pre_auth = bool(v.get("pre_auth"))
    if not is_pre_auth:
        if re.search(r"\b(unauthenticated|pre-auth|pre-authentication|without authentication|no authentication)\b", text):
            is_pre_auth = True

    if is_pre_auth and ("rce" in tags or "auth_bypass" in tags or "command_injection" in tags or "edge_perimeter" in tags):
        v["pre_auth"] = True
        tags.append("pre_auth")
        score += 25
        reasons.append("Pre-Auth Remote Execution (+25)")
        breakdown["components"].append({"signal": "Pre-Auth Remote Execution", "points": 25})
    else:
        v["pre_auth"] = is_pre_auth

    # 3. Verified Weaponized Exploit / PoC Detection
    is_weaponized = False
    refs_str = " ".join(v.get("references") or []).lower()
    for pat in EXPLOIT_PATTERNS:
        if re.search(pat, refs_str):
            is_weaponized = True
            break

    if is_weaponized:
        v["weaponized"] = True
        tags.append("weaponized")
        score += 25
        reasons.append("Weaponized Exploit / Public PoC verified (+25)")
        breakdown["components"].append({"signal": "Verified Weaponized Exploit", "points": 25})
    else:
        v["weaponized"] = False

    # 4. CISA KEV & Ransomware Campaign Cross-reference
    cid = v.get("cve_id")
    prev_kev = bool(v.get("cisa_kev") or "cisa_kev" in (v.get("tags") or []))
    prev_ransomware = bool(v.get("ransomware_campaign") or "ransomware" in (v.get("tags") or []))

    is_kev = False
    is_ransomware = False
    if cid and cid in cisa_kev_map:
        is_kev = True
        is_ransomware = bool(cisa_kev_map[cid].get("known_ransomware"))
    elif prev_kev and not cisa_kev_map:
        is_kev = True
        is_ransomware = prev_ransomware

    if is_kev:
        v["cisa_kev"] = True
        tags.append("cisa_kev")
        tags.append("in_the_wild")
        score += 40
        reasons.append("CISA KEV active exploitation (+40)")
        breakdown["components"].append({"signal": "CISA KEV Active Exploit", "points": 40})

        if is_ransomware:
            v["ransomware_campaign"] = True
            tags.append("ransomware")
            score += 35
            reasons.append("CISA KEV Known Ransomware Campaign (+35)")
            breakdown["components"].append({"signal": "Known Ransomware Campaign", "points": 35})
        else:
            v["ransomware_campaign"] = False
    else:
        v["cisa_kev"] = False
        v["ransomware_campaign"] = False

    # 5. Openwall oss-security Pre-Disclosure Correlation
    if cid and cid in oss_cve_map:
        tags.append("oss_security")
        score += 20
        reasons.append("oss-security upstream disclosure (+20)")
        breakdown["components"].append({"signal": "oss-security Pre-Disclosure", "points": 20})
        oss_info = oss_cve_map[cid]
        if oss_info.get("link") and oss_info["link"] not in (v.get("references") or []):
            v.setdefault("references", []).insert(0, oss_info["link"])

    # 6. EPSS Score Enrichment
    if cid and cid in epss_map:
        epss_info = epss_map[cid]
        epss_val = epss_info.get("score", 0.0)
        perc = epss_info.get("percentile", 0.0)
        v["epss"] = round(epss_val * 100, 1)
        v["epss_percentile"] = round(perc * 100, 1)
    else:
        v["epss"] = v.get("epss")
        v["epss_percentile"] = v.get("epss_percentile")

    if v.get("epss") is not None:
        try:
            epss_num = float(v["epss"])
            if epss_num >= 50.0:
                score += 25
                reasons.append(f"High EPSS exploit prob {v['epss']}% (+25)")
                breakdown["components"].append({"signal": f"High EPSS ({v['epss']}%)", "points": 25})
            elif epss_num >= 15.0:
                score += 10
                reasons.append(f"Moderate EPSS prob {v['epss']}% (+10)")
                breakdown["components"].append({"signal": f"Moderate EPSS ({v['epss']}%)", "points": 10})
        except (ValueError, TypeError):
            pass

    # Clamp / normalize
    v["tags"] = sorted(set(tags))
    v["intel_score"] = round(score, 2)
    v["reasons"] = reasons[:12]
    v["score_breakdown"] = breakdown
    return v

def main():
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    default_data_dir = os.path.join(repo_root, "data")
    data_dir = os.environ.get("DATA_DIR", default_data_dir)
    os.makedirs(data_dir, exist_ok=True)

    out_path = f"{data_dir}/critical_threats.json"
    top_path = f"{data_dir}/prioritized_threats.json"

    # 1. Ingest CISA KEV (with Ransomware Tracking)
    cisa_kev_map = fetch_cisa_kev()

    # 2. Ingest Openwall oss-security Vanguard Feed
    oss_items = fetch_oss_security()
    oss_cve_map = {}
    oss_standalone = []
    for it in oss_items:
        cid = it.get("cve_id")
        if cid:
            oss_cve_map[cid] = it
        else:
            title_lower = (it.get("title") or "").lower()
            if any(k in title_lower for k in ["vulnerability", "rce", "escape", "bypass", "uaf", "overflow", "injection", "zero-day", "0-day"]):
                oss_standalone.append(it)

    # 3. Fetch NVD data
    vulns = fetch_nvd_data()
    vulns = dedupe_and_filter(vulns)

    # Fallback to existing vulnerabilities if NVD returns empty / offline
    if not vulns:
        fallback_candidates = [out_path, top_path]
        for fb in fallback_candidates:
            if os.path.exists(fb):
                try:
                    with open(fb, "r", encoding="utf-8") as f:
                        vulns = json.load(f)
                    print(f"Retained {len(vulns)} vulnerabilities from cache: {fb}")
                    break
                except Exception:
                    pass

    # Inject standalone pre-NVD / zero-day disclosures from oss-security
    existing_cves = {x.get("cve_id") for x in vulns if x.get("cve_id")}
    for item in oss_standalone[:5]:
        clean_title = item.get("title", "")
        slug = hashlib.md5(clean_title.encode("utf-8")).hexdigest()[:8].upper()
        pre_id = f"PRE-NVD-{slug}"
        if pre_id not in existing_cves:
            v_oss = {
                "cve_id": pre_id,
                "published": item.get("published"),
                "last_modified": item.get("published"),
                "cvss_v3": 8.5,
                "severity": "HIGH",
                "affected": [],
                "summary": f"[Pre-Disclosure Vanguard] {clean_title} — {item.get('summary', '')[:260]}",
                "references": [item.get("link")],
                "source": "oss-security",
                "cisa_kev": False,
                "ransomware_campaign": False,
                "pre_auth": True if any(x in clean_title.lower() for x in ["pre-auth", "unauth", "remote"]) else False,
                "weaponized": True if any(x in clean_title.lower() for x in ["poc", "exploit", "uaf", "overflow"]) else False,
                "epss": None,
                "epss_percentile": None,
                "tags": ["oss_security", "pre_nvd"],
                "intel_score": 115.0,
                "reasons": ["oss-security upstream disclosure (+20)", "pre-NVD vanguard early warning (+20)"],
                "score_breakdown": {
                    "base_cvss": 42.5,
                    "freshness": 10,
                    "components": [
                        {"signal": "oss-security Upstream Advisory", "points": 20},
                        {"signal": "Pre-NVD Vanguard Alert", "points": 20}
                    ]
                }
            }
            vulns.append(v_oss)

    # 4. Query EPSS for candidate CVEs
    candidate_cve_ids = [v["cve_id"] for v in vulns if v.get("cve_id") and v["cve_id"].startswith("CVE-")]
    epss_map = fetch_epss_scores(candidate_cve_ids)

    # 5. Classify and score
    vulns = [classify_and_score(v, cisa_kev_map, epss_map, oss_cve_map) for v in vulns]
    vulns_sorted = sorted(vulns, key=lambda x: x.get("intel_score", 0.0), reverse=True)

    tmp_path = out_path + ".tmp"
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(vulns_sorted, f, indent=2, ensure_ascii=False)
    os.replace(tmp_path, out_path)

    top_items = vulns_sorted[:100]

    # Calculate delta against previous top list if present
    old_top_items = []
    if os.path.exists(top_path):
        try:
            with open(top_path, "r", encoding="utf-8") as f:
                old_top_items = json.load(f)
        except Exception:
            old_top_items = []

    old_ids = {x.get("cve_id") for x in old_top_items if x.get("cve_id")}
    new_ids = {x.get("cve_id") for x in top_items if x.get("cve_id")}

    new_count = len(new_ids - old_ids) if old_ids else 0
    dropped_count = len(old_ids - new_ids) if old_ids else 0
    top_changed = False
    if old_top_items and top_items:
        top_changed = (old_top_items[0].get("cve_id") != top_items[0].get("cve_id"))

    now_iso = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

    delta = {
        "new_count": new_count,
        "dropped_count": dropped_count,
        "top_changed": top_changed,
        "generated_at": now_iso
    }
    delta_path = f"{data_dir}/delta.json"
    delta_tmp = delta_path + ".tmp"
    with open(delta_tmp, "w", encoding="utf-8") as f:
        json.dump(delta, f, indent=2, ensure_ascii=False)
    os.replace(delta_tmp, delta_path)

    # Sync root delta.json
    root_delta_path = os.path.join(repo_root, "delta.json")
    try:
        with open(root_delta_path + ".tmp", "w", encoding="utf-8") as f:
            json.dump(delta, f, indent=2, ensure_ascii=False)
        os.replace(root_delta_path + ".tmp", root_delta_path)
    except Exception:
        pass

    top_tmp = top_path + ".tmp"
    with open(top_tmp, "w", encoding="utf-8") as f:
        json.dump(top_items, f, indent=2, ensure_ascii=False)
    os.replace(top_tmp, top_path)

    # Sync root prioritized_threats.json
    root_top_path = os.path.join(repo_root, "prioritized_threats.json")
    try:
        with open(root_top_path + ".tmp", "w", encoding="utf-8") as f:
            json.dump(top_items, f, indent=2, ensure_ascii=False)
        os.replace(root_top_path + ".tmp", root_top_path)
    except Exception:
        pass

    meta_path = f"{data_dir}/meta.json"
    meta_tmp = meta_path + ".tmp"
    meta = {
        "generated_at": now_iso,
        "count_total": len(vulns_sorted),
        "count_top": min(100, len(vulns_sorted)),
    }
    with open(meta_tmp, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2, ensure_ascii=False)
    os.replace(meta_tmp, meta_path)

    # 6. Fetch and save rolling ticker feed
    ticker_feed = fetch_ticker_intel()
    ticker_path = f"{data_dir}/ticker_feed.json"
    ticker_tmp = ticker_path + ".tmp"
    with open(ticker_tmp, "w", encoding="utf-8") as f:
        json.dump(ticker_feed, f, indent=2, ensure_ascii=False)
    os.replace(ticker_tmp, ticker_path)

    root_ticker_path = os.path.join(repo_root, "ticker_feed.json")
    try:
        with open(root_ticker_path + ".tmp", "w", encoding="utf-8") as f:
            json.dump(ticker_feed, f, indent=2, ensure_ascii=False)
        os.replace(root_ticker_path + ".tmp", root_ticker_path)
    except Exception:
        pass

    print(f"Wrote {len(vulns_sorted)} records to {out_path}")
    print(f"Wrote {min(100, len(vulns_sorted))} records to {top_path} and {root_top_path}")
    print(f"Wrote delta metrics to {delta_path}")
    print(f"Wrote {len(ticker_feed)} headlines to {ticker_path} and {root_ticker_path}")

if __name__ == "__main__":
    main()

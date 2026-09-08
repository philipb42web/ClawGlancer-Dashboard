
import os
import re
import sys
import json
import time
import requests
from datetime import datetime, timezone, timedelta


PROD_PATH = "/opt/clawglancer/public/data"
DEV_PATH = "/home/northstar/src/ClawGlancer/workspace/data"

if os.path.exists(PROD_PATH) and os.access(PROD_PATH, os.W_OK):
    DATA_DIR = PROD_PATH
else:
    DATA_DIR = DEV_PATH

os.makedirs(DATA_DIR, exist_ok=True)


KILLCHAIN_PATTERNS = {
    
    "ai_infrastructure": [
        r"\bllm\b", r"\bprompt injection\b", r"\bpytorch\b", r"\btorch\.load\b", 
        r"\bhugging\s?face\b", r"\bmodel weights\b", r"\bvector database\b", 
        r"\bpinecone\b", r"\bmilvus\b", r"\bqdrant\b", r"\bchromadb\b", 
        r"\bollama\b", r"\bvllm\b", r"\blangchain\b", r"\bllamaindex\b", 
        r"\bcomfyui\b", r"\bmlflow\b", r"\bkubeflow\b", r"\bflowise\b"
    ],
    
    "edge_perimeter": [
        r"\bvpn\b", r"\bfirewall\b", r"\bgateway\b", r"\bedge appliance\b", 
        r"\bperimeter\b", r"\bivanti\b", r"\bpalo alto\b", r"\bfortinet\b", 
        r"\bsonicwall\b", r"\bcitrix\b", r"\bnetscaler\b", r"\bcheckpoint\b"
    ],
   
    "supply_chain": [
        r"\bsupply chain\b", r"\bci/cd\b", r"\bgithub action\b", r"\bpypi\b", 
        r"\bmalicious package\b", r"\bdependency confusion\b", r"\bnpm package\b"
    ],
   
    "rce": [r"\bremote code execution\b", r"\brce\b", r"\bcode execution\b", r"\barbitrary code\b"],
    "auth_bypass": [r"\bauthentication bypass\b", r"\bauthorization bypass\b", r"\blogin bypass\b"],
    "priv_esc": [r"\bprivilege escalation\b", r"\beop\b", r"\bprivesc\b"],
    "deserialization": [r"\bdeserialization\b", r"\bgadget chain\b", r"\bpickle\b"],
    "command_injection": [r"\bcommand injection\b", r"\bos command\b", r"\barbitrary command\b"],
    "sqli": [r"\bsql injection\b", r"\bsqli\b"],
    "ssrf": [r"\bssrf\b", r"\bserver-side request forgery\b"],
    "path_traversal": [r"\bpath traversal\b", r"\bdirectory traversal\b"],
    "file_write": [r"\barbitrary file\b", r"\bfile write\b"],
    "xss": [r"\bxss\b", r"\bcross-site scripting\b"],
    "dos": [r"\bdenial of service\b", r"\bdos\b"],
    "wormable": [r"\bwormable\b"],
    "in_the_wild": [r"\bin the wild\b", r"\bactively exploited\b", r"\bexploited in the wild\b", r"\bkev\b"],
    "poc": [r"\bpoc\b", r"\bproof of concept\b", r"\bexploit code\b", r"\bmetasploit\b", r"\bweaponized\b"]
}

# Intelligence Multipliers
TAG_WEIGHTS = {
    "in_the_wild": 40,         # Actively exploited in target landscape
    "ai_infrastructure": 35,   # High-priority AI vulnerability signals
    "edge_perimeter": 35,      # Edge device vulnerabilities
    "supply_chain": 30,        
    "rce": 30,
    "auth_bypass": 25,
    "priv_esc": 25,
    "deserialization": 20,
    "poc": 20,
    "command_injection": 18,
    "sqli": 18,
    "ssrf": 18,
    "path_traversal": 15,
    "file_write": 15,
    "wormable": 25,
    "xss": 8,
    "dos": 3
}

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ThreatIntelEngine/3.0"
TIMEOUT = 12
MAX_RETRIES = 3
BACKOFF_DELAYS = [1, 2, 4]
HEADERS = {"User-Agent": USER_AGENT}

OUTPUT_KEYS = [
    "cve_id", "published", "last_modified", "cvss_v3",
    "severity", "affected", "summary", "references", "source"
]

RECENT_WINDOW = timedelta(hours=168) # Expanded to 7 days for more reliable trend analysis

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
        return "UNKNOWN"
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
    normalized["affected"] = []

    if source == "NVD":
        wrapper = threat_obj if isinstance(threat_obj, dict) else {}
        cve = wrapper.get("cve", {}) if isinstance(wrapper.get("cve", {}), dict) else {}

        normalized["cve_id"] = cve.get("id") or wrapper.get("id")
        normalized["published"] = cve.get("published") or wrapper.get("published")
        normalized["last_modified"] = cve.get("lastModified") or wrapper.get("last_modified")

        score = None
        metrics = cve.get("metrics", {}) if isinstance(cve.get("metrics", {}), dict) else {}
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV3"):
            arr = metrics.get(key)
            if isinstance(arr, list) and arr:
                cvss_data = arr[0].get("cvssData", {}) if isinstance(arr[0], dict) else {}
                score = cvss_data.get("baseScore")
                if score is not None:
                    break

        normalized["cvss_v3"] = score
        normalized["severity"] = _cvss_severity(score)

        descs = cve.get("descriptions")
        if isinstance(descs, list) and descs:
            en = next((d for d in descs if isinstance(d, dict) and d.get("lang") == "en"), None)
            normalized["summary"] = (en or descs[0]).get("value") if isinstance((en or descs[0]), dict) else None

        refs = cve.get("references") or []
        normalized["references"] = [r.get("url") for r in refs if isinstance(r, dict) and r.get("url")]

        configs = wrapper.get("configurations", [])
        all_nodes = []
        if isinstance(configs, dict):
            all_nodes = configs.get("nodes", []) or []
        elif isinstance(configs, list):
            for cfg in configs:
                if isinstance(cfg, dict):
                    all_nodes.extend(cfg.get("nodes", []) or [])

        cpe_uris = _extract_cpes_from_nodes(all_nodes)
        normalized["affected"] = _parse_affected_from_cpes(cpe_uris)

    return normalized

def dedupe_and_filter(vulns):
    unique = {}
    for v in vulns:
        cid = v.get("cve_id")
        if not cid:
            continue
        if cid not in unique:
            unique[cid] = v
    return list(unique.values())

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
        vulns.append(normalize_threat(item, "NVD"))
    return vulns

def classify_and_score(v):
    text_parts = []
    if v.get("summary"):
        text_parts.append(v["summary"])
    if v.get("references"):
        text_parts.append(" ".join(v["references"]))
    text = " ".join(text_parts).lower()

    tags = []
    reasons = []

    # CVSS Base Multiplier
    cvss = v.get("cvss_v3")
    score = float(cvss) * 5.0 if cvss is not None else 25.0  # Safe default if score not assigned yet

    if is_recent(v.get("last_modified")):
        score += 10
        reasons.append("recently modified (last 48h)")

    # Run Compiled Heuristic Rules
    for tag, patterns in KILLCHAIN_PATTERNS.items():
        for pat in patterns:
            if re.search(pat, text):
                tags.append(tag)
                w = TAG_WEIGHTS.get(tag, 0)
                score += w
                reasons.append(f"{tag}+{w}")
                break

    v["tags"] = sorted(set(tags))
    v["intel_score"] = round(score, 2)
    v["reasons"] = reasons[:12]
    return v

def main():
    print(f"Directory active: {DATA_DIR}")
    
    vulns = fetch_nvd_data()
    if not vulns:
        print("[SYSTEM FAULT] NVD API query returned no results. Retaining cache stability.")
        return

    vulns = dedupe_and_filter(vulns)
    
    # Process and rank entries
    scored_vulns = [classify_and_score(v) for v in vulns]
    
    # FILTER: Keep high severity CVEs OR those matching critical intelligence categories (such as AI)
    filtered_vulns = []
    for v in scored_vulns:
        if (v.get("cvss_v3") and v["cvss_v3"] >= 7.0) or len(v.get("tags", [])) > 0:
            filtered_vulns.append(v)
            
    vulns_sorted = sorted(filtered_vulns, key=lambda x: x.get("intel_score", 0.0), reverse=True)

    # Output Paths
    out_path = os.path.join(DATA_DIR, "critical_threats.json")
    top_path = os.path.join(DATA_DIR, "prioritized_threats.json")
    meta_path = os.path.join(DATA_DIR, "meta.json")

    # Atomic write operations
    def atomic_write(filepath, data):
        tmp_path = filepath + ".tmp"
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        os.replace(tmp_path, filepath)

    # Slice output precisely to 100 for your UI table requirements
    top_100 = vulns_sorted[:100]

    atomic_write(out_path, vulns_sorted)
    atomic_write(top_path, top_100)

    meta = {
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "count_total": len(vulns_sorted),
        "count_top": len(top_100),
    }
    atomic_write(meta_path, meta)

    print(f"Success. Generated meta update: {meta['generated_at']}")
    print(f"Total: {meta['count_total']} threats | Front-End Delivery Feed size: {meta['count_top']}")

if __name__ == "__main__":
    main()
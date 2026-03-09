import os
import requests
import time
import json
from datetime import datetime, timedelta


KILLCHAIN_PATTERNS = {
    "rce": [r"\bremote code execution\b", r"\brce\b", r"\bcode execution\b", r"\barbitrary code\b"],
    "auth_bypass": [r"\bauthentication bypass\b", r"\bauthorization bypass\b", r"\blogin bypass\b"],
    "priv_esc": [r"\bprivilege escalation\b", r"\beop\b", r"\bprivesc\b"],
    "deserialization": [r"\bdeserialization\b", r"\bgadget chain\b"],
    "command_injection": [r"\bcommand injection\b", r"\bos command\b", r"\barbitrary command\b"],
    "sqli": [r"\bsql injection\b", r"\bsqli\b"],
    "ssrf": [r"\bssrf\b", r"\bserver-side request forgery\b"],
    "path_traversal": [r"\bpath traversal\b", r"\bdirectory traversal\b"],
    "file_write": [r"\barbitrary file\b", r"\bfile write\b"],
    "xss": [r"\bxss\b", r"\bcross-site scripting\b"],
    "dos": [r"\bdenial of service\b", r"\bdos\b"],
    "wormable": [r"\bwormable\b"],
    "in_the_wild": [r"\bin the wild\b", r"\bactively exploited\b", r"\bexploited in the wild\b"],
    "poc": [r"\bpoc\b", r"\bproof of concept\b", r"\bexploit code\b", r"\bmetasploit\b", r"\bweaponized\b"]
}

TAG_WEIGHTS = {
    "rce": 30,
    "auth_bypass": 25,
    "priv_esc": 25,
    "deserialization": 20,
    "command_injection": 18,
    "sqli": 18,
    "ssrf": 18,
    "path_traversal": 15,
    "file_write": 15,
    "wormable": 25,
    "in_the_wild": 35,
    "poc": 20,
    "xss": 8,
    "dos": 3
}


USER_AGENT = "Mozilla/5.0"
TIMEOUT = 10
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
    "source"
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

from datetime import timezone

def is_recent(date_str):
    if not date_str:
        return False
    try:
        s = date_str.strip()

        # NVD sometimes returns timestamps without timezone.
        # If it's missing, assume UTC.
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
    return None

def _extract_cpes_from_nodes(nodes):
    """
    NVD configurations nodes may contain:
      - 'cpeMatch' (newer) or 'cpe_match' (older)
      - nested 'children' nodes
    """
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

        normalized["cvss_v3"] = score
        normalized["severity"] = _cvss_severity(score)

        # Summary/description
        descs = cve.get("descriptions")
        if isinstance(descs, list) and descs:
            # prefer English if present
            en = next((d for d in descs if isinstance(d, dict) and d.get("lang") == "en"), None)
            normalized["summary"] = (en or descs[0]).get("value") if isinstance((en or descs[0]), dict) else None
        else:
            # older format
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
            # older format
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
        # Unknown source format
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


def classify_and_score(v):
    """
    Adds:
      - tags: list[str]
      - intel_score: float
      - reasons: list[str] (explainable)
    """
    import re

    text_parts = []
    if v.get("summary"):
        text_parts.append(v["summary"])
    if v.get("references"):
        text_parts.append(" ".join(v["references"]))
    text = " ".join(text_parts).lower()

    tags = []
    reasons = []

    # base score from CVSS
    cvss = v.get("cvss_v3") or 0.0
    score = float(cvss) * 5.0  # 0..50

    # freshness boost (sleeping monster “woke up”)
    if is_recent(v.get("last_modified")):
        score += 10
        reasons.append("recently modified (last 48h)")

    # keyword tags
    for tag, patterns in KILLCHAIN_PATTERNS.items():
        for pat in patterns:
            if re.search(pat, text):
                tags.append(tag)
                w = TAG_WEIGHTS.get(tag, 0)
                score += w
                reasons.append(f"{tag}+{w}")
                break

    # clamp / normalize
    v["tags"] = sorted(set(tags))
    v["intel_score"] = round(score, 2)
    v["reasons"] = reasons[:12]
    return v

def main():
    vulns = fetch_nvd_data()
    vulns = dedupe_and_filter(vulns)

    vulns = [classify_and_score(v) for v in vulns]
    vulns_sorted = sorted(vulns, key=lambda x: x.get("intel_score", 0.0), reverse=True)

    
    data_dir = "/opt/clawglancer/public/data"
    os.makedirs(data_dir, exist_ok=True)

    out_path = f"{data_dir}/critical_threats.json"
    tmp_path = out_path + ".tmp"
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(vulns_sorted, f, indent=2, ensure_ascii=False)
    os.replace(tmp_path, out_path)

    top_path = f"{data_dir}/prioritized_threats.json"
    top_tmp = top_path + ".tmp"
    with open(top_tmp, "w", encoding="utf-8") as f:
        json.dump(vulns_sorted[:100], f, indent=2, ensure_ascii=False)
    os.replace(top_tmp, top_path)

    meta_path = f"{data_dir}/meta.json"
    meta_tmp = meta_path + ".tmp"
    meta = {
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00","Z"),
        "count_total": len(vulns_sorted),
        "count_top": min(100, len(vulns_sorted)),
    }
    with open(meta_tmp, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2, ensure_ascii=False)
    os.replace(meta_tmp, meta_path)

    print(f"Wrote {len(vulns_sorted)} records to {out_path}")
    print(f"Wrote {min(100, len(vulns_sorted))} records to {top_path}")

if __name__ == "__main__":
    main()






  ##demo - https://clawglancer.dev
  
 
 Claw 🦞 Glancer - dashboard:

is a VPS hosted CVE fetching pipeline that displays recently modified CVEs. 
The dashboard displays semantic kill-chain tags with a custom (signals based) scoring model.
It generates JSON artifacts from filtered records (API) & represents them on a dashboard.

Objective: 

fast overview of what is critical now (with min attack surface).

Design goal:

- pull recent CVE records from NVD
- filter for higher-signal incidents
- generate an hourly Telegram alert summary

_____________________________________________________________________________

Overview


1.   Fetcher (Python):
   - File: `workspace/fetch_intel.py`
   - Role:
     - Pull CVE records from NVD (API call with last-modified scope)
     - Normalization to strict schema
     - Filtering (recent + CVSS >= 7)
     - Application of semantic tags & `intel_score` with `reasons`
     - Write output JSON files (atomically)

2.   Dashboard:
   - File: `workspace/dashboard.html`
   - Role:
     - Read `prioritized_threats.json` (same directory)
     - Provide search / filters / refresh
     - no critical backend requirements

3.   Runtime:
   - Files: `Dockerfile`, `docker-compose.yml`
   - Role:
     - Provide structured execution environment for pipeline 
     - git gateway
    
4.   Data:
     - Array - `workspace/critical_threats.json` :
     - CVE records (recent, high severity)

      Examples (approx. top 100):
      - `cve_id`
      - `published`
      - `last_modified`
      - `cvss_v3`
      - `severity`
      - `summary`
      - `references`
  
5.   Stack:
    - Python
    - JavaScript
    - Docker
    - VPS
    - API (AI & Telegram)
      - `source`


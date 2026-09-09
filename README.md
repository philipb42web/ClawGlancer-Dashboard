*** Claw 🦞 Glancer ***

Is a Live Dashboard: [https://clawglancer.dev](https://clawglancer.dev)

Acting as an automated, serverless threat intelligence aggregator & scoring engine. It continuously tracks newly published and modified high-severity CVEs, cross-references them against active in-the-wild exploitation catalogs, enriches them with predictive exploit modeling, and rolls breaking cybersecurity advisories in real time.

---

# Core functions

* **Multi-Source Intelligence**:
  * **NIST NVD (API v2.0)**: Ingests newly published and modified CVEs across rolling 72-hour windows.
  * **CISA KEV Catalog**: Cross-references 1,700+ confirmed actively exploited vulnerabilities with instant prioritization.
  * **FIRST.org EPSS**: Enriches threats with machine-learning exploit prediction probabilities (0–100%) and percentiles.
* **Rolling Cyber Intel Marquee**:
  * Sticky real-time news ticker streaming latest dispatches from **SANS Internet Storm Center (ISC)**, **CISA Cybersecurity Alerts**, and **BleepingComputer / DFIR**.
  * Interactive pause-on-hover with direct links to vendor advisories.
* **Explainable Threat Scoring**:
  * Calculates an `intel_score` combining base CVSS, a 48h freshness boost, keyword killchain heuristics (`rce`, `auth_bypass`, `priv_esc`, `poc`), CISA KEV confirmation (+40), and high EPSS probability (+25).
* **Zero-Cost & Serverless**:
  * Runs on a cron via **GitHub Actions**; hosted globally with zero server overhead via **GitHub Pages**.

---


* Python (Scraper & Heuristics)
* JavaScript / HTML5 / CSS 
* GitHub Actions/Pages



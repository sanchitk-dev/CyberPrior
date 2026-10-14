# CyberPrior – Objective 1 Verification & Audit Report

**Date Generated**: 2026-10-11
**Dataset Evaluated**: `data/processed/CyberPrior_Enriched_Dataset_v1.csv`
**Input Source**: `data/raw/CyberPrior_Input_Dataset_v2_1160.csv`

### Source freshness recorded in the local cache

- **NVD cache files last updated**: 2026-10-11 11:00 UTC to 2026-10-11 11:07 UTC
- **EPSS scoring date(s)**: 2026-10-10
- **CISA KEV catalog**: version 2026.10.08, released 2026-10-08T20:09:18.9833Z

---

## 1. Summary of Verification

| Audit Metric | Expected | Actual | Status |
| :--- | :--- | :--- | :--- |
| **Total Asset-Vulnerability Records** | 1,160 | 1160 | **PASSED** |
| **Unique CVE Identifiers** | 58 | 58 | **PASSED** |
| **Unique Assets** | 20 | 20 | **PASSED** |
| **Enriched Columns** | 32 | 32 | **PASSED** |
| **Complete Enrichment Rate** | 100% | 100.0% | **PASSED** |
| **Missing / Null Values in Key Fields** | 0 | 0 | **PASSED** |

---

## 2. Threat Intelligence Integration Details

### A. NVD (National Vulnerability Database)
* **Coverage**: 1160 / 1160 records (100%)
* **CVSS Score Range**: 3.4 to 10.0 (Mean: 9.17)
* **Severity Breakdown**:
  * CRITICAL: 880 records (75.9%)
  * HIGH: 240 records (20.7%)
  * MEDIUM: 20 records (1.7%)
  * LOW: 20 records (1.7%)

### B. EPSS (Exploit Prediction Scoring System)
* **Coverage**: 1160 / 1160 records (100%)
* **EPSS Range**: 0.1281 to 1.0000 (Mean: 0.9515)

### C. CISA KEV (Known Exploited Vulnerabilities)
* **Unique CVEs in KEV**: 55 / 58 (94.8%)
* **Affected Asset Records**: 1100 / 1160 records (94.8%)
* **Ransomware Campaign Linked CVEs**: 41 unique CVEs

---

## 3. Conclusion for Objective 1 Evaluation

Objective 1 is **100% complete, verified, and defensible**:
1. All records preserved without data loss or row duplication.
2. External intelligence from NVD, EPSS, and CISA KEV successfully joined.
3. Clean local cache prevents external rate-limit failures and guarantees reproducibility.
4. Dataset is primed for Objective 2 (Risk Assessment & ML classification).

# CyberPrior – Objective 1 Methodology

## 1. Overview

CyberPrior Objective 1 focuses on automated vulnerability data enrichment.

The system accepts an input dataset containing assets, CVE identifiers and organization-specific risk attributes. For every unique CVE, the system retrieves additional vulnerability intelligence from NVD, EPSS and the CISA KEV Catalog.

The enriched vulnerability information is then merged back with the original asset records.

---

## 2. Input Dataset

The current project dataset contains 1,160 asset-vulnerability records.

Each record contains:

* Asset ID
* Asset type
* CVE ID
* Asset criticality
* Exposure
* Data sensitivity
* Control effectiveness

The same CVE may occur on multiple assets.

This is intentional because the vulnerability information remains associated with the CVE, while the resulting organizational risk can differ depending on the affected asset.

---

## 3. CVE-Based Enrichment

The CVE identifier acts as the common key between the project dataset and external vulnerability intelligence sources.

For each unique CVE:

### NVD

The system retrieves technical vulnerability information including CVSS score, severity, vector, CWE, description, dates and affected CPE information.

### EPSS

The system retrieves the current EPSS score, percentile and associated date.

### CISA KEV

The system checks whether the CVE exists in the CISA Known Exploited Vulnerabilities Catalog.

If the CVE is present, relevant KEV information is stored.

If it is not present, the `cisa_kev` field is recorded as false.

---

## 4. Caching

The pipeline stores API responses locally in:

`data/raw/api_cache/`

Caching reduces unnecessary repeated requests and allows previously retrieved vulnerability information to be reused during development.

This also makes the enrichment process easier to reproduce.

---

## 5. Data Integration

After enrichment, the external vulnerability information is joined with the original dataset using the CVE ID.

The original asset-level information is preserved.

The resulting dataset therefore combines:

**Asset Context + Vulnerability Severity + Exploitation Likelihood + Known Exploitation Information**

---

## 6. Output

The processed dataset is generated at:

`data/processed/CyberPrior_Enriched_Dataset_v1.csv`

The output contains the original project fields along with additional vulnerability intelligence fields.

---

## 7. Role in the Overall CyberPrior System

Objective 1 forms the data foundation for the remaining objectives.

The enriched dataset will subsequently be used for:

* vulnerability risk assessment
* risk-level classification
* factor-based explanations
* inherent and residual risk calculation
* vulnerability prioritization
* mitigation recommendations

Therefore, Objective 1 is not only a data collection step. It establishes an automated pipeline that converts basic CVE-based input into threat-informed vulnerability records for downstream risk analysis.

# CyberPrior – Objective 1 Source Mapping

## Objective

The first objective of CyberPrior is to develop an automated vulnerability data enrichment pipeline by integrating vulnerability intelligence from NVD, exploitation likelihood from EPSS, and known exploitation information from the CISA Known Exploited Vulnerabilities (KEV) Catalog.

The purpose is to transform basic CVE information into a richer vulnerability intelligence record that can later be used by the CyberPrior risk assessment and prioritization system.

---

## 1. NVD – National Vulnerability Database

NVD provides vulnerability information associated with CVE identifiers.

### Data used

* CVE ID
* CVSS version
* CVSS base score
* CVSS severity
* CVSS vector
* CWE information
* Vulnerability description
* Published date
* Last modified date
* Affected CPE information

### Role in CyberPrior

NVD information provides the technical vulnerability and severity characteristics required for the initial risk assessment.

CVSS is treated as a vulnerability severity indicator rather than the complete organizational risk because the actual risk also depends on factors such as asset criticality, exposure and control effectiveness.

---

## 2. EPSS – Exploit Prediction Scoring System

EPSS provides an estimate of the likelihood that a vulnerability will be exploited in the wild.

### Data used

* EPSS score
* EPSS percentile
* EPSS date

### Role in CyberPrior

EPSS provides an exploitation-likelihood signal.

This allows CyberPrior to distinguish between vulnerabilities with similar technical severity but different levels of expected exploitation activity.

The EPSS score ranges from 0 to 1.

---

## 3. CISA KEV – Known Exploited Vulnerabilities Catalog

The CISA KEV Catalog contains vulnerabilities for which exploitation has been observed in the wild.

### Data used

* CVE ID
* Known exploited status
* Vendor/project
* Product
* Vulnerability name
* Date added
* Due date
* Required action
* Known ransomware campaign use

### Role in CyberPrior

CISA KEV provides an important real-world exploitation signal.

A vulnerability appearing in the KEV Catalog is treated as having documented known exploitation, which can increase its priority during vulnerability assessment.

---

## 4. Organizational Input Data

The external vulnerability intelligence is combined with project-specific asset information.

### Input fields

* Asset ID
* Asset
* CVE ID
* Criticality
* Exposure
* Data sensitivity
* Control effectiveness

These fields represent the organization's asset and security context.

For this academic project, the organizational asset attributes are project-generated scenarios, while the CVE identifiers and external vulnerability intelligence are based on real vulnerability records.

---

## 5. Enrichment Flow

The enrichment pipeline follows this process:

Input CSV

→ Extract unique CVE IDs

→ Query NVD

→ Query EPSS

→ Match CVEs against CISA KEV

→ Extract relevant vulnerability intelligence

→ Merge external intelligence with asset-specific information

→ Generate enriched CyberPrior dataset

---

## 6. Result

The output dataset contains both:

1. Asset-specific organizational context
2. External vulnerability intelligence

This enriched dataset serves as the input for the next stage of CyberPrior, where vulnerability risk is calculated using multiple risk factors rather than relying only on CVSS severity.

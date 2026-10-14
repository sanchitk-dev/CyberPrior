# CyberPrior – Objective 2 Methodology: Risk Assessment, Prioritization & Machine Learning

## 1. Executive Summary

CyberPrior Objective 2 bridges external threat intelligence (NVD, EPSS, CISA KEV) with internal organizational context to solve the core limitation of modern vulnerability management: **CVSS score alone does not represent real business risk**.

Objective 2 accomplishes this through:
1. **Quantitative Risk Formulation**: Calculating NIST SP 800-30 aligned Inherent and Residual Risk.
2. **Prioritization Index & Ranking**: Continuous scoring (0-100) and strict ordering from Rank #1 to #1,160.
3. **Actionable Remediation Classification**: Explicit mitigation action categories (`Patch Vulnerability`, `Network Segmentation`, `Enable MFA & Access Restriction`, `Apply Compensating Controls`).
4. **Remediation SLAs**: Automated operational response windows (P1 to P4).
5. **Multi-Model Machine Learning Benchmark**: Logistic Regression, Decision Tree, and Random Forest.
6. **Dual Explainability**: Business-readable factor narratives + SHAP game-theoretic feature attribution.

---

## 2. Mathematical Risk Formulation (NIST SP 800-30 Aligned)

In cybersecurity risk engineering, risk is evaluated as:

$$\text{Risk} = \text{Threat Likelihood} \times \text{Asset Impact} \times (1 - \text{Control Credit})$$

### A. Threat & Exploitability Factor ($T \in [0, 1]$)
Combines technical vulnerability severity, empirical exploitation probability, and active threat weaponization:

$$T = 0.40 \times \left(\frac{\text{CVSS}}{10}\right) + 0.30 \times \text{EPSS} + 0.30 \times \text{CISA\_KEV}$$

* **CVSS (0.0 to 10.0)**: Normalized to $[0, 1]$ representing baseline flaw severity.
* **EPSS (0.0 to 1.0)**: Statistical probability of exploitation in the next 30 days.
* **CISA KEV (0 or 1)**: Empirical confirmation of active weaponization in the wild.

For this dataset, the enriched CSV has no missing CVSS or EPSS scores, and every row records an NVD/EPSS source. The engine still uses explicit fallbacks for future incomplete inputs: CVSS defaults to 5.0 and EPSS to 0.0. `nvd_cvss_fallback_used` and `epss_fallback_used` in the assessed output identify those records; these are assumptions, not external intelligence values. Current fallback counts are zero for both fields.

### B. Asset Impact Factor ($I \in [0, 1]$)
Captures organizational consequence if the asset is compromised:

$$I = 0.40 \times \text{Criticality} + 0.30 \times \text{Exposure} + 0.30 \times \text{Data Sensitivity}$$

Mapped ordinals:
* **Asset Criticality**: Low = 0.25, Medium = 0.50, High = 0.75, Critical = 1.00
* **Network Exposure**: Internal = 0.40, External = 1.00
* **Data Sensitivity**: Low = 0.25, Medium = 0.50, High = 0.75, Critical = 1.00

### C. Inherent vs. Residual Risk
* **Inherent Risk** (Raw exposure before defenses):
  $$R_{\text{inherent}} = T \times I \times 100$$
* **Residual Risk** (Operational exposure remaining after controls):
  $$R_{\text{residual}} = R_{\text{inherent}} \times (1 - \text{Control Mitigation Credit})$$
  * Low Controls: 15% reduction credit
  * Medium Controls: 40% reduction credit
  * High Controls: 70% reduction credit

Risk tiers use the residual (and inherent) score on a 0–100 scale: **Low < 25; Moderate 25–<50; High 50–<70; Critical ≥70**.

---

## 3. Intelligent Prioritization Engine & Action Matrix

A security team cannot fix 1,160 vulnerabilities simultaneously. CyberPrior assigns a continuous **Priority Score** to strictly rank tickets:

$$\text{Priority Score} = 0.50 \times R_{\text{residual}} + 0.25 \times (\text{EPSS} \times 100) + 0.15 \times (\text{KEV} \times 100) + 0.10 \times (\text{Exposure} \times 100)$$

EPSS and KEV already affect residual risk, so their additional terms are intentional urgency adjustments: residual risk represents overall risk after controls, while the priority score adds weight for active exploitation indicators. The score is capped only by its formula's component ranges (0–100); no extra normalization is applied.

### A. Priority Rank & Remediation SLAs
Records are sorted by priority score (descending), then CVSS and EPSS (descending), and assigned a unique 1-based rank. SLA is selected from residual risk level: Critical = P1 (24–48 hours), High = P2 (7–14 days), Moderate = P3 (30 days), Low = P4 (90 days / next maintenance window). Rank intervals are not hardcoded to risk tiers.

### B. Targeted Mitigation Action Categories
1. **Enable MFA & Access Restriction**: External assets whose project asset names contain gateway, portal, VPN, firewall, or web.
2. **Network Segmentation**: High/critical internal assets whose project asset names contain database, controller, finance, backup, or HR.
3. **Apply Compensating Controls (WAF / IPS / Virtual Patch)**: Active in CISA KEV where controls are currently weak.
4. **Patch Vulnerability**: Default vendor software updates.

These are rules over the project's synthetic `asset` categories and exposure/criticality fields, not a universal enterprise asset ontology. New asset names that do not match these keywords fall through to other rules or the default patch action.

---

## 4. Machine Learning & SHAP Explainability

The target, `residual_risk_level`, is generated by the CyberPrior risk framework from the same underlying features. The ML models learn and automate these project risk-framework labels. The rule-based risk engine is the interpretable foundation; the ML models provide automated classification and comparison. They are not independently validated against real organizational incidents and do not independently discover real-world cyber risk.

Two evaluations are used: a stratified random 80/20 split (seed 42) as a baseline, and a single `GroupShuffleSplit` holdout (test size 0.20, seed 42) grouped by `cve_id`. Entire CVEs stay together in the latter, making it the more meaningful check for previously unseen CVEs. Preprocessing is fitted on training rows only; ordinal encodings are used for ordered asset categories, binary encodings for exposure/KEV, and `StandardScaler` is fitted on training features for Logistic Regression only. The seven features are CVSS score, EPSS score, KEV, criticality, exposure, data sensitivity, and control effectiveness.

Model settings: Logistic Regression (`max_iter=1000`, balanced class weights); Decision Tree (`max_depth=5`, `min_samples_split=4`); Random Forest (`n_estimators=100`, `max_depth=6`, `min_samples_split=4`); all model random states are 42. Evaluation reports accuracy, macro precision/recall/F1, weighted F1, and confusion matrices. See `objective2_ml_evaluation_report.md` for metrics calculated from the current dataset.

### SHAP Game-Theoretic Feature Attribution
Using `shap.TreeExplainer`, CyberPrior reports feature attribution relative to the predicted class. A positive SHAP value supports that class; when the predicted class is Low, it does not mean risk increased. SHAP explains the model's class prediction, not the underlying rule-engine score directly.

---

## 5. Visual Artifacts (Saved in `docs/figures/`)

* `fig1_inherent_vs_residual.png`: Quantitative proof of risk reduction via defensive controls.
* `fig2_model_confusion_matrices.png`: Side-by-side multi-class confusion matrix heatmaps.
* `fig3_feature_importance.png`: Feature importance bar ranking.
* `fig3_shap_summary.png`: Multi-class SHAP summary attribution plot.
* `fig4_threat_vs_impact_matrix.png`: Threat Likelihood vs. Impact Priority scatter plot.

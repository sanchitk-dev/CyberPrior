# CyberPrior – Objective 2 Machine Learning Evaluation Report

**Evaluation Task**: Multi-class Vulnerability Residual Risk Classification (`Low`, `Moderate`, `High`, `Critical`)  
**Report generated**: 2026-10-11  
**Dataset**: `data/processed/CyberPrior_Risk_Assessed_Dataset_v1.csv` (1,160 records)  
**Split Protocol**: Stratified 80% Train (928 records) / 20% Test (232 records), `random_state=42`  
**Features Evaluated (7)**: `cvss_score`, `epss_score`, `cisa_kev`, `criticality`, `exposure`, `data_sensitivity`, `control_effectiveness`  
**What is being evaluated**: CyberPrior's rule-based risk engine assigns each record a residual risk label using the listed factors. The ML models are trained on those same factors to reproduce those labels. This evaluates consistency with the project framework; it does not validate predictions against real incidents or independently discover real-world risk.

**What is a CVE?** CVE means *Common Vulnerabilities and Exposures*. A CVE ID is a public identifier assigned to a disclosed cybersecurity vulnerability, such as `CVE-2024-3400`. The same CVE can appear in multiple rows because it may affect several assets. The CVE-grouped evaluation keeps all rows for a CVE together to check whether a model can reproduce the project's labels for vulnerabilities it did not see during training.

The source refresh date and cached EPSS/KEV dates are recorded in `docs/objective1_verification_report.md`.

Risk formula: `T = 0.40 × (CVSS/10) + 0.30 × EPSS + 0.30 × KEV`; `I = 0.40 × criticality + 0.30 × exposure + 0.30 × data sensitivity`; inherent risk = `T × I × 100`; residual risk = `inherent risk × (1 − control credit)`. Tiers: Low < 25, Moderate 25–<50, High 50–<70, Critical ≥70. Missing CVSS/EPSS use fallback values 5.0/0.0, with explicit flags in assessed output; current dataset fallback counts are CVSS=0, EPSS=0.

Preprocessing maps ordered asset categories to ordinal values and exposure/KEV to binary values. `StandardScaler` is fitted on training data and used for Logistic Regression only; tree models use the unscaled encoded features. Model settings: Logistic Regression (`max_iter=1000`, `class_weight='balanced'`), Decision Tree (`max_depth=5`, `min_samples_split=4`), Random Forest (`n_estimators=100`, `max_depth=6`, `min_samples_split=4`); model seeds are 42.

### How to read the comparison metrics

- **Accuracy**: share of test records assigned the correct risk class.
- **Precision**: when the model predicts a particular risk class, how often that prediction is correct.
- **Recall**: of the records that truly belong to a risk class, how many the model identifies.
- **F1**: a combined score that balances precision and recall.
- **Equal-class average** (often called *macro average*): calculate a metric separately for Low, Moderate, High, and Critical, then give each class equal weight. This makes rare classes count as much as common ones.
- **Class-frequency weighted F1**: average each class's F1 while giving more weight to classes with more test records.

Precision, recall, and F1 are proportions from 0 to 1; accuracy is shown as a percentage. Higher is better, but the class-level trade-offs should also be considered. In the detailed classification reports below, `macro avg` means equal-class average and `weighted avg` means class-frequency weighted average.

---

## 1. Comparative Model Performance

| Algorithm | Correct overall | Precision | Recall | Average F1 | Weighted F1 |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Logistic Regression** | 93.53% | 0.8563 | 0.9494 | 0.8902 | 0.9371 |
| **Decision Tree** | 85.78% | 0.7650 | 0.8654 | 0.7843 | 0.8604 |
| **Random Forest** | 89.66% | 0.9227 | 0.7076 | 0.7382 | 0.8896 |

### Evaluation 2: Performance on CVEs excluded from training

The second evaluation uses `GroupShuffleSplit(test_size=0.20, random_state=42)` with `cve_id` as the group. It produced 920 training rows across 46 CVEs and 240 test rows across 12 CVEs, with zero CVE overlap. A CVE (Common Vulnerabilities and Exposures) is a public identifier for a disclosed cybersecurity vulnerability, such as `CVE-2024-3400`. The same CVE can occur in multiple asset rows. Keeping all those rows on one side checks whether models reproduce project labels for vulnerabilities they did not see during training. Because groups have different row counts, the row split is approximate. This is one holdout from a limited number of CVEs and should be interpreted cautiously.

| Algorithm | Correct overall | Precision | Recall | Average F1 | Weighted F1 |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Logistic Regression** | 93.33% | 0.9476 | 0.9510 | 0.9490 | 0.9336 |
| **Decision Tree** | 87.92% | 0.8674 | 0.8232 | 0.8409 | 0.8797 |
| **Random Forest** | 87.50% | 0.6520 | 0.6389 | 0.6403 | 0.8631 |

The first split is the standard baseline: its test set contains records held back from training, but some CVEs and repeated synthetic asset scenarios can occur on both sides. The second split holds out whole CVEs and is the more relevant check for unseen vulnerabilities. These are two views of model performance, not two separate projects or model sets.

**Interpretation**: Logistic Regression leads the baseline weighted F1 (0.9371); compare the unseen-CVE class averages and individual-class results too. No model should be declared the winner on every metric. This comparison measures reproduction of project-generated labels, not real-world incident prediction.

---

## 2. Feature Importance Ranking (Random Forest)

| Rank | Feature | Importance Score | Percentage Contribution |
| :---: | :--- | :---: | :---: |
| 1 | `control_effectiveness` | 0.6071 | 60.71% |
| 2 | `criticality` | 0.1022 | 10.22% |
| 3 | `data_sensitivity` | 0.0794 | 7.94% |
| 4 | `exposure` | 0.0752 | 7.52% |
| 5 | `epss_score` | 0.0523 | 5.23% |
| 6 | `cisa_kev` | 0.0442 | 4.42% |
| 7 | `cvss_score` | 0.0396 | 3.96% |

### Key Takeaway for Viva
* Feature importance describes which inputs the Random Forest uses to reproduce the rule-generated labels; it is not evidence of real-world causal importance.

---

## 3. Detailed Classification Reports

### Logistic Regression
```text
              precision    recall  f1-score   support

         Low       0.97      0.96      0.96        89
    Moderate       0.96      0.92      0.94        97
        High       0.90      0.93      0.91        40
    Critical       0.60      1.00      0.75         6

    accuracy                           0.94       232
   macro avg       0.86      0.95      0.89       232
weighted avg       0.94      0.94      0.94       232

```

### Decision Tree
```text
              precision    recall  f1-score   support

         Low       0.92      0.91      0.92        89
    Moderate       0.87      0.88      0.87        97
        High       0.84      0.68      0.75        40
    Critical       0.43      1.00      0.60         6

    accuracy                           0.86       232
   macro avg       0.77      0.87      0.78       232
weighted avg       0.87      0.86      0.86       232

```

### Random Forest
```text
              precision    recall  f1-score   support

         Low       0.99      0.90      0.94        89
    Moderate       0.84      0.99      0.91        97
        High       0.86      0.78      0.82        40
    Critical       1.00      0.17      0.29         6

    accuracy                           0.90       232
   macro avg       0.92      0.71      0.74       232
weighted avg       0.91      0.90      0.89       232

```

---

## 4. Conclusion for Objective 2 Evaluation

1. All three approved algorithms were compared on the same stratified baseline split and the same CVE-grouped holdout. Preprocessing is fitted on each training partition only.
2. The risk labels are generated from the same features supplied to the models. These evaluations measure how well ML reproduces the CyberPrior framework labels, not real-world incident prediction or independent validation of organizational risk.
3. The stratified split uses seed 42, test size 0.20, and `StandardScaler` for Logistic Regression only. Model settings: Logistic Regression (`max_iter=1000`, `class_weight='balanced'`); Decision Tree (`max_depth=5`, `min_samples_split=4`); Random Forest (`n_estimators=100`, `max_depth=6`, `min_samples_split=4`); all use seed 42.
4. Scores use accuracy and macro precision, recall, and F1, plus weighted F1. CVE-grouped evaluation uses one `GroupShuffleSplit` holdout with `cve_id`, test size 0.20, and seed 42.
5. Serialized models and the scaler are stored in `models/` for later integration.

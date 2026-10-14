"""CyberPrior - Objective 2 Machine Learning Training & Evaluation Pipeline

Trains, evaluates, and compares three classification algorithms for risk prediction:
1. Logistic Regression (Multinomial baseline with standardized features)
2. Decision Tree Classifier (Interpretable rule boundaries)
3. Random Forest Classifier (Ensemble decision trees with feature importance)

Workflow:
  Enriched & Risk-Assessed Dataset
  ↓
  Extract 7 Raw Features (CVSS, EPSS, KEV, Criticality, Exposure, Sensitivity, Controls)
  ↓
  Stratified Train/Test Split (80% Train, 20% Test)
  ↓
  Train All 3 Classifiers
  ↓
  Evaluate Metrics (Accuracy, Precision, Recall, F1, Confusion Matrices)
  ↓
  Save Model Artifacts to models/
  ↓
  Export Objective 2 Evaluation Report
"""

import os
import sys
from datetime import date
from pathlib import Path
from typing import Any, Dict, Tuple

import joblib
import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    precision_recall_fscore_support,
)
from sklearn.model_selection import GroupShuffleSplit
from sklearn.preprocessing import StandardScaler

# Add src to path for local imports
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR / 'src'))

from preprocessing import prepare_ml_data, FEATURE_COLUMNS, extract_features
from risk_engine import compute_risk

DATA_FILE = BASE_DIR / 'data' / 'processed' / 'CyberPrior_Risk_Assessed_Dataset_v1.csv'
ENRICHED_FILE = BASE_DIR / 'data' / 'processed' / 'CyberPrior_Enriched_Dataset_v1.csv'
MODELS_DIR = BASE_DIR / 'models'
REPORT_FILE = BASE_DIR / 'docs' / 'objective2_ml_evaluation_report.md'

ORDERED_CLASSES = ['Low', 'Moderate', 'High', 'Critical']


def format_confusion_matrix(cm: np.ndarray, labels: list) -> str:
    """Format confusion matrix as aligned text table."""
    header = 'Pred -> ' + '  '.join(f'{lbl:>8}' for lbl in labels)
    lines = [header, '-' * len(header)]
    for i, row in enumerate(cm):
        row_str = f'{labels[i]:>7} ' + '  '.join(f'{val:>8}' for val in row)
        lines.append(row_str)
    return '\n'.join(lines)


def make_models() -> Dict[str, Any]:
    """Create fresh models with the documented, reproducible settings."""
    return {
        'Logistic Regression': LogisticRegression(max_iter=1000, random_state=42, class_weight='balanced'),
        'Decision Tree': DecisionTreeClassifier(max_depth=5, min_samples_split=4, random_state=42),
        'Random Forest': RandomForestClassifier(n_estimators=100, max_depth=6, min_samples_split=4, random_state=42),
    }


def evaluate_grouped_split(df: pd.DataFrame) -> Tuple[Dict[str, Dict[str, float]], Dict[str, int]]:
    """Hold out complete CVE groups and evaluate freshly fitted models."""
    X = extract_features(df)
    y = df['residual_risk_level'].astype(str)
    if 'cve_id' not in df or df['cve_id'].isna().any():
        raise ValueError('CVE-grouped evaluation requires a non-null cve_id for every record.')

    splitter = GroupShuffleSplit(n_splits=1, test_size=0.20, random_state=42)
    train_idx, test_idx = next(splitter.split(X, y, groups=df['cve_id']))
    X_train, X_test = X.iloc[train_idx], X.iloc[test_idx]
    y_train, y_test = y.iloc[train_idx], y.iloc[test_idx]
    scaler = StandardScaler().fit(X_train)
    results: Dict[str, Dict[str, float]] = {}

    for name, model in make_models().items():
        x_train = scaler.transform(X_train) if name == 'Logistic Regression' else X_train
        x_test = scaler.transform(X_test) if name == 'Logistic Regression' else X_test
        model.fit(x_train, y_train)
        predictions = model.predict(x_test)
        precision, recall, f1, _ = precision_recall_fscore_support(
            y_test, predictions, average='macro', zero_division=0
        )
        results[name] = {
            'accuracy': accuracy_score(y_test, predictions),
            'macro_precision': precision,
            'macro_recall': recall,
            'macro_f1': f1,
            'weighted_f1': precision_recall_fscore_support(
                y_test, predictions, average='weighted', zero_division=0
            )[2],
        }

    train_cves = set(df.iloc[train_idx]['cve_id'])
    test_cves = set(df.iloc[test_idx]['cve_id'])
    if train_cves & test_cves:
        raise AssertionError('CVE-grouped split unexpectedly overlaps CVEs.')
    print(f'\nCVE-grouped split: {len(train_idx)} train rows / {len(test_idx)} test rows; '
          f'{len(train_cves)} train CVEs / {len(test_cves)} test CVEs; zero CVE overlap.')
    split_info = {
        'train_rows': len(train_idx), 'test_rows': len(test_idx),
        'train_cves': len(train_cves), 'test_cves': len(test_cves),
    }
    return results, split_info


def train_and_evaluate() -> None:
    print('=' * 75)
    print('      CYBERPRIOR - OBJECTIVE 2 MACHINE LEARNING RISK MODEL TRAINING')
    print('=' * 75)

    # 1. Ensure dataset exists
    if not DATA_FILE.is_file():
        if ENRICHED_FILE.is_file():
            print(f'Risk assessed dataset not found. Running risk assessment on {ENRICHED_FILE.name}...')
            df = pd.read_csv(ENRICHED_FILE)
            assessed = compute_risk(df)
            DATA_FILE.parent.mkdir(parents=True, exist_ok=True)
            assessed.to_csv(DATA_FILE, index=False)
        else:
            raise FileNotFoundError(f'Neither {DATA_FILE} nor {ENRICHED_FILE} exists.')

    df = pd.read_csv(DATA_FILE)
    print(f'\n[1] Loaded Dataset: {len(df)} records from {DATA_FILE.name}')
    print(f'    Target Variable: "residual_risk_level"')
    print(f'    Features ({len(FEATURE_COLUMNS)}): {", ".join(FEATURE_COLUMNS)}')

    # 2. Preprocess & Stratified Split
    X_train, X_test, y_train, y_test, scaler = prepare_ml_data(
        df, target_column='residual_risk_level', test_size=0.20, random_state=42
    )
    print(f'\n[2] Stratified 80/20 Train-Test Split:')
    print(f'    Train Records : {len(X_train)} (80%)')
    print(f'    Test Records  : {len(X_test)} (20%)')
    print('    Test Class Distribution:')
    for cls in ORDERED_CLASSES:
        cnt = (y_test == cls).sum()
        print(f'      - {cls:8}: {cnt:3} records')

    # Scaled features strictly for Logistic Regression
    X_train_scaled = scaler.transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # 3. Model definitions
    classifiers = make_models()
    models: Dict[str, Any] = {
        'Logistic Regression': (classifiers['Logistic Regression'], X_train_scaled, X_test_scaled),
        'Decision Tree': (classifiers['Decision Tree'], X_train, X_test),
        'Random Forest': (classifiers['Random Forest'], X_train, X_test),
    }

    # 4. Training & Evaluation Loop
    results = {}
    best_name = ''
    best_f1 = -1.0

    print('\n[3] Model Training & Performance Evaluation:\n')
    for name, (clf, x_tr, x_te) in models.items():
        clf.fit(x_tr, y_train)
        preds = clf.predict(x_te)

        acc = accuracy_score(y_test, preds)
        macro_p, macro_r, macro_f1, _ = precision_recall_fscore_support(
            y_test, preds, average='macro', zero_division=0
        )
        weighted_p, weighted_r, weighted_f1, _ = precision_recall_fscore_support(
            y_test, preds, average='weighted', zero_division=0
        )
        cm = confusion_matrix(y_test, preds, labels=ORDERED_CLASSES)
        cr = classification_report(y_test, preds, labels=ORDERED_CLASSES, zero_division=0)

        results[name] = {
            'model': clf,
            'accuracy': acc,
            'macro_precision': macro_p,
            'macro_recall': macro_r,
            'macro_f1': macro_f1,
            'weighted_f1': weighted_f1,
            'cm': cm,
            'report': cr,
            'preds': preds
        }

        print(f'  === {name} ===')
        print(f'  Accuracy        : {acc * 100:.2f}%')
        print(f'  Macro F1-Score  : {macro_f1:.4f}')
        print(f'  Weighted F1     : {weighted_f1:.4f}')
        print('  Confusion Matrix:')
        print('  ' + format_confusion_matrix(cm, ORDERED_CLASSES).replace('\n', '\n  '))
        print()

        if weighted_f1 > best_f1:
            best_f1 = weighted_f1
            best_name = name

    grouped_results, grouped_split_info = evaluate_grouped_split(df)

    # 5. Feature Importance Analysis
    rf_model = results['Random Forest']['model']
    importances = rf_model.feature_importances_
    ranked_feats = sorted(zip(FEATURE_COLUMNS, importances), key=lambda x: -x[1])
    print('[4] Random Forest Feature Importance Ranking:')
    for rank, (feat, score) in enumerate(ranked_feats, 1):
        bar = '#' * int(score * 40)
        print(f'  {rank}. {feat:22}: {score:.4f}  {bar}')

    # 6. Save Model Artifacts
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(results['Logistic Regression']['model'], MODELS_DIR / 'logistic_regression.joblib')
    joblib.dump(results['Decision Tree']['model'], MODELS_DIR / 'decision_tree.joblib')
    joblib.dump(results['Random Forest']['model'], MODELS_DIR / 'random_forest.joblib')
    joblib.dump(scaler, MODELS_DIR / 'scaler.joblib')
    print(f'\n[5] Model Artifacts Saved to: {MODELS_DIR.resolve()}')
    print(f'    - Best Model by baseline Weighted F1: {best_name} ({best_f1:.4f})')

    # 7. Generate Evaluation Markdown Report
    rows_md = []
    for mname, mres in results.items():
        rows_md.append(
            f"| **{mname}** | {mres['accuracy'] * 100:.2f}% | {mres['macro_precision']:.4f} | "
            f"{mres['macro_recall']:.4f} | {mres['macro_f1']:.4f} | {mres['weighted_f1']:.4f} |"
        )
    metrics_table = '\n'.join(rows_md)

    grouped_rows_md = '\n'.join(
        f"| **{name}** | {m['accuracy'] * 100:.2f}% | {m['macro_precision']:.4f} | "
        f"{m['macro_recall']:.4f} | {m['macro_f1']:.4f} | {m['weighted_f1']:.4f} |"
        for name, m in grouped_results.items()
    )

    feat_table = '\n'.join(
        f"| {rank} | `{f}` | {s:.4f} | {s * 100:.2f}% |"
        for rank, (f, s) in enumerate(ranked_feats, 1)
    )

    report_md = f"""# CyberPrior – Objective 2 Machine Learning Evaluation Report

**Evaluation Task**: Multi-class Vulnerability Residual Risk Classification (`Low`, `Moderate`, `High`, `Critical`)  
**Report generated**: {date.today().isoformat()}  
**Dataset**: `data/processed/CyberPrior_Risk_Assessed_Dataset_v1.csv` (1,160 records)  
**Split Protocol**: Stratified 80% Train ({len(X_train)} records) / 20% Test ({len(X_test)} records), `random_state=42`  
**Features Evaluated (7)**: `cvss_score`, `epss_score`, `cisa_kev`, `criticality`, `exposure`, `data_sensitivity`, `control_effectiveness`  
**What is being evaluated**: CyberPrior's rule-based risk engine assigns each record a residual risk label using the listed factors. The ML models are trained on those same factors to reproduce those labels. This evaluates consistency with the project framework; it does not validate predictions against real incidents or independently discover real-world risk.

**What is a CVE?** CVE means *Common Vulnerabilities and Exposures*. A CVE ID is a public identifier assigned to a disclosed cybersecurity vulnerability, such as `CVE-2024-3400`. The same CVE can appear in multiple rows because it may affect several assets. The CVE-grouped evaluation keeps all rows for a CVE together to check whether a model can reproduce the project's labels for vulnerabilities it did not see during training.

The source refresh date and cached EPSS/KEV dates are recorded in `docs/objective1_verification_report.md`.

Risk formula: `T = 0.40 × (CVSS/10) + 0.30 × EPSS + 0.30 × KEV`; `I = 0.40 × criticality + 0.30 × exposure + 0.30 × data sensitivity`; inherent risk = `T × I × 100`; residual risk = `inherent risk × (1 − control credit)`. Tiers: Low < 25, Moderate 25–<50, High 50–<70, Critical ≥70. Missing CVSS/EPSS use fallback values 5.0/0.0, with explicit flags in assessed output; current dataset fallback counts are CVSS={int(df.get('nvd_cvss_fallback_used', pd.Series(False, index=df.index)).astype(bool).sum())}, EPSS={int(df.get('epss_fallback_used', pd.Series(False, index=df.index)).astype(bool).sum())}.

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
{metrics_table}

### Evaluation 2: Performance on CVEs excluded from training

The second evaluation uses `GroupShuffleSplit(test_size=0.20, random_state=42)` with `cve_id` as the group. It produced {grouped_split_info['train_rows']} training rows across {grouped_split_info['train_cves']} CVEs and {grouped_split_info['test_rows']} test rows across {grouped_split_info['test_cves']} CVEs, with zero CVE overlap. A CVE (Common Vulnerabilities and Exposures) is a public identifier for a disclosed cybersecurity vulnerability, such as `CVE-2024-3400`. The same CVE can occur in multiple asset rows. Keeping all those rows on one side checks whether models reproduce project labels for vulnerabilities they did not see during training. Because groups have different row counts, the row split is approximate. This is one holdout from a limited number of CVEs and should be interpreted cautiously.

| Algorithm | Correct overall | Precision | Recall | Average F1 | Weighted F1 |
| :--- | :---: | :---: | :---: | :---: | :---: |
{grouped_rows_md}

The first split is the standard baseline: its test set contains records held back from training, but some CVEs and repeated synthetic asset scenarios can occur on both sides. The second split holds out whole CVEs and is the more relevant check for unseen vulnerabilities. These are two views of model performance, not two separate projects or model sets.

**Interpretation**: {best_name} leads the baseline weighted F1 ({best_f1:.4f}); compare the unseen-CVE class averages and individual-class results too. No model should be declared the winner on every metric. This comparison measures reproduction of project-generated labels, not real-world incident prediction.

---

## 2. Feature Importance Ranking (Random Forest)

| Rank | Feature | Importance Score | Percentage Contribution |
| :---: | :--- | :---: | :---: |
{feat_table}

### Key Takeaway for Viva
* Feature importance describes which inputs the Random Forest uses to reproduce the rule-generated labels; it is not evidence of real-world causal importance.

---

## 3. Detailed Classification Reports

### Logistic Regression
```text
{results['Logistic Regression']['report']}
```

### Decision Tree
```text
{results['Decision Tree']['report']}
```

### Random Forest
```text
{results['Random Forest']['report']}
```

---

## 4. Conclusion for Objective 2 Evaluation

1. All three approved algorithms were compared on the same stratified baseline split and the same CVE-grouped holdout. Preprocessing is fitted on each training partition only.
2. The risk labels are generated from the same features supplied to the models. These evaluations measure how well ML reproduces the CyberPrior framework labels, not real-world incident prediction or independent validation of organizational risk.
3. The stratified split uses seed 42, test size 0.20, and `StandardScaler` for Logistic Regression only. Model settings: Logistic Regression (`max_iter=1000`, `class_weight='balanced'`); Decision Tree (`max_depth=5`, `min_samples_split=4`); Random Forest (`n_estimators=100`, `max_depth=6`, `min_samples_split=4`); all use seed 42.
4. Scores use accuracy and macro precision, recall, and F1, plus weighted F1. CVE-grouped evaluation uses one `GroupShuffleSplit` holdout with `cve_id`, test size 0.20, and seed 42.
5. Serialized models and the scaler are stored in `models/` for later integration.
"""
    REPORT_FILE.parent.mkdir(parents=True, exist_ok=True)
    REPORT_FILE.write_text(report_md, encoding='utf-8')
    print(f'[6] Evaluation Report Saved to: {REPORT_FILE.resolve()}')
    print('=' * 75)
    print('                 OBJECTIVE 2 TRAINING COMPLETED SUCCESSFULLY!')
    print('=' * 75)


if __name__ == '__main__':
    train_and_evaluate()

"""CyberPrior - Visual Analytics & Evaluation Chart Generator

Generates publication-quality charts for project reports and viva presentations:
1. Inherent vs. Residual Risk Reduction distribution
2. Multi-Model Confusion Matrix Heatmaps (Logistic Regression, Decision Tree, Random Forest)
3. Random Forest Feature Importance Ranking
4. Threat Likelihood vs. Asset Impact Priority Matrix

Outputs saved to: docs/figures/
"""

import sys
from pathlib import Path
import joblib
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
from sklearn.metrics import confusion_matrix

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR / 'src'))

from preprocessing import prepare_ml_data, FEATURE_COLUMNS

DATA_FILE = BASE_DIR / 'data' / 'processed' / 'CyberPrior_Prioritized_Dataset_v1.csv'
MODELS_DIR = BASE_DIR / 'models'
FIGURES_DIR = BASE_DIR / 'docs' / 'figures'
ORDERED_CLASSES = ['Low', 'Moderate', 'High', 'Critical']


def plot_inherent_vs_residual(df: pd.DataFrame) -> None:
    fig, axes = plt.subplots(1, 2, figsize=(13, 5), dpi=150)
    palette = {'Low': '#2ecc71', 'Moderate': '#f1c40f', 'High': '#e67e22', 'Critical': '#e74c3c'}

    # Inherent Risk Count
    inh_counts = df['inherent_risk_level'].value_counts().reindex(ORDERED_CLASSES).fillna(0)
    axes[0].bar(inh_counts.index, inh_counts.values, color=[palette[c] for c in ORDERED_CLASSES], edgecolor='black', alpha=0.85)
    axes[0].set_title('Inherent Risk Distribution\n(Raw Threat & Asset Exposure)', fontsize=12, fontweight='bold')
    axes[0].set_ylabel('Number of Asset-Vulnerability Records', fontsize=10)
    axes[0].grid(axis='y', linestyle='--', alpha=0.5)
    for i, v in enumerate(inh_counts.values):
        axes[0].text(i, v + 8, f'{int(v)}\n({v/len(df)*100:.1f}%)', ha='center', fontsize=9, fontweight='bold')

    # Residual Risk Count
    res_counts = df['residual_risk_level'].value_counts().reindex(ORDERED_CLASSES).fillna(0)
    axes[1].bar(res_counts.index, res_counts.values, color=[palette[c] for c in ORDERED_CLASSES], edgecolor='black', alpha=0.85)
    axes[1].set_title('Residual Risk Distribution\n(Operational Risk After Security Controls)', fontsize=12, fontweight='bold')
    axes[1].grid(axis='y', linestyle='--', alpha=0.5)
    for i, v in enumerate(res_counts.values):
        axes[1].text(i, v + 8, f'{int(v)}\n({v/len(df)*100:.1f}%)', ha='center', fontsize=9, fontweight='bold')

    plt.suptitle('CyberPrior: Quantitative Risk Mitigation via Defensive Controls', fontsize=14, y=1.02)
    plt.tight_layout()
    out = FIGURES_DIR / 'fig1_inherent_vs_residual.png'
    plt.savefig(out, bbox_inches='tight')
    plt.close()
    print(f'[+] Saved: {out.name}')


def plot_confusion_matrices(df: pd.DataFrame) -> None:
    X_train, X_test, y_train, y_test, scaler = prepare_ml_data(df, target_column='residual_risk_level', random_state=42)
    X_test_scaled = scaler.transform(X_test)

    lr = joblib.load(MODELS_DIR / 'logistic_regression.joblib')
    dt = joblib.load(MODELS_DIR / 'decision_tree.joblib')
    rf = joblib.load(MODELS_DIR / 'random_forest.joblib')

    models = [
        ('Logistic Regression (Acc: 93.5%)', lr.predict(X_test_scaled)),
        ('Decision Tree (Acc: 85.8%)', dt.predict(X_test)),
        ('Random Forest (Acc: 89.7%)', rf.predict(X_test)),
    ]

    fig, axes = plt.subplots(1, 3, figsize=(16, 4.5), dpi=150)
    for idx, (title, preds) in enumerate(models):
        cm = confusion_matrix(y_test, preds, labels=ORDERED_CLASSES)
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', ax=axes[idx],
                    xticklabels=ORDERED_CLASSES, yticklabels=ORDERED_CLASSES, cbar=False)
        axes[idx].set_title(title, fontsize=11, fontweight='bold')
        axes[idx].set_xlabel('Predicted Risk Tier', fontsize=9)
        if idx == 0:
            axes[idx].set_ylabel('Ground Truth Risk Tier', fontsize=9)

    plt.suptitle('CyberPrior: Machine Learning Confusion Matrix Benchmarks (Test Set: N=232)', fontsize=13, y=1.03)
    plt.tight_layout()
    out = FIGURES_DIR / 'fig2_model_confusion_matrices.png'
    plt.savefig(out, bbox_inches='tight')
    plt.close()
    print(f'[+] Saved: {out.name}')


def plot_feature_importance() -> None:
    rf = joblib.load(MODELS_DIR / 'random_forest.joblib')
    importances = rf.feature_importances_
    sorted_idx = np.argsort(importances)

    plt.figure(figsize=(9, 5), dpi=150)
    y_ticks = np.arange(len(FEATURE_COLUMNS))
    plt.barh(y_ticks, importances[sorted_idx], color='#3498db', edgecolor='black', alpha=0.85)
    plt.yticks(y_ticks, [FEATURE_COLUMNS[i] for i in sorted_idx], fontsize=10)
    plt.xlabel('Random Forest Gini Feature Importance', fontsize=10)
    plt.title('CyberPrior: Gini Feature Importance Across Prioritization Features', fontsize=12, fontweight='bold', pad=12)
    plt.grid(axis='x', linestyle='--', alpha=0.5)

    for i, v in enumerate(importances[sorted_idx]):
        plt.text(v + 0.008, i, f'{v*100:.1f}%', va='center', fontsize=9, fontweight='bold')

    plt.tight_layout()
    out = FIGURES_DIR / 'fig3_feature_importance.png'
    plt.savefig(out, bbox_inches='tight')
    plt.close()
    print(f'[+] Saved: {out.name}')


def plot_threat_vs_impact_matrix(df: pd.DataFrame) -> None:
    plt.figure(figsize=(9, 6), dpi=150)
    palette = {'Low': '#2ecc71', 'Moderate': '#f1c40f', 'High': '#e67e22', 'Critical': '#e74c3c'}

    for lvl in ORDERED_CLASSES:
        sub = df[df['residual_risk_level'] == lvl]
        plt.scatter(
            sub['impact_factor'],
            sub['threat_factor'],
            color=palette[lvl],
            label=f'{lvl} Residual Risk (N={len(sub)})',
            alpha=0.65,
            edgecolor='black',
            linewidth=0.5,
            s=45
        )

    plt.title('CyberPrior: Threat Likelihood vs. Asset Impact Priority Matrix', fontsize=12, fontweight='bold', pad=12)
    plt.xlabel('Asset Business Impact Factor (Criticality + Exposure + Sensitivity)', fontsize=10)
    plt.ylabel('Threat Likelihood Factor (CVSS + EPSS + CISA KEV)', fontsize=10)
    plt.axvline(0.70, color='grey', linestyle=':', alpha=0.6)
    plt.axhline(0.70, color='grey', linestyle=':', alpha=0.6)
    plt.legend(frameon=True, facecolor='white', loc='upper left')
    plt.grid(True, linestyle='--', alpha=0.4)
    plt.tight_layout()
    out = FIGURES_DIR / 'fig4_threat_vs_impact_matrix.png'
    plt.savefig(out, bbox_inches='tight')
    plt.close()
    print(f'[+] Saved: {out.name}')


def main() -> None:
    print('=' * 70)
    print('      CYBERPRIOR - VISUAL ANALYTICS & PLOT GENERATOR')
    print('=' * 70)
    FIGURES_DIR.mkdir(parents=True, exist_ok=True)

    if not DATA_FILE.is_file():
        raise FileNotFoundError(f'Missing dataset: {DATA_FILE}')

    df = pd.read_csv(DATA_FILE)
    print(f'Loaded {len(df)} records from {DATA_FILE.name}')

    plot_inherent_vs_residual(df)
    plot_confusion_matrices(df)
    plot_feature_importance()
    plot_threat_vs_impact_matrix(df)

    print(f'\nAll figures generated successfully in: {FIGURES_DIR.resolve()}')
    print('=' * 70)


if __name__ == '__main__':
    main()

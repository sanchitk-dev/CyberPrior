"""CyberPrior - Objective 2: Model & Factor Explainability Engine

Combines:
1. NIST Factor-level Breakdown (Threat Likelihood, Asset Impact, Control Reductions)
2. Game-Theoretic ML Attribution via SHAP (SHapley Additive exPlanations)
3. Actionable Remediation Guidance

Generates local sample attributions and global feature summary plots.
"""

import sys
from pathlib import Path
from typing import Any, Dict, List, Optional
import joblib
import numpy as np
import pandas as pd
import shap
import matplotlib.pyplot as plt

# Ensure immediate console output
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(line_buffering=True)

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR / 'src'))

from preprocessing import extract_features, FEATURE_COLUMNS

PRIORITIZED_CSV = BASE_DIR / 'data' / 'processed' / 'CyberPrior_Prioritized_Dataset_v1.csv'
MODEL_FILE = BASE_DIR / 'models' / 'random_forest.joblib'
FIGURES_DIR = BASE_DIR / 'docs' / 'figures'


class CyberPriorExplainer:
    """Provides local and global explainability for CyberPrior risk predictions."""

    def __init__(self, model_path: Path = MODEL_FILE, data_path: Path = PRIORITIZED_CSV):
        if not model_path.is_file():
            raise FileNotFoundError(f'Model not found: {model_path}')
        if not data_path.is_file():
            raise FileNotFoundError(f'Data not found: {data_path}')

        self.model = joblib.load(model_path)
        self.df = pd.read_csv(data_path)
        self.X = extract_features(self.df)
        self.tree_explainer = shap.TreeExplainer(self.model)

    def explain_asset(self, asset_id: str) -> Dict[str, Any]:
        """Generate comprehensive multi-layer explanation for a specific asset ID."""
        matches = self.df[self.df['asset_id'].str.upper() == asset_id.strip().upper()]
        if matches.empty:
            raise KeyError(f'Asset ID "{asset_id}" not found in dataset.')

        row = matches.iloc[0]
        idx = matches.index[0]

        # 1. NIST Factor breakdown
        nist_breakdown = {
            'threat_factor': row.get('threat_factor'),
            'impact_factor': row.get('impact_factor'),
            'inherent_risk_score': row.get('inherent_risk_score'),
            'inherent_risk_level': row.get('inherent_risk_level'),
            'control_mitigation_credit': row.get('control_mitigation_credit'),
            'residual_risk_score': row.get('residual_risk_score'),
            'residual_risk_level': row.get('residual_risk_level'),
            'priority_rank': row.get('priority_rank'),
            'priority_score': row.get('priority_score'),
            'action_category': row.get('action_category'),
            'remediation_sla': row.get('remediation_sla'),
            'text_explanation': row.get('risk_explanation'),
            'recommended_action': row.get('recommended_action'),
        }

        # 2. Local SHAP Values
        sample_X = self.X.iloc[[idx]]
        shap_vals = self.tree_explainer.shap_values(sample_X)

        # Map predicted class index
        pred_label = self.model.predict(sample_X)[0]
        classes_list = list(self.model.classes_)
        pred_class_idx = classes_list.index(pred_label)

        # Extract SHAP array for predicted class
        if isinstance(shap_vals, list):
            class_shap = shap_vals[pred_class_idx][0]
        else:
            class_shap = shap_vals[0, :, pred_class_idx]

        feature_contributions = []
        for feat, val, sval in zip(FEATURE_COLUMNS, sample_X.iloc[0], class_shap):
            feature_contributions.append({
                'feature': feat,
                'value': val,
                'shap_attribution': round(float(sval), 4),
                'direction': (
                    'Supports predicted class' if sval > 0 else
                    'Opposes predicted class' if sval < 0 else
                    'Neutral for predicted class'
                )
            })

        # Sort by absolute SHAP magnitude
        feature_contributions.sort(key=lambda x: abs(x['shap_attribution']), reverse=True)

        return {
            'asset_id': row['asset_id'],
            'asset_name': row['asset'],
            'cve_id': row['cve_id'],
            'nist_breakdown': nist_breakdown,
            'predicted_class': pred_label,
            'shap_contributions': feature_contributions
        }

    def generate_global_shap_plot(self, output_path: Path = FIGURES_DIR / 'fig3_shap_summary.png') -> None:
        """Generate global SHAP summary beeswarm/bar plot across all features."""
        FIGURES_DIR.mkdir(parents=True, exist_ok=True)
        print('Computing global SHAP values across dataset sample...')
        sample_size = min(300, len(self.X))
        X_sample = self.X.sample(n=sample_size, random_state=42)

        shap_vals = self.tree_explainer.shap_values(X_sample)

        # Multi-class bar summary
        plt.figure(figsize=(10, 6), dpi=150)
        shap.summary_plot(
            shap_vals,
            X_sample,
            feature_names=FEATURE_COLUMNS,
            class_names=list(self.model.classes_),
            plot_type='bar',
            show=False
        )
        plt.title('CyberPrior - Global SHAP Feature Attributions Across Risk Classes', fontsize=12, pad=15)
        plt.tight_layout()
        plt.savefig(output_path, bbox_inches='tight')
        plt.close()
        print(f'[+] Global SHAP Plot saved to: {output_path.resolve()}')


def main() -> None:
    print('=' * 75)
    print('          CYBERPRIOR - MODEL & FACTOR EXPLAINABILITY ENGINE')
    print('=' * 75)

    explainer = CyberPriorExplainer()

    # Explain top critical asset AST-0004
    sample_id = 'AST-0004'
    print(f'\n[1] Generating Explainability Report for Sample Asset: {sample_id}')
    info = explainer.explain_asset(sample_id)

    print(f'  Target       : {info["asset_name"]} ({info["asset_id"]}) -> {info["cve_id"]}')
    print(f'  Priority     : Rank #{info["nist_breakdown"]["priority_rank"]} (Score: {info["nist_breakdown"]["priority_score"]})')
    print(f'  Risk Level   : {info["nist_breakdown"]["residual_risk_level"]} (Score: {info["nist_breakdown"]["residual_risk_score"]})')
    print(f'  SLA & Action : {info["nist_breakdown"]["remediation_sla"]} | {info["nist_breakdown"]["action_category"]}')
    print(f'\n  --- Factor Explanation ---')
    print(f'  {info["nist_breakdown"]["text_explanation"]}')

    print(f'\n  --- Machine Learning (SHAP) Game-Theoretic Feature Attributions ---')
    for feat in info['shap_contributions']:
        sign = '+' if feat['shap_attribution'] > 0 else ''
        print(f'    * {feat["feature"]:22} (val={feat["value"]}): {sign}{feat["shap_attribution"]:.4f}  [{feat["direction"]}]')

    # Generate global visualization
    explainer.generate_global_shap_plot()
    print('=' * 75)


if __name__ == '__main__':
    main()

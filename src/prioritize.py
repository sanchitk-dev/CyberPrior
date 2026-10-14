"""CyberPrior - Interactive Vulnerability Prioritization & Decision Support Tool

Command-line tool designed for security analysts and project viva evaluation:
- Filter and rank vulnerabilities by Priority Score (1-100) and SLA
- Query by Asset, CVE, Action Category, or CISA KEV status
- Inspect deep multi-factor and SHAP model explainability for any asset record

Examples:
  python src/prioritize.py --top 10
  python src/prioritize.py --asset "VPN Gateway"
  python src/prioritize.py --kev-only
  python src/prioritize.py --action "Enable MFA"
  python src/prioritize.py --sla P1
  python src/prioritize.py --explain AST-0004
"""

import argparse
import sys
from pathlib import Path
import pandas as pd

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR / 'src'))

from explainability import CyberPriorExplainer

DATA_FILE = BASE_DIR / 'data' / 'processed' / 'CyberPrior_Prioritized_Dataset_v1.csv'


def print_table(df_subset: pd.DataFrame, title: str) -> None:
    print('=' * 105)
    print(f' {title.upper()} ({len(df_subset)} records matching)')
    print('=' * 105)
    header = f'{"RANK":<5} | {"ASSET ID":<9} | {"ASSET NAME":<18} | {"CVE ID":<15} | {"SCORE":<6} | {"RISK":<9} | {"SLA":<14} | {"ACTION CATEGORY":<25}'
    print(header)
    print('-' * len(header))
    for _, r in df_subset.iterrows():
        sla_short = str(r['remediation_sla']).split(' - ')[0]
        act_short = str(r['action_category'])[:25]
        print(f'{r["priority_rank"]:<5} | {r["asset_id"]:<9} | {r["asset"][:18]:<18} | {r["cve_id"]:<15} | {r["priority_score"]:<6.2f} | {r["residual_risk_level"]:<9} | {sla_short:<14} | {act_short:<25}')
    print('=' * 105)


def explain_single(asset_id: str) -> None:
    explainer = CyberPriorExplainer()
    try:
        res = explainer.explain_asset(asset_id)
    except KeyError as e:
        print(f'[ERROR] {e}')
        return

    nb = res['nist_breakdown']
    print('\n' + '=' * 80)
    print(f'          EXPLAINABLE RISK PROFILE: {res["asset_id"]} ({res["asset_name"]})')
    print('=' * 80)
    print(f'  Target CVE           : {res["cve_id"]}')
    print(f'  Priority Rank        : #{nb["priority_rank"]} (Priority Score: {nb["priority_score"]:.2f}/100)')
    print(f'  Residual Risk Level  : {nb["residual_risk_level"]} (Score: {nb["residual_risk_score"]:.2f}/100)')
    print(f'  Inherent Risk Level  : {nb["inherent_risk_level"]} (Score: {nb["inherent_risk_score"]:.2f}/100)')
    print(f'  Control Mitigation   : {nb["control_mitigation_credit"] * 100:.0f}% risk reduction credited')
    print(f'  Remediation SLA      : {nb["remediation_sla"]}')
    print(f'  Target Action        : {nb["action_category"]}')
    print('\n  [1] Contributing Risk Factors:')
    for f in nb['text_explanation'].split('; '):
        print(f'      * {f}')
    print('\n  [2] Recommended Mitigation Guidance:')
    print(f'      -> {nb["recommended_action"]}')
    print('\n  [3] Machine Learning (SHAP) Model Attribution:')
    for item in res['shap_contributions']:
        sign = '+' if item['shap_attribution'] > 0 else ''
        print(f'      * {item["feature"]:24} (val={item["value"]}): {sign}{item["shap_attribution"]:.4f} [{item["direction"]}]')
    print('=' * 80 + '\n')


def main() -> None:
    parser = argparse.ArgumentParser(description='CyberPrior Intelligent Prioritization Query Tool')
    parser.add_argument('--top', type=int, default=10, help='Show top N prioritized vulnerabilities')
    parser.add_argument('--asset', type=str, default=None, help='Filter by asset name substring')
    parser.add_argument('--action', type=str, default=None, help='Filter by action category substring')
    parser.add_argument('--sla', type=str, default=None, help='Filter by SLA level (P1, P2, P3, P4)')
    parser.add_argument('--kev-only', action='store_true', help='Show only vulnerabilities listed in CISA KEV')
    parser.add_argument('--explain', type=str, default=None, help='Show full factor & SHAP explainability for an Asset ID')

    args = parser.parse_args()

    if args.explain:
        explain_single(args.explain)
        return

    if not DATA_FILE.is_file():
        print(f'[ERROR] Prioritized dataset not found at {DATA_FILE}. Run prioritization_engine.py first.')
        sys.exit(1)

    df = pd.read_csv(DATA_FILE)

    # Apply filters
    filtered = df.copy()
    filter_desc = []

    if args.asset:
        filtered = filtered[filtered['asset'].str.contains(args.asset, case=False, na=False)]
        filter_desc.append(f'Asset="{args.asset}"')

    if args.action:
        filtered = filtered[filtered['action_category'].str.contains(args.action, case=False, na=False)]
        filter_desc.append(f'Action="{args.action}"')

    if args.sla:
        filtered = filtered[filtered['remediation_sla'].str.contains(args.sla, case=False, na=False)]
        filter_desc.append(f'SLA="{args.sla}"')

    if args.kev_only:
        filtered = filtered[filtered['cisa_kev'] == True]
        filter_desc.append('CISA KEV=True')

    desc_str = ' | '.join(filter_desc) if filter_desc else f'Top {args.top} Priority Queue'
    subset = filtered.head(args.top)
    print_table(subset, f'CyberPrior Prioritized Queue - {desc_str}')


if __name__ == '__main__':
    main()

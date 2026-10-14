"""CyberPrior - Objective 2: Intelligent Vulnerability Prioritization Engine

Calculates continuous Prioritization Index (1-100), absolute Priority Ranks (1 to N),
remediation SLAs, and targeted mitigation action categories:
- Patch Vulnerability
- Network Segmentation
- Enable MFA & Access Restriction
- Apply Compensating Controls

Input:  data/processed/CyberPrior_Risk_Assessed_Dataset_v1.csv
Output: data/processed/CyberPrior_Prioritized_Dataset_v1.csv & .xlsx
"""

import sys
from pathlib import Path
from typing import Dict, List, Tuple
import pandas as pd

# Ensure immediate console output
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(line_buffering=True)

BASE_DIR = Path(__file__).resolve().parent.parent
INPUT_CSV = BASE_DIR / 'data' / 'processed' / 'CyberPrior_Risk_Assessed_Dataset_v1.csv'
OUTPUT_CSV = BASE_DIR / 'data' / 'processed' / 'CyberPrior_Prioritized_Dataset_v1.csv'
OUTPUT_XLSX = BASE_DIR / 'data' / 'processed' / 'CyberPrior_Prioritized_Dataset_v1.xlsx'


def assign_action_category(row: pd.Series) -> str:
    """Categorize targeted mitigation into standardized organizational defense actions."""
    is_external = str(row.get('exposure', '')) == 'External'
    ctrl_low = str(row.get('control_effectiveness', '')) == 'Low'
    crit_high = str(row.get('criticality', '')) in ('Critical', 'High')
    asset = str(row.get('asset', '')).lower()
    cisa_kev = bool(row.get('cisa_kev'))

    # Public-facing gateways and admin portals require authentication and perimeter restriction
    if is_external and any(k in asset for k in ['gateway', 'portal', 'vpn', 'firewall', 'web']):
        return 'Enable MFA & Access Restriction'

    # High-value internal infrastructure needs network isolation
    if not is_external and crit_high and any(k in asset for k in ['database', 'controller', 'finance', 'backup', 'hr']):
        return 'Network Segmentation'

    # If actively exploited in KEV and controls are weak, urgent compensating controls are needed if patch takes time
    if cisa_kev and ctrl_low:
        return 'Apply Compensating Controls (WAF / IPS / Virtual Patch)'

    # Default and primary response is vendor software patching
    return 'Patch Vulnerability'


def assign_remediation_sla(residual_level: str) -> str:
    """Assign defensible remediation service level agreement (SLA) based on residual risk."""
    if residual_level == 'Critical':
        return 'P1 - Emergency (24 to 48 Hours)'
    if residual_level == 'High':
        return 'P2 - High Priority (7 to 14 Days)'
    if residual_level == 'Moderate':
        return 'P3 - Medium Priority (30 Days)'
    return 'P4 - Routine Cycle (90 Days / Next Maintenance Window)'


def prioritize_dataset(df: pd.DataFrame) -> pd.DataFrame:
    """Calculate multi-criteria priority scores and order vulnerabilities strictly."""
    out = df.copy()

    # Priority Index formula:
    # 50% Residual Risk + 25% Exploit Velocity (EPSS) + 15% CISA KEV presence + 10% Exposure
    res_risk = out['residual_risk_score']
    epss_contrib = out['epss_score'].fillna(0.0) * 100.0
    kev_contrib = out['cisa_kev'].astype(bool).astype(float) * 100.0
    exp_contrib = (out['exposure'] == 'External').astype(float) * 100.0

    priority_score = (
        0.50 * res_risk +
        0.25 * epss_contrib +
        0.15 * kev_contrib +
        0.10 * exp_contrib
    ).round(2)

    out['priority_score'] = priority_score

    # Sort descending by priority_score, then cvss_score
    out.sort_values(
        by=['priority_score', 'nvd_cvss_score', 'epss_score'],
        ascending=[False, False, False],
        inplace=True
    )
    out.reset_index(drop=True, inplace=True)

    # Assign 1-indexed Priority Rank
    out['priority_rank'] = out.index + 1

    # Assign actionable defense categorization and remediation SLA
    out['action_category'] = out.apply(assign_action_category, axis=1)
    out['remediation_sla'] = out['residual_risk_level'].apply(assign_remediation_sla)

    return out


def main() -> None:
    print('=' * 75)
    print('     CYBERPRIOR - INTELLIGENT VULNERABILITY PRIORITIZATION ENGINE')
    print('=' * 75)

    if not INPUT_CSV.is_file():
        raise FileNotFoundError(f'Input risk-assessed file missing: {INPUT_CSV.resolve()}')

    df = pd.read_csv(INPUT_CSV)
    print(f'Loaded {len(df)} assessed records from {INPUT_CSV.name}')

    prioritized = prioritize_dataset(df)

    OUTPUT_CSV.parent.mkdir(parents=True, exist_ok=True)
    prioritized.to_csv(OUTPUT_CSV, index=False)
    try:
        prioritized.to_excel(OUTPUT_XLSX, index=False)
    except Exception as e:
        print(f'Excel export skipped: {e}')

    print(f'\n[+] Prioritization Complete:')
    print(f'    Output CSV   : {OUTPUT_CSV.resolve()}')
    print(f'    Output Excel : {OUTPUT_XLSX.resolve()}')

    print('\n--- Action Category Distribution ---')
    for act, cnt in prioritized['action_category'].value_counts().items():
        print(f'  - {act:50}: {cnt:4} ({cnt / len(prioritized) * 100:5.1f}%)')

    print('\n--- Remediation SLA Distribution ---')
    for sla, cnt in prioritized['remediation_sla'].value_counts().items():
        print(f'  - {sla:45}: {cnt:4} ({cnt / len(prioritized) * 100:5.1f}%)')

    print('\n--- TOP 5 HIGHEST PRIORITY VULNERABILITIES TO REMEDIATE ---')
    cols_to_show = ['priority_rank', 'asset_id', 'asset', 'cve_id', 'priority_score', 'residual_risk_level', 'action_category', 'remediation_sla']
    top5 = prioritized[cols_to_show].head(5)
    for _, r in top5.iterrows():
        print(f'  #{r["priority_rank"]} [{r["asset_id"]} | {r["asset"]:18}] {r["cve_id"]} -> Score={r["priority_score"]:.2f} ({r["residual_risk_level"]}) | SLA: {r["remediation_sla"].split(" - ")[0]} | Action: {r["action_category"]}')

    print('=' * 75)


if __name__ == '__main__':
    main()

"""CyberPrior - Objective 2: Vulnerability Risk Assessment Engine

Calculates Inherent and Residual Risk scores and classifies vulnerabilities into
explainable risk categories (Low, Moderate, High, Critical) using a NIST SP 800-30
aligned formulation:

  Threat Factor (T) = 0.40 * (CVSS / 10) + 0.30 * EPSS + 0.30 * CISA_KEV
  Impact Factor (I) = 0.40 * Criticality + 0.30 * Exposure + 0.30 * Data_Sensitivity
  Inherent Risk (R_inh) = T * I * 100
  Residual Risk (R_res) = R_inh * (1 - Control_Credit)

Input:  data/processed/CyberPrior_Enriched_Dataset_v1.csv
Output: data/processed/CyberPrior_Risk_Assessed_Dataset_v1.csv & .xlsx
"""

import sys
from pathlib import Path
from typing import Dict, List, Tuple
import pandas as pd

# Ensure line-buffered immediate console output
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(line_buffering=True)

BASE_DIR = Path(__file__).resolve().parent.parent
INPUT_CSV = BASE_DIR / 'data' / 'processed' / 'CyberPrior_Enriched_Dataset_v1.csv'
OUTPUT_CSV = BASE_DIR / 'data' / 'processed' / 'CyberPrior_Risk_Assessed_Dataset_v1.csv'
OUTPUT_XLSX = BASE_DIR / 'data' / 'processed' / 'CyberPrior_Risk_Assessed_Dataset_v1.xlsx'

# Scale mappings aligned with cybersecurity risk frameworks
CRITICALITY_MAP = {'Low': 0.25, 'Medium': 0.50, 'High': 0.75, 'Critical': 1.00}
EXPOSURE_MAP = {'Internal': 0.40, 'External': 1.00}
SENSITIVITY_MAP = {'Low': 0.25, 'Medium': 0.50, 'High': 0.75, 'Critical': 1.00}
CONTROL_CREDIT_MAP = {'Low': 0.15, 'Medium': 0.40, 'High': 0.70}


def classify_risk_level(score: float) -> str:
    """Classify 0-100 numerical risk score into standard risk tier."""
    if score >= 70.0:
        return 'Critical'
    if score >= 50.0:
        return 'High'
    if score >= 25.0:
        return 'Moderate'
    return 'Low'


def generate_explanation(row: pd.Series) -> str:
    """Produce human-readable, factor-level explanation of risk drivers."""
    factors: List[str] = []

    # Threat & exploitability factors
    cvss = row.get('nvd_cvss_score', 0.0)
    if cvss >= 9.0:
        factors.append(f'Critical CVSS severity ({cvss:.1f}/10)')
    elif cvss >= 7.0:
        factors.append(f'High CVSS severity ({cvss:.1f}/10)')

    epss = row.get('epss_score', 0.0)
    if epss >= 0.70:
        factors.append(f'High exploitation likelihood (EPSS {epss * 100:.1f}%)')
    elif epss >= 0.30:
        factors.append(f'Moderate exploitation likelihood (EPSS {epss * 100:.1f}%)')

    if row.get('cisa_kev') is True or str(row.get('cisa_kev')).lower() == 'true':
        factors.append('Active in CISA Known Exploited Vulnerabilities (KEV)')
        if str(row.get('cisa_ransomware_use', '')).lower() == 'known':
            factors.append('Associated with known ransomware campaigns')

    # Asset context factors
    crit = str(row.get('criticality', ''))
    if crit in ('Critical', 'High'):
        factors.append(f'{crit} asset business criticality')

    exp = str(row.get('exposure', ''))
    if exp == 'External':
        factors.append('Publicly exposed to external network')

    sens = str(row.get('data_sensitivity', ''))
    if sens in ('Critical', 'High'):
        factors.append(f'{sens} data sensitivity')

    ctrl = str(row.get('control_effectiveness', ''))
    if ctrl == 'Low':
        factors.append('Weak existing defense controls (Low effectiveness)')
    elif ctrl == 'High':
        factors.append('Strong existing defense controls (Mitigating residual risk)')

    return '; '.join(factors) if factors else 'Standard baseline risk factors'


def generate_recommendation(residual_level: str, row: pd.Series) -> str:
    """Recommend actionable mitigation steps based on residual risk and exposure."""
    is_external = str(row.get('exposure', '')) == 'External'
    ctrl_low = str(row.get('control_effectiveness', '')) == 'Low'

    if residual_level == 'Critical':
        rec = 'Emergency Patching (24-48h). Isolate affected systems or restrict inbound traffic immediately.'
        if is_external:
            rec += ' Place behind WAF/Reverse Proxy and mandate MFA.'
        return rec
    if residual_level == 'High':
        rec = 'High Priority Patching (within 7 days). Implement compensating network segmentation.'
        if ctrl_low:
            rec += ' Strengthen firewall and access monitoring rules.'
        return rec
    if residual_level == 'Moderate':
        return 'Standard Remediation: Schedule patch in regular maintenance cycle (within 30 days). Verify intrusion logs.'
    return 'Monitor & Maintain: Review during periodic vulnerability assessment cycle. Current controls are adequate.'


def compute_risk(df: pd.DataFrame) -> pd.DataFrame:
    """Apply risk calculation, explanation, and recommendation logic across dataset."""
    out = df.copy()

    # 1. Threat Factor T in [0, 1]
    cvss_values = pd.to_numeric(out['nvd_cvss_score'], errors='coerce')
    epss_values = pd.to_numeric(out['epss_score'], errors='coerce')
    out['nvd_cvss_fallback_used'] = cvss_values.isna()
    out['epss_fallback_used'] = epss_values.isna()
    cvss_norm = cvss_values.fillna(5.0) / 10.0
    epss_norm = epss_values.fillna(0.0)
    kev_norm = out['cisa_kev'].astype(bool).astype(float)
    out['threat_factor'] = (0.40 * cvss_norm + 0.30 * epss_norm + 0.30 * kev_norm).round(4)

    # 2. Impact Factor I in [0, 1]
    crit_val = out['criticality'].map(CRITICALITY_MAP).fillna(0.50)
    exp_val = out['exposure'].map(EXPOSURE_MAP).fillna(0.40)
    sens_val = out['data_sensitivity'].map(SENSITIVITY_MAP).fillna(0.50)
    out['impact_factor'] = (0.40 * crit_val + 0.30 * exp_val + 0.30 * sens_val).round(4)

    # 3. Inherent Risk Score & Level
    out['inherent_risk_score'] = (out['threat_factor'] * out['impact_factor'] * 100.0).round(2)
    out['inherent_risk_level'] = out['inherent_risk_score'].apply(classify_risk_level)

    # 4. Control Credit & Residual Risk Score & Level
    ctrl_credit = out['control_effectiveness'].map(CONTROL_CREDIT_MAP).fillna(0.15)
    out['control_mitigation_credit'] = ctrl_credit
    out['residual_risk_score'] = (out['inherent_risk_score'] * (1.0 - ctrl_credit)).round(2)
    out['residual_risk_level'] = out['residual_risk_score'].apply(classify_risk_level)

    # 5. Explainability & Mitigation Actions
    out['risk_explanation'] = out.apply(generate_explanation, axis=1)
    out['recommended_action'] = out.apply(
        lambda r: generate_recommendation(r['residual_risk_level'], r),
        axis=1
    )

    return out


def main() -> None:
    print('=' * 70)
    print('       CYBERPRIOR - OBJECTIVE 2 RISK ASSESSMENT ENGINE')
    print('=' * 70)

    if not INPUT_CSV.is_file():
        raise FileNotFoundError(f'Enriched dataset not found: {INPUT_CSV.resolve()}')

    df = pd.read_csv(INPUT_CSV)
    print(f'Loaded enriched records: {len(df)} from {INPUT_CSV.name}')

    assessed = compute_risk(df)

    OUTPUT_CSV.parent.mkdir(parents=True, exist_ok=True)
    assessed.to_csv(OUTPUT_CSV, index=False)
    try:
        assessed.to_excel(OUTPUT_XLSX, index=False)
    except Exception as e:
        print(f'Excel export skipped: {e}')

    print('\n[+] Risk Assessment Complete:')
    print(f'  Saved CSV   : {OUTPUT_CSV.resolve()}')
    print(f'  Saved Excel : {OUTPUT_XLSX.resolve()}')

    print('\n--- Inherent Risk Distribution ---')
    for level, count in assessed['inherent_risk_level'].value_counts().items():
        print(f'  {level:10}: {count:4} ({count / len(assessed) * 100:5.1f}%)')

    print('\n--- Residual Risk Distribution (After Controls) ---')
    for level, count in assessed['residual_risk_level'].value_counts().items():
        print(f'  {level:10}: {count:4} ({count / len(assessed) * 100:5.1f}%)')

    print('\n[+] Sample Risk Assessment Record:')
    sample = assessed.iloc[0]
    print(f'  Asset      : {sample["asset"]} ({sample["asset_id"]})')
    print(f'  CVE        : {sample["cve_id"]} (CVSS={sample["nvd_cvss_score"]}, EPSS={sample["epss_score"]:.4f}, KEV={sample["cisa_kev"]})')
    print(f'  Context    : Criticality={sample["criticality"]}, Exposure={sample["exposure"]}, Controls={sample["control_effectiveness"]}')
    print(f'  Inherent   : Score={sample["inherent_risk_score"]} ({sample["inherent_risk_level"]})')
    print(f'  Residual   : Score={sample["residual_risk_score"]} ({sample["residual_risk_level"]})')
    print(f'  Explanation: {sample["risk_explanation"]}')
    print(f'  Action     : {sample["recommended_action"]}')
    print('=' * 70)


if __name__ == '__main__':
    main()

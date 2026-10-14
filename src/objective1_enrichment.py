"""CyberPrior - Objective 1: Automated Vulnerability Data Enrichment Pipeline

Integrates organization-specific asset/control records with external vulnerability
intelligence from:
1. NVD (National Vulnerability Database) - CVSS v2/v3/v4 score, severity, CWE, descriptions
2. EPSS (Exploit Prediction Scoring System) - Exploitation probability and percentile
3. CISA KEV (Known Exploited Vulnerabilities Catalog) - Active in-the-wild exploitation status

Input:  data/raw/CyberPrior_Input_Dataset_v2_1160.csv
Output: data/processed/CyberPrior_Enriched_Dataset_v1.csv & .xlsx
Cache:  data/raw/api_cache/ (nvd/, epss.json, kev.json)
"""

import json
import argparse
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import pandas as pd
import requests

# Ensure line-buffered immediate console output
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(line_buffering=True)

# Project base paths
BASE_DIR = Path(__file__).resolve().parent.parent

# Use the canonical project dataset unless the caller explicitly supplies another file.
env_input = os.getenv('CYBERPRIOR_INPUT')
INPUT = Path(env_input).expanduser() if env_input else BASE_DIR / 'data' / 'raw' / 'CyberPrior_Input_Dataset_v2_1160.csv'

# Output destinations
PROCESSED_DIR = BASE_DIR / 'data' / 'processed'
OUTPUT_CSV = PROCESSED_DIR / 'CyberPrior_Enriched_Dataset_v1.csv'
OUTPUT_XLSX = PROCESSED_DIR / 'CyberPrior_Enriched_Dataset_v1.xlsx'

# Cache directories
CACHE = BASE_DIR / 'data' / 'raw' / 'api_cache'
NVD_CACHE = CACHE / 'nvd'
EPSS_CACHE = CACHE / 'epss.json'
KEV_CACHE = CACHE / 'kev.json'

# External threat intelligence APIs
NVD_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
EPSS_URL = 'https://api.first.org/data/v1/epss'
KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'

NVD_API_KEY = os.getenv('NVD_API_KEY', '').strip()
TIMEOUT = 30


def get_json(
    session: requests.Session,
    url: str,
    params: Optional[Dict[str, Any]] = None,
    headers: Optional[Dict[str, str]] = None,
    retries: int = 4
) -> Dict[str, Any]:
    """Execute HTTP GET with automatic retries and exponential backoff for rate limits."""
    last: Optional[Exception] = None
    for attempt in range(retries):
        try:
            r = session.get(url, params=params, headers=headers, timeout=TIMEOUT)
            if r.status_code == 200:
                return r.json()
            if r.status_code in (429, 500, 502, 503, 504):
                wait = min(60, 5 * (attempt + 1))
                print(f'HTTP {r.status_code}; retrying in {wait}s...')
                time.sleep(wait)
                last = RuntimeError(f'HTTP {r.status_code}')
                continue
            r.raise_for_status()
        except Exception as e:
            last = e
            if attempt < retries - 1:
                wait = min(30, 3 * (attempt + 1))
                print(f'Request failed: {e}; retrying in {wait}s...')
                time.sleep(wait)

    if last is not None:
        raise last
    raise RuntimeError(f'Failed to fetch {url}: retries exhausted')


def first_text(items: Optional[List[Dict[str, Any]]]) -> str:
    """Extract first English string from NVD description array."""
    for x in items or []:
        if isinstance(x, dict) and x.get('lang') == 'en' and x.get('value'):
            return str(x['value'])
    return ''


def extract_nvd(cve_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
    """Parse NVD JSON payload into standardized schema fields."""
    vulns = data.get('vulnerabilities', [])
    if not vulns:
        return {
            'cve_id': cve_id, 'nvd_found': False, 'nvd_description': '',
            'nvd_cvss_version': '', 'nvd_cvss_score': None, 'nvd_cvss_severity': '',
            'nvd_cvss_vector': '', 'nvd_cwe': '', 'nvd_affected_products': '',
            'nvd_published': '', 'nvd_last_modified': ''
        }

    cve = vulns[0].get('cve', {})
    metrics = cve.get('metrics', {})
    chosen = None
    version = ''
    for key, ver in [
        ('cvssMetricV40', '4.0'),
        ('cvssMetricV31', '3.1'),
        ('cvssMetricV30', '3.0'),
        ('cvssMetricV2', '2.0')
    ]:
        if metrics.get(key):
            chosen = metrics[key][0]
            version = ver
            break

    cvss = (chosen or {}).get('cvssData', {})
    score = cvss.get('baseScore')
    severity = cvss.get('baseSeverity') or (chosen or {}).get('baseSeverity', '')
    vector = cvss.get('vectorString', '')

    cwes = []
    for pt in cve.get('weaknesses', []):
        for d in pt.get('description', []):
            if d.get('value') and d['value'] not in cwes:
                cwes.append(d['value'])

    products = []
    for config in cve.get('configurations', []):
        for node in config.get('nodes', []):
            for match in node.get('cpeMatch', []):
                criteria = match.get('criteria', '')
                if criteria and criteria not in products:
                    products.append(criteria)

    return {
        'cve_id': cve_id,
        'nvd_found': True,
        'nvd_description': first_text(cve.get('descriptions', [])),
        'nvd_cvss_version': version,
        'nvd_cvss_score': score,
        'nvd_cvss_severity': severity,
        'nvd_cvss_vector': vector,
        'nvd_cwe': '; '.join(cwes),
        'nvd_affected_products': '; '.join(products[:30]),
        'nvd_published': cve.get('published', ''),
        'nvd_last_modified': cve.get('lastModified', '')
    }


def fetch_nvd(session: requests.Session, cves: List[str], refresh: bool = False) -> pd.DataFrame:
    """Retrieve NVD records for unique CVEs, using local file cache."""
    NVD_CACHE.mkdir(parents=True, exist_ok=True)
    rows = []
    delay = 0.7 if NVD_API_KEY else 6.5
    headers = {'User-Agent': 'CyberPrior/1.0 academic vulnerability enrichment'}
    if NVD_API_KEY:
        headers['apiKey'] = NVD_API_KEY

    for i, cve in enumerate(cves, 1):
        path = NVD_CACHE / f'{cve}.json'
        if path.exists() and not refresh:
            data = json.loads(path.read_text(encoding='utf-8'))
            print(f'NVD {i}/{len(cves)} cached: {cve}')
        else:
            print(f'NVD {i}/{len(cves)} fetching: {cve}')
            data = get_json(session, NVD_URL, params={'cveId': cve}, headers=headers)
            path.write_text(json.dumps(data), encoding='utf-8')
            if i < len(cves):
                time.sleep(delay)
        rows.append(extract_nvd(cve, data))
    return pd.DataFrame(rows)


def fetch_epss(session: requests.Session, cves: List[str], refresh: bool = False) -> pd.DataFrame:
    """Retrieve EPSS scores and percentiles via bulk query."""
    CACHE.mkdir(parents=True, exist_ok=True)
    if EPSS_CACHE.exists() and not refresh:
        data = json.loads(EPSS_CACHE.read_text(encoding='utf-8'))
        print('EPSS loaded from cache')
    else:
        print('Fetching EPSS for all unique CVEs...')
        data = get_json(session, EPSS_URL, params={'cve': ','.join(cves)})
        EPSS_CACHE.write_text(json.dumps(data), encoding='utf-8')

    mapping = {}
    for row in data.get('data', []):
        mapping[row['cve']] = {
            'epss_score': float(row['epss']) if row.get('epss') else None,
            'epss_percentile': float(row['percentile']) if row.get('percentile') else None,
            'epss_date': row.get('date', '')
        }
    return pd.DataFrame([
        {'cve_id': cve, **mapping.get(cve, {'epss_score': None, 'epss_percentile': None, 'epss_date': ''})}
        for cve in cves
    ])


def fetch_kev(session: requests.Session, cves: List[str], refresh: bool = False) -> pd.DataFrame:
    """Download or load CISA Known Exploited Vulnerabilities catalog and match against CVEs."""
    CACHE.mkdir(parents=True, exist_ok=True)
    if KEV_CACHE.exists() and not refresh:
        data = json.loads(KEV_CACHE.read_text(encoding='utf-8'))
        print('CISA KEV loaded from cache')
    else:
        print('Fetching CISA KEV catalog...')
        data = get_json(session, KEV_URL)
        KEV_CACHE.write_text(json.dumps(data), encoding='utf-8')

    mapping = {item.get('cveID'): item for item in data.get('vulnerabilities', [])}
    rows = []
    for cve in cves:
        item = mapping.get(cve)
        if item:
            rows.append({
                'cve_id': cve,
                'cisa_kev': True,
                'cisa_vendor_project': item.get('vendorProject', ''),
                'cisa_product': item.get('product', ''),
                'cisa_vulnerability_name': item.get('vulnerabilityName', ''),
                'cisa_date_added': item.get('dateAdded', ''),
                'cisa_due_date': item.get('dueDate', ''),
                'cisa_required_action': item.get('requiredAction', ''),
                'cisa_ransomware_use': item.get('knownRansomwareCampaignUse', '')
            })
        else:
            rows.append({
                'cve_id': cve, 'cisa_kev': False,
                'cisa_vendor_project': '', 'cisa_product': '',
                'cisa_vulnerability_name': '', 'cisa_date_added': '',
                'cisa_due_date': '', 'cisa_required_action': '',
                'cisa_ransomware_use': ''
            })
    return pd.DataFrame(rows)


def main(refresh_intelligence: bool = False) -> None:
    """Execute the Objective 1 enrichment pipeline end-to-end."""
    if not INPUT.is_file():
        raise FileNotFoundError(f'Input file not found: {INPUT.resolve()}')

    df = pd.read_csv(INPUT)
    required = {
        'asset_id', 'asset', 'cve_id', 'criticality',
        'exposure', 'data_sensitivity', 'control_effectiveness'
    }
    missing = required - set(df.columns)
    if missing:
        raise ValueError(f'Missing required columns: {sorted(missing)}')

    df['cve_id'] = df['cve_id'].astype(str).str.strip().str.upper()
    cves = sorted(df.loc[df['cve_id'].str.startswith('CVE-'), 'cve_id'].dropna().unique())
    print(f'Input file: {INPUT.resolve()}')
    print(f'Input rows: {len(df)}')
    print(f'Unique CVEs: {len(cves)}')

    with requests.Session() as session:
        nvd = fetch_nvd(session, cves, refresh=refresh_intelligence)
        epss = fetch_epss(session, cves, refresh=refresh_intelligence)
        kev = fetch_kev(session, cves, refresh=refresh_intelligence)

    enrichment = nvd.merge(epss, on='cve_id', how='left').merge(kev, on='cve_id', how='left')
    out = df.merge(enrichment, on='cve_id', how='left', validate='many_to_one')

    # Provenance fields ensure academic reproducibility and data auditability
    out['nvd_source'] = NVD_URL
    out['epss_source'] = EPSS_URL
    out['cisa_kev_source'] = KEV_URL
    out['enrichment_status'] = out.apply(
        lambda r: 'complete' if bool(r['nvd_found']) and pd.notna(r['epss_score']) and pd.notna(r['cisa_kev']) else 'partial',
        axis=1
    )

    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    out.to_csv(OUTPUT_CSV, index=False)
    try:
        out.to_excel(OUTPUT_XLSX, index=False)
    except Exception as e:
        print(f'Excel export skipped: {e}')

    print('\nDONE')
    print(f'Rows preserved: {len(out)}')
    print(f'Columns: {len(out.columns)}')
    print(f'Output CSV: {OUTPUT_CSV.resolve()}')
    print(f'Output Excel: {OUTPUT_XLSX.resolve()}')
    print(f'Complete enrichment rows: {(out["enrichment_status"] == "complete").sum()}')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Enrich asset-vulnerability records with NVD, EPSS, and CISA KEV data.')
    parser.add_argument('--refresh-intelligence', action='store_true', help='bypass local caches and retrieve current NVD, EPSS, and KEV records')
    main(refresh_intelligence=parser.parse_args().refresh_intelligence)

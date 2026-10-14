"""CyberPrior - Feature Preprocessing & Engineering Module

Prepares raw and threat-enriched vulnerability asset records for Machine Learning
classification by:
1. Encoding categorical features (Criticality, Exposure, Data Sensitivity, Controls)
2. Handling missing or null threat intelligence values
3. Splitting into stratified train/test sets to prevent data leakage
4. Applying feature scaling for linear models
"""

from typing import Dict, List, Optional, Tuple
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

# Standard ordinal & binary encodings for risk attributes
CRITICALITY_ENCODING: Dict[str, int] = {'Low': 1, 'Medium': 2, 'High': 3, 'Critical': 4}
EXPOSURE_ENCODING: Dict[str, int] = {'Internal': 0, 'External': 1}
SENSITIVITY_ENCODING: Dict[str, int] = {'Low': 1, 'Medium': 2, 'High': 3, 'Critical': 4}
CONTROL_ENCODING: Dict[str, int] = {'Low': 1, 'Medium': 2, 'High': 3}

# Canonical feature list for ML risk classification
FEATURE_COLUMNS: List[str] = [
    'cvss_score',
    'epss_score',
    'cisa_kev',
    'criticality',
    'exposure',
    'data_sensitivity',
    'control_effectiveness'
]


def extract_features(df: pd.DataFrame) -> pd.DataFrame:
    """Transform dataset into numeric feature matrix X without data leakage."""
    X = pd.DataFrame(index=df.index)

    # Technical threat intelligence features
    X['cvss_score'] = pd.to_numeric(df.get('nvd_cvss_score'), errors='coerce').fillna(5.0)
    X['epss_score'] = pd.to_numeric(df.get('epss_score'), errors='coerce').fillna(0.0)
    X['cisa_kev'] = df.get('cisa_kev', False).astype(bool).astype(int)

    # Organizational context features (ordinal encodings)
    X['criticality'] = df['criticality'].map(CRITICALITY_ENCODING).fillna(2)
    X['exposure'] = df['exposure'].map(EXPOSURE_ENCODING).fillna(0)
    X['data_sensitivity'] = df['data_sensitivity'].map(SENSITIVITY_ENCODING).fillna(2)
    X['control_effectiveness'] = df['control_effectiveness'].map(CONTROL_ENCODING).fillna(2)

    return X[FEATURE_COLUMNS]


def prepare_ml_data(
    df: pd.DataFrame,
    target_column: str = 'residual_risk_level',
    test_size: float = 0.20,
    random_state: int = 42
) -> Tuple[pd.DataFrame, pd.DataFrame, pd.Series, pd.Series, StandardScaler]:
    """Prepare stratified train and test datasets, along with a fitted standard scaler."""
    if target_column not in df.columns:
        raise KeyError(f'Target column "{target_column}" not found in dataframe.')

    X = extract_features(df)
    y = df[target_column].astype(str)

    # Stratified split ensures all risk categories are proportionally represented in train and test
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, random_state=random_state, stratify=y
    )

    # Fit scaler strictly on training data to prevent data leakage
    scaler = StandardScaler()
    scaler.fit(X_train)

    return X_train, X_test, y_train, y_test, scaler

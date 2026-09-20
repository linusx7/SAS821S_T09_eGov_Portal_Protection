"""
Feature engineering module for creating ML-ready features.
"""

import pandas as pd
import numpy as np
import math
from collections import Counter
from sklearn.model_selection import train_test_split
import logging
import os

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

SCANNING_PATHS = ['/admin', '/.env', '/backup', '/wp-admin', '/config', '/phpmyadmin', '/debug', '/.git']

def compute_shannon_entropy(values: list) -> float:
    """Computes Shannon entropy for a list of values."""
    if not values:
        return 0.0
    counts = Counter(values)
    total = len(values)
    entropy = -sum((count/total) * math.log2(count/total) for count in counts.values())
    return entropy

def compute_user_agent_entropy(user_agents: list) -> float:
    """Wrapper to compute entropy for user agents."""
    return compute_shannon_entropy(user_agents)

def get_feature_names() -> list:
    """Returns list of feature column names."""
    return [
        'request_rate_1min', 'request_rate_5min', 'failed_login_ratio',
        'unique_endpoints_accessed', 'user_agent_entropy', 'url_path_entropy',
        'avg_response_time_ms', 'bytes_sent_std', 'status_4xx_ratio',
        'status_5xx_ratio', 'off_hours_flag', 'distinct_countries',
        'payload_variance', 'max_rows_returned', 'is_scanning_pattern'
    ]

def compute_session_features(waf_df: pd.DataFrame, api_df: pd.DataFrame, auth_df: pd.DataFrame) -> pd.DataFrame:
    """
    Computes session/IP-level features aggregated per src_ip per 5-minute window.
    """
    logger.info("Computing session features...")
    
    waf_df['timestamp_5m'] = pd.to_datetime(waf_df['timestamp']).dt.floor('5min')
    api_df['timestamp_5m'] = pd.to_datetime(api_df['timestamp']).dt.floor('5min')
    auth_df['timestamp_5m'] = pd.to_datetime(auth_df['timestamp']).dt.floor('5min')
    
    def waf_features(g):
        n = len(g)
        return pd.Series({
            'request_rate_1min': n / 5.0,
            'request_rate_5min': n,
            'unique_endpoints_accessed': g['url_path'].nunique(),
            'user_agent_entropy': compute_shannon_entropy(g['user_agent'].tolist()),
            'url_path_entropy': compute_shannon_entropy(g['url_path'].tolist()),
            'bytes_sent_std': g['bytes_sent'].std() if n > 1 else 0,
            'status_4xx_ratio': sum((g['status_code'] >= 400) & (g['status_code'] < 500)) / n if n > 0 else 0,
            'status_5xx_ratio': sum((g['status_code'] >= 500) & (g['status_code'] < 600)) / n if n > 0 else 0,
            'is_scanning_pattern': 1 if any(p in str(path) for path in g['url_path'].dropna() for p in SCANNING_PATHS) else 0,
            'label': 1 if any(g['attack_type'] != 'BENIGN') else 0
        })

    def api_features(g):
        return pd.Series({
            'avg_response_time_ms': g['response_time_ms'].mean(),
            'payload_variance': g['request_payload_bytes'].var() if len(g) > 1 else 0
        })

    def auth_features(g):
        login_events = g[g['auth_event'].isin(['LOGIN_FAILED', 'LOGIN_SUCCESS', 'LOGIN'])]
        n_logins = len(login_events)
        return pd.Series({
            'failed_login_ratio': sum(login_events['auth_event'] == 'LOGIN_FAILED') / n_logins if n_logins > 0 else 0,
            'distinct_countries': g['geo_country'].nunique(),
            'max_rows_returned': g['rows_returned'].max()
        })

    waf_agg = waf_df.groupby(['src_ip', 'timestamp_5m']).apply(waf_features).reset_index()
    api_agg = api_df.groupby(['src_ip', 'timestamp_5m']).apply(api_features).reset_index()
    auth_agg = auth_df.groupby(['src_ip', 'timestamp_5m']).apply(auth_features).reset_index()
    
    df = pd.merge(waf_agg, api_agg, on=['src_ip', 'timestamp_5m'], how='outer')
    df = pd.merge(df, auth_agg, on=['src_ip', 'timestamp_5m'], how='outer')
    
    df.fillna(0, inplace=True)
    df['off_hours_flag'] = df['timestamp_5m'].dt.hour.apply(lambda h: 1 if h >= 22 or h < 6 else 0)
    
    return df

def create_training_dataset(feature_df: pd.DataFrame, labels: pd.Series) -> tuple:
    """Creates X and y with stratified split."""
    X = feature_df[get_feature_names()].fillna(0)
    y = labels
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, stratify=y, random_state=42)
    return X_train, X_test, y_train, y_test

if __name__ == '__main__':
    base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    data_dir = os.path.join(base_dir, 'data')
    raw_dir = os.path.join(data_dir, 'raw')
    proc_dir = os.path.join(data_dir, 'processed')
    os.makedirs(proc_dir, exist_ok=True)
    
    logger.info("Loading raw datasets...")
    waf_df = pd.read_csv(os.path.join(raw_dir, 'web_waf_logs.csv'))
    api_df = pd.read_csv(os.path.join(raw_dir, 'api_gateway_logs.csv'))
    auth_df = pd.read_csv(os.path.join(raw_dir, 'auth_db_audit_logs.csv'))
    
    features_df = compute_session_features(waf_df, api_df, auth_df)
    
    out_path = os.path.join(proc_dir, 'ml_features.csv')
    features_df.to_csv(out_path, index=False)
    logger.info(f"Saved {len(features_df)} feature rows to {out_path}")
    logger.info(f"Label distribution: {features_df['label'].value_counts().to_dict()}")

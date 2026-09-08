"""
Feature engineering module for creating ML-ready features.
"""

import pandas as pd
import numpy as np
import math
from collections import Counter
from sklearn.model_selection import train_test_split
import logging

logger = logging.getLogger(__name__)

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

def compute_session_features(feature_store_df: pd.DataFrame) -> pd.DataFrame:
    """
    Computes session/IP-level features aggregated per src_ip per 5-minute window.
    Assumes feature_store_df contains necessary raw columns or is joined with raw data.
    """
    logger.info("Computing session features...")
    df = feature_store_df.copy()
    if df.empty or 'timestamp' not in df.columns:
        return pd.DataFrame()
        
    df.set_index('timestamp', inplace=True)
    
    grouped = df.groupby(['src_ip', pd.Grouper(freq='5T')])
    
    features = []
    for (src_ip, timestamp), group in grouped:
        feat = {
            'src_ip': src_ip,
            'timestamp': timestamp,
            'request_rate_1min': len(group) / 5.0,
            'request_rate_5min': len(group),
            'failed_login_ratio': np.random.rand(), # Mock value, requires proper auth join
            'unique_endpoints_accessed': group.get('event_id', pd.Series([])).nunique(),
            'user_agent_entropy': compute_shannon_entropy(group.get('user_agent', ['UNKNOWN']).tolist()),
            'url_path_entropy': compute_shannon_entropy(group.get('url_path', ['UNKNOWN']).tolist()),
            'avg_response_time_ms': group.get('response_time_ms', pd.Series([0])).mean() if 'response_time_ms' in group else 0,
            'bytes_sent_std': group.get('bytes_sent', pd.Series([0])).std() if 'bytes_sent' in group else 0,
            'status_4xx_ratio': 0.0, # Mock value
            'status_5xx_ratio': 0.0, # Mock value
            'off_hours_flag': 1 if timestamp.hour >= 22 or timestamp.hour < 6 else 0,
            'distinct_countries': group.get('geo_country', pd.Series([])).nunique() if 'geo_country' in group else 1,
            'payload_variance': group.get('request_payload_bytes', pd.Series([0])).var() if 'request_payload_bytes' in group else 0,
            'max_rows_returned': group.get('rows_returned', pd.Series([0])).max() if 'rows_returned' in group else 0,
            'is_scanning_pattern': 0 # Mock value
        }
        features.append(feat)
        
    features_df = pd.DataFrame(features)
    logger.info(f"Computed features for {len(features_df)} windows.")
    return features_df

def get_feature_names() -> list:
    """Returns list of feature column names."""
    return [
        'request_rate_1min', 'request_rate_5min', 'failed_login_ratio',
        'unique_endpoints_accessed', 'user_agent_entropy', 'url_path_entropy',
        'avg_response_time_ms', 'bytes_sent_std', 'status_4xx_ratio',
        'status_5xx_ratio', 'off_hours_flag', 'distinct_countries',
        'payload_variance', 'max_rows_returned', 'is_scanning_pattern'
    ]

def create_training_dataset(feature_df: pd.DataFrame, labels: pd.Series) -> tuple:
    """Creates X and y with stratified split."""
    X = feature_df[get_feature_names()].fillna(0)
    y = labels
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, stratify=y, random_state=42)
    return X_train, X_test, y_train, y_test

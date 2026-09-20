"""
ETL pipeline for SAS821S e-Gov Portal Protection Project.
"""

import os
import pandas as pd
import numpy as np
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def load_raw_data(data_dir: str) -> dict:
    """Loads raw data from CSV and JSON files."""
    data = {}
    try:
        data['web_waf'] = pd.read_csv(os.path.join(data_dir, 'web_waf_logs.csv'))
        data['api'] = pd.read_csv(os.path.join(data_dir, 'api_gateway_logs.csv'))
        data['auth'] = pd.read_csv(os.path.join(data_dir, 'auth_db_audit_logs.csv'))
        data['complaints'] = pd.read_json(os.path.join(data_dir, 'citizen_complaints.json'))
        logger.info("Successfully loaded raw data.")
    except Exception as e:
        logger.error(f"Error loading data: {e}")
    return data

def clean_web_waf_logs(df: pd.DataFrame) -> pd.DataFrame:
    """Cleans Web WAF logs."""
    df = df.copy()
    if 'timestamp' in df.columns:
        df['timestamp'] = pd.to_datetime(df['timestamp'], utc=True)
    df.fillna({'status_code': 0, 'bytes_sent': 0, 'user_agent': 'UNKNOWN', 'url_path': 'UNKNOWN', 'http_method': 'UNKNOWN'}, inplace=True)
    if 'timestamp' in df.columns:
        df['timestamp'] = df['timestamp'].ffill()
    return df

def clean_api_logs(df: pd.DataFrame) -> pd.DataFrame:
    """Cleans API logs."""
    df = df.copy()
    if 'timestamp' in df.columns:
        df['timestamp'] = pd.to_datetime(df['timestamp'], utc=True)
    df.fillna({'http_status': 0, 'request_payload_bytes': 0, 'response_time_ms': 0, 'endpoint': 'UNKNOWN', 'token_id': 'UNKNOWN'}, inplace=True)
    if 'timestamp' in df.columns:
        df['timestamp'] = df['timestamp'].ffill()
    return df

def clean_auth_logs(df: pd.DataFrame) -> pd.DataFrame:
    """Cleans Authentication DB audit logs."""
    df = df.copy()
    if 'timestamp' in df.columns:
        df['timestamp'] = pd.to_datetime(df['timestamp'], utc=True)
    df.fillna({'rows_returned': 0, 'db_execution_ms': 0, 'db_query': 'UNKNOWN', 'auth_event': 'UNKNOWN', 'geo_country': 'UNKNOWN', 'geo_city': 'UNKNOWN'}, inplace=True)
    if 'timestamp' in df.columns:
        df['timestamp'] = df['timestamp'].ffill()
    return df

def clean_complaints(df: pd.DataFrame) -> pd.DataFrame:
    """Cleans Citizen complaints."""
    df = df.copy()
    if 'timestamp' in df.columns:
        df['timestamp'] = pd.to_datetime(df['timestamp'], utc=True)
    df.fillna({'complaint_text': 'UNKNOWN', 'category': 'UNKNOWN', 'urgency_level': 'UNKNOWN'}, inplace=True)
    if 'timestamp' in df.columns:
        df['timestamp'] = df['timestamp'].ffill()
    return df

def build_feature_store(waf_df: pd.DataFrame, api_df: pd.DataFrame, auth_df: pd.DataFrame) -> pd.DataFrame:
    """Builds the unified feature store by merging logs on session_id and src_ip."""
    logger.info("Building feature store...")
    
    waf_subset = waf_df[['timestamp', 'session_id', 'src_ip', 'event_id']].copy() if not waf_df.empty else pd.DataFrame(columns=['timestamp', 'session_id', 'src_ip', 'event_id'])
    waf_subset['source'] = 'waf'
    api_subset = api_df[['timestamp', 'session_id', 'src_ip', 'event_id']].copy() if not api_df.empty else pd.DataFrame(columns=['timestamp', 'session_id', 'src_ip', 'event_id'])
    api_subset['source'] = 'api'
    auth_subset = auth_df[['timestamp', 'src_ip', 'event_id', 'citizen_id']].copy() if not auth_df.empty else pd.DataFrame(columns=['timestamp', 'src_ip', 'event_id', 'citizen_id'])
    auth_subset['source'] = 'auth'
    auth_subset['session_id'] = 'UNKNOWN'

    feature_store = pd.concat([waf_subset, api_subset, auth_subset], ignore_index=True)
    if not feature_store.empty and 'timestamp' in feature_store.columns:
        feature_store.sort_values(by='timestamp', inplace=True)
    logger.info(f"Feature store built with {len(feature_store)} records.")
    return feature_store

def run_etl_pipeline(raw_dir: str, output_dir: str) -> pd.DataFrame:
    """Runs the complete ETL pipeline."""
    data = load_raw_data(raw_dir)
    if not data:
        return pd.DataFrame()
        
    waf_df = clean_web_waf_logs(data.get('web_waf', pd.DataFrame()))
    api_df = clean_api_logs(data.get('api', pd.DataFrame()))
    auth_df = clean_auth_logs(data.get('auth', pd.DataFrame()))
    
    feature_store = build_feature_store(waf_df, api_df, auth_df)
    
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, 'security_feature_store.csv')
    if not feature_store.empty:
        feature_store.to_csv(output_path, index=False)
        logger.info(f"Saved feature store to {output_path}")
        
        print("=== Data Quality Report ===")
        print(f"Total Records: {len(feature_store)}")
        print(f"Null Percentages:\n{feature_store.isnull().mean() * 100}")
        print(f"Duplicates: {feature_store.duplicated().sum()}")
    
    return feature_store

if __name__ == '__main__':
    run_etl_pipeline('data/raw', 'data/processed')

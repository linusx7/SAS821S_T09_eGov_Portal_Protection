"""
User and Entity Behavior Analytics (UEBA) Anomaly Detector.
"""
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
import math
import matplotlib.pyplot as plt
import seaborn as sns
import logging

logger = logging.getLogger(__name__)

class UEBADetector:
    def __init__(self, contamination=0.1, random_state=42):
        self.contamination = contamination
        self.random_state = random_state
        self.model = IsolationForest(contamination=self.contamination, random_state=self.random_state)
        self.anomaly_scores = None

    def fit(self, X: pd.DataFrame):
        """Fits Isolation Forest on normal behavior features."""
        self.model.fit(X)

    def detect_anomalies(self, X: pd.DataFrame) -> tuple:
        """Returns anomaly scores and labels (-1 for anomaly, 1 for normal)."""
        labels = self.model.predict(X)
        self.anomaly_scores = self.model.decision_function(X)
        return self.anomaly_scores, labels

    def compute_haversine_distance(self, lat1, lon1, lat2, lon2) -> float:
        """Calculates distance between two points on Earth in km."""
        if pd.isna(lat1) or pd.isna(lon1) or pd.isna(lat2) or pd.isna(lon2):
            return 0.0
        r = 6371 # Earth radius in km
        phi1, phi2 = math.radians(lat1), math.radians(lat2)
        dphi = math.radians(lat2 - lat1)
        dlambda = math.radians(lon2 - lon1)
        
        a = math.sin(dphi/2)**2 + math.cos(phi1) * math.cos(phi2) * math.sin(dlambda/2)**2
        c = 2 * math.atan2(math.sqrt(a), math.sqrt(1-a))
        return r * c

    def detect_impossible_travel(self, auth_df: pd.DataFrame) -> pd.DataFrame:
        """Detects impossible travel between consecutive logins > 900 km/h."""
        df = auth_df.copy()
        if df.empty or 'latitude' not in df.columns or 'longitude' not in df.columns:
            df['impossible_travel_flag'] = 0
            df['travel_speed_kmh'] = 0.0
            return df
            
        df['timestamp'] = pd.to_datetime(df['timestamp'], utc=True)
        df.sort_values(by=['citizen_id', 'timestamp'], inplace=True)
        
        df['prev_lat'] = df.groupby('citizen_id')['latitude'].shift(1)
        df['prev_lon'] = df.groupby('citizen_id')['longitude'].shift(1)
        df['prev_time'] = df.groupby('citizen_id')['timestamp'].shift(1)
        
        def calc_speed(row):
            if pd.isna(row['prev_lat']) or pd.isna(row['prev_time']):
                return 0.0
            dist = self.compute_haversine_distance(row['latitude'], row['longitude'], row['prev_lat'], row['prev_lon'])
            time_diff_hours = (row['timestamp'] - row['prev_time']).total_seconds() / 3600.0
            if time_diff_hours <= 0:
                return float('inf') if dist > 0 else 0.0
            return dist / time_diff_hours
            
        df['travel_speed_kmh'] = df.apply(calc_speed, axis=1)
        df['impossible_travel_flag'] = (df['travel_speed_kmh'] > 900).astype(int)
        
        return df

    def build_user_baseline(self, auth_df: pd.DataFrame) -> pd.DataFrame:
        """Builds per-user behavioral baseline."""
        df = auth_df.copy()
        if df.empty or 'citizen_id' not in df.columns:
            return pd.DataFrame()
        df['timestamp'] = pd.to_datetime(df['timestamp'], utc=True)
        df['hour'] = df['timestamp'].dt.hour
        
        baselines = []
        for citizen_id, group in df.groupby('citizen_id'):
            days = max(1, (group['timestamp'].max() - group['timestamp'].min()).days)
            baseline = {
                'citizen_id': citizen_id,
                'avg_logins_per_day': len(group) / days,
                'typical_hour_mean': group['hour'].mean(),
                'typical_hour_std': group['hour'].std(),
                'unique_cities': group['geo_city'].nunique() if 'geo_city' in group.columns else 0
            }
            baselines.append(baseline)
        return pd.DataFrame(baselines)

    def detect_off_hours_access(self, auth_df: pd.DataFrame) -> pd.DataFrame:
        """Detects off-hours access (22:00-06:00 UTC)."""
        df = auth_df.copy()
        if df.empty:
            return df
        df['timestamp'] = pd.to_datetime(df['timestamp'], utc=True)
        df['hour'] = df['timestamp'].dt.hour
        df['off_hours_flag'] = ((df['hour'] >= 22) | (df['hour'] < 6)).astype(int)
        return df

    def detect_privilege_escalation(self, auth_df: pd.DataFrame) -> pd.DataFrame:
        """Detects privilege escalation based on db_query keywords."""
        df = auth_df.copy()
        suspicious_keywords = ['GRANT', 'ALTER', 'DROP', 'UPDATE PG_AUTHID']
        df['privilege_escalation_flag'] = 0
        if 'db_query' in df.columns:
            mask = df['db_query'].str.upper().apply(lambda x: any(k in str(x) for k in suspicious_keywords) if pd.notna(x) else False)
            df.loc[mask, 'privilege_escalation_flag'] = 1
        return df

    def get_anomaly_scores(self) -> np.ndarray:
        return self.anomaly_scores

    def plot_anomaly_distribution(self, save_path=None):
        if self.anomaly_scores is None:
            return
        plt.figure(figsize=(8, 5))
        sns.histplot(self.anomaly_scores, bins=50, kde=True)
        plt.title('Anomaly Score Distribution')
        plt.xlabel('Anomaly Score')
        plt.ylabel('Frequency')
        if save_path:
            plt.savefig(save_path)
            plt.close()
        else:
            plt.show()

    def plot_impossible_travel_map(self, flagged_df: pd.DataFrame, save_path=None):
        plt.figure(figsize=(10, 6))
        if 'impossible_travel_flag' in flagged_df.columns:
            anomalies = flagged_df[flagged_df['impossible_travel_flag'] == 1]
            if not anomalies.empty:
                sns.scatterplot(x='longitude', y='latitude', hue='citizen_id', data=anomalies)
        plt.title('Impossible Travel Events (Lat/Lon)')
        if save_path:
            plt.savefig(save_path)
            plt.close()
        else:
            plt.show()

if __name__ == '__main__':
    import os
    import json
    
    PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
    RAW_DIR = os.path.join(PROJECT_ROOT, 'data', 'raw')
    PROCESSED_DIR = os.path.join(PROJECT_ROOT, 'data', 'processed')
    
    os.makedirs(PROCESSED_DIR, exist_ok=True)
    
    auth_df = pd.read_csv(os.path.join(RAW_DIR, 'auth_db_audit_logs.csv'))
    api_df = pd.read_csv(os.path.join(RAW_DIR, 'api_gateway_logs.csv'))
    
    detector = UEBADetector(contamination=0.05)
    
    impossible_travel = detector.detect_impossible_travel(auth_df)
    off_hours = detector.detect_off_hours_access(auth_df)
    priv_escalation = detector.detect_privilege_escalation(auth_df)
    user_baselines = detector.build_user_baseline(auth_df)
    
    api_numeric = api_df[['src_ip', 'request_payload_bytes', 'response_time_ms', 'http_status']].copy()
    api_features = api_numeric.groupby('src_ip').mean().fillna(0)
    
    detector.fit(api_features)
    scores, labels = detector.detect_anomalies(api_features)
    
    def default_serializer(obj):
        if isinstance(obj, pd.Timestamp):
            return str(obj)
        if isinstance(obj, np.integer):
            return int(obj)
        if isinstance(obj, np.floating):
            return float(obj)
        if isinstance(obj, np.ndarray):
            return obj.tolist()
        if pd.isna(obj):
            return None
        return str(obj)
        
    it_cols = ['citizen_id', 'timestamp', 'travel_speed_kmh', 'src_ip', 'geo_country', 'geo_city', 'latitude', 'longitude']
    available_cols = [c for c in it_cols if c in impossible_travel.columns]
    it_events = impossible_travel[impossible_travel['impossible_travel_flag'] == 1][available_cols].to_dict('records')
    oh_events = off_hours[off_hours['off_hours_flag'] == 1].to_dict('records')
    pe_events = priv_escalation[priv_escalation['privilege_escalation_flag'] == 1].to_dict('records')
    
    results = {
        'impossible_travel_events': [{k: v for k, v in e.items() if pd.notna(v)} for e in it_events],
        'off_hours_events': {
            'count': len(oh_events),
            'events': [{k: v for k, v in e.items() if pd.notna(v)} for e in oh_events]
        },
        'privilege_escalation_events': {
            'count': len(pe_events),
            'events': [{k: v for k, v in e.items() if pd.notna(v)} for e in pe_events]
        },
        'anomaly_scores': scores.tolist(),
        'anomaly_labels': labels.tolist(),
        'user_baselines': [{k: v for k, v in e.items() if pd.notna(v)} for e in user_baselines.to_dict('records')],
        'total_anomalies_detected': int(sum(labels == -1)),
        'contamination_rate': detector.contamination
    }
    
    with open(os.path.join(PROCESSED_DIR, 'ueba_results.json'), 'w') as f:
        json.dump(results, f, default=default_serializer, indent=2)
        
    print(f"UEBA Anomaly Detection Complete. Found {results['total_anomalies_detected']} anomalies.")

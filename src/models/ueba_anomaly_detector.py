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

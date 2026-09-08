"""
UEBA & Access Analytics View component.
Displays user behavior, geo anomalies and impossible travel.
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import numpy as np

def render(data_dict: dict):
    st.header("UEBA & Access Analytics")
    
    if 'auth_db_audit_logs' not in data_dict or data_dict['auth_db_audit_logs'].empty:
        st.warning("No Auth DB Audit Logs available.")
        return
        
    df = data_dict['auth_db_audit_logs'].copy()
    
    if 'timestamp' in df.columns:
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        df['hour'] = df['timestamp'].dt.hour
        df['day_of_week'] = df['timestamp'].dt.day_name()
    
    # Mock data for geo if missing
    if 'latitude' not in df.columns or 'longitude' not in df.columns:
        df['latitude'] = np.random.uniform(-90, 90, len(df))
        df['longitude'] = np.random.uniform(-180, 180, len(df))
    if 'is_impossible_travel' not in df.columns:
        df['is_impossible_travel'] = np.random.choice([True, False], len(df), p=[0.05, 0.95])
        
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.subheader("Global Access & Anomaly Map")
        fig_map = px.scatter_geo(
            df, lat='latitude', lon='longitude', 
            color='is_impossible_travel',
            color_discrete_map={True: 'red', False: 'blue'},
            hover_name='citizen_id',
            title='Login Locations (Red = Impossible Travel)',
            projection="natural earth"
        )
        st.plotly_chart(fig_map, use_container_width=True)

    with col2:
        st.subheader("Impossible Travel Alerts")
        alerts = df[df['is_impossible_travel'] == True]
        if not alerts.empty:
            display_alerts = alerts[['citizen_id', 'src_ip', 'geo_country']].head(10)
            st.dataframe(display_alerts, use_container_width=True)
        else:
            st.info("No impossible travel detected.")
            
        st.subheader("Anomaly Score Distribution")
        # Mock score
        scores = np.random.normal(30, 15, len(df))
        scores = np.clip(scores, 0, 100)
        fig_score = px.histogram(x=scores, nbins=20, labels={'x': 'UEBA Anomaly Score'}, title="Score Distribution")
        st.plotly_chart(fig_score, use_container_width=True)

    st.subheader("Off-hours Access Patterns")
    if 'hour' in df.columns and 'day_of_week' in df.columns:
        pivot = df.groupby(['day_of_week', 'hour']).size().reset_index(name='count')
        days_order = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
        
        # Ensure complete matrix for heatmap
        all_combos = pd.MultiIndex.from_product([days_order, range(24)], names=['day_of_week', 'hour']).to_frame(index=False)
        pivot = pd.merge(all_combos, pivot, on=['day_of_week', 'hour'], how='left').fillna(0)
        
        heatmap_data = pivot.pivot(index='day_of_week', columns='hour', values='count').reindex(days_order)
        
        fig_heat = px.imshow(heatmap_data, labels=dict(x="Hour of Day", y="Day of Week", color="Access Count"),
                             title="Access Heatmap", aspect="auto")
        st.plotly_chart(fig_heat, use_container_width=True)

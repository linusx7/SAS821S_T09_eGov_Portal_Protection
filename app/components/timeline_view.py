"""
Incident Timeline View component.
Displays attack timelines and entity correlations.
"""

import streamlit as st
import pandas as pd
import plotly.express as px

def render(data_dict: dict):
    st.header("Incident Timeline & Correlation")
    
    if 'api_gateway_logs' not in data_dict or data_dict['api_gateway_logs'].empty:
        st.warning("No data available for timeline view.")
        return
        
    df = data_dict['api_gateway_logs'].copy()
    if 'timestamp' in df.columns:
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        df = df.sort_values('timestamp')
        
    # Assume some basic anomalies
    if 'is_anomalous_scraping' in df.columns:
        anomalies = df[df['is_anomalous_scraping'] == True]
    else:
        # Mock anomalies for display
        anomalies = df.sample(frac=0.1)

    st.subheader("Interactive Attack Timeline")
    
    # Scatter plot over time
    if not anomalies.empty:
        fig = px.scatter(anomalies, x='timestamp', y='endpoint', color='src_ip', 
                         title='Anomalous Activity Timeline',
                         hover_data=['citizen_id', 'response_time_ms'])
        st.plotly_chart(fig, use_container_width=True)
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("Entity Correlation")
        entity_type = st.radio("Select Entity Type to correlate", ["Source IP", "Citizen ID"])
        
        if entity_type == "Source IP":
            top_entity = anomalies['src_ip'].value_counts().head(5).index
            selected = st.selectbox("Select IP", top_entity) if len(top_entity) > 0 else None
            if selected:
                correlated = df[df['src_ip'] == selected]
                st.dataframe(correlated[['timestamp', 'endpoint', 'citizen_id', 'http_status']].head(10))
        else:
            top_entity = anomalies['citizen_id'].value_counts().head(5).index
            selected = st.selectbox("Select Citizen ID", top_entity) if len(top_entity) > 0 else None
            if selected:
                correlated = df[df['citizen_id'] == selected]
                st.dataframe(correlated[['timestamp', 'endpoint', 'src_ip', 'http_status']].head(10))

    with col2:
        st.subheader("Incident Response Status")
        # Mock IR tracker
        ir_status = pd.DataFrame({
            'Incident ID': ['INC-001', 'INC-002', 'INC-003'],
            'Severity': ['High', 'Medium', 'Critical'],
            'Status': ['Investigating', 'Mitigated', 'Open'],
            'Affected Entities': [12, 4, 156]
        })
        st.dataframe(ir_status, use_container_width=True)

"""
SOC Threat Triage View component for Streamlit dashboard.
Displays real-time style event table and risk analysis.
"""

import streamlit as st
import pandas as pd
import plotly.express as px

def render(data_dict: dict):
    """
    Render the SOC Triage View.
    
    Args:
        data_dict: Dictionary containing raw and processed dataframes.
    """
    st.header("SOC Threat Triage Dashboard")
    st.markdown("Real-time monitoring and TTAPR recommendations based on risk scores.")

    if 'api_gateway_logs' not in data_dict or data_dict['api_gateway_logs'].empty:
        st.warning("No API Gateway Logs available.")
        return

    df = data_dict['api_gateway_logs'].copy()
    
    # Mock some risk scores and actions if not present in the dataset
    if 'risk_score' not in df.columns:
        import numpy as np
        np.random.seed(42)
        df['risk_score'] = np.random.randint(0, 100, size=len(df))
        
    def determine_action(score):
        if score < 30: return "Allow"
        elif score < 60: return "MFA"
        elif score < 80: return "Rate-Limit"
        else: return "Terminate"
        
    df['Recommended_Action'] = df['risk_score'].apply(determine_action)

    col1, col2 = st.columns([2, 1])

    with col1:
        st.subheader("Recent Security Events")
        # Display top 50 recent events
        display_df = df[['timestamp', 'src_ip', 'citizen_id', 'endpoint', 'risk_score', 'Recommended_Action']].head(50)
        
        def color_risk(val):
            if isinstance(val, int) or isinstance(val, float):
                if val >= 80: return 'color: red'
                elif val >= 60: return 'color: orange'
                elif val >= 30: return 'color: yellow'
                else: return 'color: green'
            return ''
            
        st.dataframe(display_df.style.map(color_risk, subset=['risk_score']), use_container_width=True)

    with col2:
        st.subheader("Risk Score Distribution")
        fig = px.histogram(df, x='risk_score', nbins=20, 
                           color='Recommended_Action',
                           color_discrete_map={
                               'Allow': 'green', 'MFA': 'yellow', 
                               'Rate-Limit': 'orange', 'Terminate': 'red'
                           },
                           title="Events by Risk Level")
        fig.update_layout(showlegend=False, margin=dict(l=0, r=0, t=30, b=0))
        st.plotly_chart(fig, use_container_width=True)
        
        st.subheader("Action Recommendations")
        action_counts = df['Recommended_Action'].value_counts().reset_index()
        action_counts.columns = ['Action', 'Count']
        st.dataframe(action_counts, use_container_width=True)

    st.subheader("High Risk Entities (Top 10 IPs)")
    top_ips = df.groupby('src_ip')['risk_score'].mean().sort_values(ascending=False).head(10).reset_index()
    top_ips.columns = ['Source IP', 'Average Risk Score']
    st.table(top_ips)

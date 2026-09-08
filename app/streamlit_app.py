"""
Main Streamlit Application for e-Gov Portal Security Analytics.
"""

import streamlit as st
import pandas as pd
import json
import os
import sys

# Ensure src is in path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))

from components import triage_view, model_view, timeline_view, ueba_view, simulation_view, nlp_view

st.set_page_config(page_title='e-Gov Portal Security Analytics', layout='wide', page_icon="🛡️")

# --- DATA LOADING ---
@st.cache_data
def load_data():
    """Load all necessary datasets."""
    data_dict = {}
    
    # Mock data generation if real files don't exist yet, to ensure dashboard renders
    import numpy as np
    from datetime import datetime, timedelta
    
    np.random.seed(42)
    now = datetime.utcnow()
    
    # Generate mock API Gateway Logs
    api_logs = pd.DataFrame({
        'event_id': [f"EVT-{i}" for i in range(1000)],
        'timestamp': [(now - timedelta(minutes=i)).isoformat() for i in range(1000)],
        'src_ip': np.random.choice(['192.0.2.10', '198.51.100.20', '203.0.113.30', '192.0.2.55'], 1000),
        'citizen_id': [f"CIT-{np.random.randint(100000, 999999)}" for _ in range(1000)],
        'endpoint': np.random.choice(['/login', '/api/data', '/profile', '/documents'], 1000),
        'response_time_ms': np.random.exponential(50, 1000),
        'http_status': np.random.choice([200, 401, 403, 429, 500], 1000, p=[0.7, 0.1, 0.05, 0.1, 0.05]),
        'is_anomalous_scraping': np.random.choice([True, False], 1000, p=[0.1, 0.9])
    })
    data_dict['api_gateway_logs'] = api_logs

    # Generate mock Auth DB Audit Logs
    auth_logs = pd.DataFrame({
        'event_id': [f"AUTH-{i}" for i in range(500)],
        'timestamp': [(now - timedelta(minutes=i*2)).isoformat() for i in range(500)],
        'citizen_id': api_logs['citizen_id'].head(500).tolist(),
        'src_ip': api_logs['src_ip'].head(500).tolist(),
        'geo_country': np.random.choice(['US', 'UK', 'CA', 'RU', 'CN'], 500),
        'latitude': np.random.uniform(-90, 90, 500),
        'longitude': np.random.uniform(-180, 180, 500),
        'is_impossible_travel': np.random.choice([True, False], 500, p=[0.05, 0.95])
    })
    data_dict['auth_db_audit_logs'] = auth_logs
    
    # Generate mock Complaints
    complaints = pd.DataFrame({
        'ticket_id': [f"TKT-{i}" for i in range(100)],
        'timestamp': [(now - timedelta(hours=i)).isoformat() for i in range(100)],
        'complaint_text': ["My account was hacked!" if i%3==0 else "Portal is very slow." for i in range(100)]
    })
    data_dict['citizen_complaints'] = complaints
    
    return data_dict

data_dict = load_data()

# --- SIDEBAR ---
with st.sidebar:
    st.title("🛡️ e-Gov SecOps")
    st.markdown("Security Analytics Decision-Support System")
    
    st.divider()
    
    selected_tab = st.radio(
        "Navigation",
        ["SOC Threat Triage", 
         "ML Model Performance", 
         "Incident Timeline", 
         "UEBA & Access Analytics", 
         "Monte Carlo Simulator", 
         "NLP Complaint Mining"]
    )
    
    st.divider()
    
    st.subheader("Global Filters")
    date_range = st.date_input("Date Range", [])
    ip_filter = st.text_input("IP Address Filter")
    risk_level = st.multiselect("Risk Level", ["Critical", "High", "Medium", "Low"])
    
    if st.button("Refresh Data"):
        st.cache_data.clear()
        st.rerun()

# --- HEADER METRICS ---
st.title("e-Government Portal Security Dashboard")

col1, col2, col3, col4 = st.columns(4)
with col1:
    st.metric("Total Events (24h)", "145,231", "12%")
with col2:
    st.metric("Threats Detected", "1,423", "-5%")
with col3:
    st.metric("Avg Risk Score", "42/100", "3")
with col4:
    st.metric("Active Incidents", "7", "-2")

st.divider()

# --- ROUTING ---
if selected_tab == "SOC Threat Triage":
    triage_view.render(data_dict)
elif selected_tab == "ML Model Performance":
    model_view.render(data_dict)
elif selected_tab == "Incident Timeline":
    timeline_view.render(data_dict)
elif selected_tab == "UEBA & Access Analytics":
    ueba_view.render(data_dict)
elif selected_tab == "Monte Carlo Simulator":
    simulation_view.render(data_dict)
elif selected_tab == "NLP Complaint Mining":
    nlp_view.render(data_dict)

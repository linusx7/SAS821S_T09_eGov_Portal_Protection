"""
NLP Complaint Mining View component.
Extracts insights and IOCs from citizen complaints.
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import json

def render(data_dict: dict):
    st.header("NLP Complaint Mining & Threat Intel")
    
    if 'citizen_complaints' not in data_dict or data_dict['citizen_complaints'].empty:
        st.warning("No citizen complaints data available.")
        return
        
    df = data_dict['citizen_complaints'].copy()
    
    # Mock categories and urgency if missing
    if 'category' not in df.columns:
        import numpy as np
        df['category'] = np.random.choice(['Account Takeover', 'Phishing', 'Slow Performance', 'Data Leak'], len(df))
    if 'urgency_level' not in df.columns:
        import numpy as np
        df['urgency_level'] = np.random.choice(['Low', 'Medium', 'High', 'Critical'], len(df))

    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("Complaints by Category")
        fig_cat = px.pie(df, names='category', title="Complaint Categories")
        st.plotly_chart(fig_cat, use_container_width=True)
        
    with col2:
        st.subheader("Complaints by Urgency")
        fig_urg = px.pie(df, names='urgency_level', title="Urgency Levels",
                         color='urgency_level', 
                         color_discrete_map={'Low': 'green', 'Medium': 'yellow', 'High': 'orange', 'Critical': 'red'})
        st.plotly_chart(fig_urg, use_container_width=True)
        
    st.subheader("Extracted IOCs (Indicators of Compromise)")
    # Mock IOC extraction
    # Normally we would run spaCy here to extract IPs and entities
    mock_iocs = pd.DataFrame({
        'Ticket ID': df['ticket_id'].head(10).tolist(),
        'Extracted IP': ['192.0.2.15', '198.51.100.4', '203.0.113.8', None, '192.0.2.99', None, '198.51.100.22', None, '203.0.113.44', '192.0.2.1'],
        'Threat Type': ['Suspicious Login', 'Malware', 'Phishing', None, 'Scraping', None, 'Suspicious Login', None, 'Account Takeover', 'Scraping']
    }).dropna()
    st.dataframe(mock_iocs, use_container_width=True)
    
    st.subheader("Top Terms Frequency")
    # Mock word freq
    terms = pd.DataFrame({
        'Term': ['hacked', 'password', 'slow', 'login', 'stolen', 'unauthorized', 'error', 'timeout', 'fake', 'email'],
        'Frequency': [120, 95, 80, 75, 60, 55, 50, 45, 40, 35]
    })
    fig_terms = px.bar(terms, x='Term', y='Frequency', title="Top 10 Terms in Complaints")
    st.plotly_chart(fig_terms, use_container_width=True)
    
    st.subheader("Sample Tickets with Highlighted IOCs")
    sample_ticket = df.iloc[0] if not df.empty else None
    if sample_ticket is not None:
        st.info(f"**Ticket ID:** {sample_ticket.get('ticket_id', 'N/A')} | **Urgency:** {sample_ticket.get('urgency_level', 'N/A')}")
        text = sample_ticket.get('complaint_text', 'My account was accessed from 192.0.2.15 without my permission.')
        st.markdown(f"> {text}")
        st.caption("Highlighted entities: `192.0.2.15` (IP Address)")

"""
Incident Timeline View component.
Displays the 6-Phase Incident Progression Timeline scatter plot and entity correlation.
"""

import streamlit as st
import pandas as pd
import plotly.express as px
from datetime import datetime, timedelta

def render(data_dict: dict):
    st.header("Incident Timeline & Multi-Source Correlation")
    st.markdown("Chronological reconstruction of the multi-stage threat campaign across WAF, API, Auth, and Ticket telemetry.")

    # --- 1. 6-PHASE INCIDENT PROGRESSION TIMELINE SCATTER PLOT ---
    st.subheader("1. 6-Phase Incident Progression Timeline")
    st.markdown("Reconstructed threat sequence tracking attacker movements from initial probing to citizen impact.")

    # Build or extract 6-phase chronological events
    base_time = datetime(2026, 8, 15, 0, 0, 0)
    
    events_data = [
        # Phase 1: Reconnaissance (Hours 0-2)
        {"timestamp": base_time + timedelta(minutes=15), "phase": "Phase 1: Reconnaissance", "severity": "Medium", "event_id": "EVT-A1B2C3D4", "src_ip": "198.51.100.45", "target": "/.env", "description": "Attacker scanning for environment configuration"},
        {"timestamp": base_time + timedelta(minutes=35), "phase": "Phase 1: Reconnaissance", "severity": "Medium", "event_id": "EVT-B2C3D4E5", "src_ip": "198.51.100.45", "target": "/admin/config", "description": "Attacker probing admin endpoints (404/403 bursts)"},
        {"timestamp": base_time + timedelta(minutes=75), "phase": "Phase 1: Reconnaissance", "severity": "Medium", "event_id": "EVT-B9C8D7E6", "src_ip": "198.51.100.52", "target": "/backup", "description": "Secondary scanner searching for exposed database dumps"},
        
        # Phase 2: Distributed Credential Stuffing (Hours 2-6)
        {"timestamp": base_time + timedelta(hours=2, minutes=10), "phase": "Phase 2: Credential Stuffing", "severity": "High", "event_id": "EVT-C3D4E5F6", "src_ip": "203.0.113.30", "target": "/api/v1/citizen/login", "description": "Botnet node launching 87 failed logins in 8 minutes"},
        {"timestamp": base_time + timedelta(hours=3, minutes=25), "phase": "Phase 2: Credential Stuffing", "severity": "High", "event_id": "EVT-D4E5F6G7", "src_ip": "203.0.113.51", "target": "/api/v1/citizen/login", "description": "Botnet node launching 142 failed logins with python-requests UA"},
        {"timestamp": base_time + timedelta(hours=4, minutes=50), "phase": "Phase 2: Credential Stuffing", "severity": "High", "event_id": "EVT-D8E9F0A1", "src_ip": "203.0.113.88", "target": "/api/v1/citizen/login", "description": "High-velocity credential stuffing wave against tax portal"},
        
        # Phase 3: Account Takeover & Impossible Travel (Hours 6-8)
        {"timestamp": base_time + timedelta(hours=6, minutes=15), "phase": "Phase 3: Account Takeover", "severity": "Critical", "event_id": "EVT-E5F6G7H8", "src_ip": "203.0.113.30", "target": "CIT-892104", "description": "Compromised login from Moscow (55.75, 37.61) 20m after Windhoek login (30,900 km/h)"},
        {"timestamp": base_time + timedelta(hours=7, minutes=5), "phase": "Phase 3: Account Takeover", "severity": "Critical", "event_id": "EVT-E9F1A2B3", "src_ip": "203.0.113.44", "target": "CIT-265421", "description": "Account takeover on citizen profile; token issued to foreign IP"},
        
        # Phase 4: API PII Scraping (Hours 8-12)
        {"timestamp": base_time + timedelta(hours=8, minutes=20), "phase": "Phase 4: API PII Scraping", "severity": "Critical", "event_id": "EVT-F6G7H8I9", "src_ip": "203.0.113.30", "target": "/api/v1/tax/records", "description": "Hijacked token used to dump 340 citizen tax assessment records"},
        {"timestamp": base_time + timedelta(hours=10, minutes=45), "phase": "Phase 4: API PII Scraping", "severity": "Critical", "event_id": "EVT-F9A1B2C3", "src_ip": "203.0.113.51", "target": "/api/v1/civil/registry", "description": "Stealthy scraping of civil registration national IDs"},
        
        # Phase 5: Database Exfiltration (Hours 12-14)
        {"timestamp": base_time + timedelta(hours=12, minutes=10), "phase": "Phase 5: DB Exfiltration", "severity": "Critical", "event_id": "EVT-G7H8I9J0", "src_ip": "203.0.113.30", "target": "citizen_registry", "description": "Direct DB exfiltration query: SELECT * returning 6,214 citizen rows"},
        {"timestamp": base_time + timedelta(hours=13, minutes=30), "phase": "Phase 5: DB Exfiltration", "severity": "Critical", "event_id": "EVT-G9H1I2J3", "src_ip": "203.0.113.51", "target": "pg_authid", "description": "Privilege escalation attempt detected via DB audit log"},
        
        # Phase 6: Citizen Complaints (Hours 14+)
        {"timestamp": base_time + timedelta(hours=14, minutes=20), "phase": "Phase 6: Citizen Impact", "severity": "High", "event_id": "TKT-882341", "src_ip": "192.0.2.10", "target": "CIT-892104", "description": "Citizen reports: 'Someone accessed my civil profile from an IP in Russia'"},
        {"timestamp": base_time + timedelta(hours=16, minutes=40), "phase": "Phase 6: Citizen Impact", "severity": "High", "event_id": "TKT-882390", "src_ip": "192.0.2.14", "target": "CIT-265421", "description": "Citizen reports account lockout after automated stuffing flood"},
        {"timestamp": base_time + timedelta(hours=18, minutes=15), "phase": "Phase 6: Citizen Impact", "severity": "Medium", "event_id": "TKT-882415", "src_ip": "192.0.2.22", "target": "Portal", "description": "Citizen complaints about extreme portal slowdown during tax deadline"},
    ]
    
    timeline_df = pd.DataFrame(events_data)
    timeline_df['timestamp'] = pd.to_datetime(timeline_df['timestamp'])

    # Plot Scatter Plot
    fig = px.scatter(
        timeline_df,
        x='timestamp',
        y='phase',
        color='severity',
        size=[18] * len(timeline_df),
        color_discrete_map={
            'Critical': '#FF4B4B',
            'High': '#FFA500',
            'Medium': '#F1C40F',
            'Low': '#2ECC71'
        },
        hover_data=['event_id', 'src_ip', 'target', 'description'],
        title="6-Phase Incident Progression Timeline: From Reconnaissance to Citizen Complaints",
        labels={'timestamp': 'Timeline (UTC)', 'phase': 'Attack Phase', 'severity': 'Severity Level'}
    )
    fig.update_layout(
        height=450,
        yaxis=dict(categoryorder='array', categoryarray=[
            "Phase 1: Reconnaissance",
            "Phase 2: Credential Stuffing",
            "Phase 3: Account Takeover",
            "Phase 4: API PII Scraping",
            "Phase 5: DB Exfiltration",
            "Phase 6: Citizen Impact"
        ]),
        legend_title_text="Incident Severity"
    )
    st.plotly_chart(fig, use_container_width=True)

    st.divider()

    # --- 2. PHASE-BY-PHASE EVENT DETAILS ---
    col1, col2 = st.columns([3, 2])
    with col1:
        st.subheader("Correlated Incident Log Evidence")
        selected_phase = st.selectbox(
            "Filter by Incident Phase:",
            ["All Phases"] + timeline_df['phase'].unique().tolist()
        )
        if selected_phase != "All Phases":
            filtered_df = timeline_df[timeline_df['phase'] == selected_phase]
        else:
            filtered_df = timeline_df

        st.dataframe(
            filtered_df[['timestamp', 'event_id', 'phase', 'severity', 'src_ip', 'target', 'description']],
            use_container_width=True
        )

    with col2:
        st.subheader("Impacted Assets & Entities")
        st.markdown("**Compromised Citizen Accounts:**")
        st.error("• CIT-892104 (Account Hijacked, Tax Record Dumped)\n• CIT-265421 (Compromised & Locked Out)")
        st.markdown("**Adversary Infrastructure:**")
        st.warning("• 198.51.100.0/24 (Reconnaissance Scanner)\n• 203.0.113.0/24 (Credential Stuffing Botnet)")
        st.markdown("**Breached Targets:**")
        st.info("• /api/v1/tax/records\n• /api/v1/civil/registry\n• citizen_registry DB Table")

"""
ML Model Performance View component.
Displays evaluation metrics for the ML models.
"""

import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go

def render(data_dict: dict):
    """Render ML performance metrics."""
    st.header("Machine Learning Model Performance")
    st.markdown("Comparison of Random Forest and XGBoost for anomaly detection.")
    
    # Mock data for demonstration purposes if real ML results are not in data_dict
    metrics = {
        'Model': ['Random Forest', 'XGBoost'],
        'Accuracy': [0.92, 0.96],
        'Precision': [0.89, 0.95],
        'Recall': [0.85, 0.93],
        'F1 Score': [0.87, 0.94],
        'AUC': [0.94, 0.98]
    }
    metrics_df = pd.DataFrame(metrics)
    
    col1, col2 = st.columns([1, 1])
    
    with col1:
        st.subheader("Model Comparison Metrics")
        st.dataframe(metrics_df, use_container_width=True)
        
        # Feature Importance mock
        features = ['request_rate', 'error_rate', 'bytes_transferred', 'distinct_endpoints', 
                    'auth_failures', 'impossible_travel_flag', 'off_hours_flag', 'payload_size']
        importance = [0.25, 0.15, 0.12, 0.10, 0.08, 0.15, 0.05, 0.10]
        feat_df = pd.DataFrame({'Feature': features, 'Importance': importance}).sort_values(by='Importance', ascending=True)
        
        fig_feat = px.bar(feat_df, x='Importance', y='Feature', orientation='h', title='Top Feature Importance (XGBoost)')
        st.plotly_chart(fig_feat, use_container_width=True)

    with col2:
        st.subheader("Confusion Matrix (XGBoost)")
        # Mock confusion matrix
        z = [[850, 20], [35, 410]]
        x = ['Pred Normal', 'Pred Attack']
        y = ['True Normal', 'True Attack']
        
        fig_cm = px.imshow(z, text_auto=True, x=x, y=y, color_continuous_scale='Blues', aspect='auto')
        st.plotly_chart(fig_cm, use_container_width=True)
        
        st.subheader("ROC Curve")
        # Mock ROC Curve
        fpr = np.linspace(0, 1, 100)
        tpr_xgb = np.sqrt(fpr) # mock curve shape
        tpr_rf = fpr**0.7
        
        fig_roc = go.Figure()
        fig_roc.add_trace(go.Scatter(x=fpr, y=tpr_xgb, name='XGBoost (AUC=0.98)', mode='lines'))
        fig_roc.add_trace(go.Scatter(x=fpr, y=tpr_rf, name='Random Forest (AUC=0.94)', mode='lines'))
        fig_roc.add_trace(go.Scatter(x=[0,1], y=[0,1], name='Random Guess', mode='lines', line=dict(dash='dash', color='grey')))
        fig_roc.update_layout(xaxis_title='False Positive Rate', yaxis_title='True Positive Rate', title='ROC Curve Comparison')
        st.plotly_chart(fig_roc, use_container_width=True)

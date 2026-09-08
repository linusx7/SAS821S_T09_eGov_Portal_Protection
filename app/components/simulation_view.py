"""
Monte Carlo Simulation View component.
Interactive front-end for the Monte Carlo simulator.
"""

import streamlit as st
import pandas as pd
import sys
import os

# Ensure src is in path to import simulator
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', 'src')))

try:
    from simulation.monte_carlo_simulator import SecurityControlSimulator
except ImportError:
    st.error("Failed to import SecurityControlSimulator. Ensure it exists in src/simulation/.")
    SecurityControlSimulator = None

def render(data_dict: dict):
    st.header("Monte Carlo Defense Simulation")
    st.markdown("Evaluate security control scenarios under varying attack intensities.")
    
    if SecurityControlSimulator is None:
        return

    # Use session state to cache simulation results so it doesn't re-run on every UI interaction
    if 'sim_results' not in st.session_state:
        st.session_state.sim_results = None
        st.session_state.sim_stats = None

    with st.sidebar:
        st.subheader("Simulation Controls")
        n_iters = st.slider("Monte Carlo Iterations", min_value=100, max_value=2000, value=500, step=100)
        run_sim = st.button("Run/Refresh Simulation")

    if run_sim or st.session_state.sim_results is None:
        with st.spinner("Running Monte Carlo Simulations..."):
            simulator = SecurityControlSimulator(n_iterations=n_iters)
            results = simulator.run_simulation()
            stats = simulator.compute_statistics(results)
            
            st.session_state.sim_results = results
            st.session_state.sim_stats = stats
            st.session_state.simulator = simulator

    if st.session_state.sim_stats is not None:
        stats = st.session_state.sim_stats
        simulator = st.session_state.simulator

        st.subheader("Simulation Tradeoff Analysis")
        fig_comp = simulator.plot_comprehensive_tradeoff(stats)
        st.plotly_chart(fig_comp, use_container_width=True)
        
        col1, col2 = st.columns(2)
        with col1:
            st.subheader("Breach Probability")
            fig_breach = simulator.plot_breach_probability(stats)
            st.plotly_chart(fig_breach, use_container_width=True)
            
        with col2:
            st.subheader("False Positive Comparison")
            fig_fp = simulator.plot_false_positive_comparison(stats)
            st.plotly_chart(fig_fp, use_container_width=True)

        st.subheader("Recommendation Report")
        report = simulator.generate_simulation_report(stats)
        st.markdown(report)
        
        with st.expander("Raw Simulation Data"):
            st.dataframe(stats)

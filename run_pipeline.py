#!/usr/bin/env python
"""
SAS821S Capstone Pipeline Runner
Runs all analytical components in the correct dependency order.
"""
import subprocess
import sys
import os
import time

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
os.chdir(PROJECT_ROOT)

steps = [
    ("Step 1: Generating Synthetic Data", [sys.executable, "-m", "src.data_generation.generate_synthetic_data"]),
    ("Step 2: Running ETL Pipeline", [sys.executable, "-m", "src.pipelines.etl_pipeline"]),
    ("Step 3: Computing ML Features", [sys.executable, "-m", "src.pipelines.feature_engineering"]),
    ("Step 4: Training Supervised ML Models", [sys.executable, "-m", "src.models.supervised_detector"]),
    ("Step 5: Running UEBA Anomaly Detection", [sys.executable, "-m", "src.models.ueba_anomaly_detector"]),
    ("Step 6: Running Adversarial Evaluation", [sys.executable, "-m", "src.models.adversarial_evaluator"]),
    ("Step 7: Building Incident Timeline", [sys.executable, "-m", "src.intelligence.correlation_engine"]),
    ("Step 8: Generating STIX Threat Intel", [sys.executable, "-m", "src.intelligence.stix_threat_intel"]),
    ("Step 9: Mining NLP Complaints", [sys.executable, "-m", "src.intelligence.nlp_ticket_miner"]),
    ("Step 10: Running Monte Carlo Simulation", [sys.executable, "-m", "src.simulation.monte_carlo_simulator"]),
]

def run_pipeline():
    print("=" * 70)
    print("SAS821S CAPSTONE FULL PIPELINE EXECUTION")
    print(f"Project Root: {PROJECT_ROOT}")
    print("=" * 70)
    
    results = []
    total_start = time.time()
    
    for i, (description, command) in enumerate(steps):
        print(f"\n{'='*70}")
        print(f"{description} ({i+1}/{len(steps)})")
        print(f"{'='*70}")
        
        step_start = time.time()
        try:
            result = subprocess.run(command, capture_output=False, text=True, cwd=PROJECT_ROOT)
            elapsed = time.time() - step_start
            
            if result.returncode == 0:
                status = "SUCCESS"
                print(f"\n✓ {description} completed in {elapsed:.1f}s")
            else:
                status = "FAILED"
                print(f"\n✗ {description} FAILED (exit code {result.returncode}) in {elapsed:.1f}s")
        except Exception as e:
            elapsed = time.time() - step_start
            status = "ERROR"
            print(f"\n✗ {description} ERROR: {e}")
        
        results.append((description, status, elapsed))
    
    total_elapsed = time.time() - total_start
    
    print(f"\n\n{'='*70}")
    print("PIPELINE EXECUTION SUMMARY")
    print(f"{'='*70}")
    
    for desc, status, elapsed in results:
        icon = "✓" if status == "SUCCESS" else "✗"
        print(f"  {icon} {desc}: {status} ({elapsed:.1f}s)")
    
    successes = sum(1 for _, s, _ in results if s == "SUCCESS")
    print(f"\nTotal: {successes}/{len(steps)} steps succeeded in {total_elapsed:.1f}s")
    
    if successes == len(steps):
        print(f"\n🎉 Pipeline complete! Launch dashboard with:")
        print(f"   streamlit run app/streamlit_app.py")
    else:
        print(f"\n⚠️  Some steps failed. Check output above for details.")
    
    # Check for expected output files
    print(f"\n{'='*70}")
    print("OUTPUT FILE CHECK")
    print(f"{'='*70}")
    expected_files = [
        'data/raw/web_waf_logs.csv',
        'data/raw/api_gateway_logs.csv', 
        'data/raw/auth_db_audit_logs.csv',
        'data/raw/citizen_complaints.json',
        'data/processed/security_feature_store.parquet',
        'data/processed/ml_features.csv',
        'data/processed/model_metrics.json',
        'data/processed/best_model.pkl',
        'data/processed/ueba_results.json',
        'data/processed/adversarial_results.json',
        'data/processed/incident_timeline.json',
        'data/processed/incident_report.md',
        'data/processed/stix_bundle.json',
        'data/processed/pir_report.json',
        'data/processed/nlp_results.json',
        'data/processed/simulation_results.json',
    ]
    for f in expected_files:
        full_path = os.path.join(PROJECT_ROOT, f)
        exists = os.path.exists(full_path)
        icon = "✓" if exists else "✗"
        size = f"{os.path.getsize(full_path):,} bytes" if exists else "MISSING"
        print(f"  {icon} {f}: {size}")

if __name__ == '__main__':
    run_pipeline()

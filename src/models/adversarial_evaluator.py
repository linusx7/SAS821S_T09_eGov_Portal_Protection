"""
Adversarial Evaluator for robustness testing.
"""
import os
import json
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from sklearn.metrics import f1_score, precision_score, recall_score
import logging
from src.pipelines.feature_engineering import get_feature_names
import joblib
from src.models.supervised_detector import SupervisedSecurityDetector

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AdversarialEvaluator:
    def __init__(self, model, feature_names):
        self.model = model
        self.feature_names = feature_names

    def _eval_model(self, X, y):
        try:
            y_pred = self.model.predict(X)
            return {
                'f1': float(f1_score(y, y_pred, zero_division=0)),
                'precision': float(precision_score(y, y_pred, zero_division=0)),
                'recall': float(recall_score(y, y_pred, zero_division=0))
            }
        except Exception:
            return {'f1': 0.0, 'precision': 0.0, 'recall': 0.0}

    def scenario_user_agent_spoofing(self, X_test: pd.DataFrame, y_test: pd.Series) -> dict:
        """Modifies user_agent_entropy to mimic legitimate browsers."""
        levels = [0.1, 0.2, 0.3, 0.5, 0.7, 1.0]
        f1_scores = []
        precision_scores = []
        recall_scores = []
        
        X_adv = X_test.copy()
        
        for lvl in levels:
            if 'user_agent_entropy' in self.feature_names:
                X_adv['user_agent_entropy'] = X_test['user_agent_entropy'] * (1 - lvl)
            scores = self._eval_model(X_adv[self.feature_names], y_test)
            f1_scores.append(scores['f1'])
            precision_scores.append(scores['precision'])
            recall_scores.append(scores['recall'])
            
        return {
            'perturbation_levels': levels,
            'f1_scores': f1_scores,
            'precision_scores': precision_scores,
            'recall_scores': recall_scores
        }

    def scenario_slow_and_low(self, X_test: pd.DataFrame, y_test: pd.Series) -> dict:
        """Reduces request_rate features."""
        levels = [0.1, 0.2, 0.3, 0.5, 0.7, 1.0]
        f1_scores = []
        precision_scores = []
        recall_scores = []
        
        rates = [c for c in self.feature_names if 'rate' in c]
        
        for lvl in levels:
            X_adv = X_test.copy()
            for col in rates:
                X_adv[col] = X_test[col] * (1 - lvl)
            scores = self._eval_model(X_adv[self.feature_names], y_test)
            f1_scores.append(scores['f1'])
            precision_scores.append(scores['precision'])
            recall_scores.append(scores['recall'])
            
        return {
            'perturbation_levels': levels,
            'f1_scores': f1_scores,
            'precision_scores': precision_scores,
            'recall_scores': recall_scores
        }

    def scenario_payload_padding(self, X_test: pd.DataFrame, y_test: pd.Series) -> dict:
        """Adds noise to payload/bytes features."""
        levels = [0.05, 0.1, 0.2, 0.3, 0.5]
        f1_scores = []
        precision_scores = []
        recall_scores = []
        
        byte_cols = [c for c in self.feature_names if 'byte' in c or 'payload' in c]
        
        for lvl in levels:
            X_adv = X_test.copy()
            for col in byte_cols:
                noise = np.random.normal(0, lvl * (X_test[col].mean() + 1e-5), size=len(X_test))
                X_adv[col] = X_test[col] + noise
            scores = self._eval_model(X_adv[self.feature_names], y_test)
            f1_scores.append(scores['f1'])
            precision_scores.append(scores['precision'])
            recall_scores.append(scores['recall'])
            
        return {
            'perturbation_levels': levels,
            'f1_scores': f1_scores,
            'precision_scores': precision_scores,
            'recall_scores': recall_scores
        }

    def run_all_scenarios(self, X_test: pd.DataFrame, y_test: pd.Series) -> dict:
        return {
            'user_agent_spoofing': self.scenario_user_agent_spoofing(X_test, y_test),
            'slow_and_low': self.scenario_slow_and_low(X_test, y_test),
            'payload_padding': self.scenario_payload_padding(X_test, y_test)
        }

if __name__ == '__main__':
    base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    data_dir = os.path.join(base_dir, 'data')
    proc_dir = os.path.join(data_dir, 'processed')
    
    features_path = os.path.join(proc_dir, 'ml_features.csv')
    model_path = os.path.join(proc_dir, 'best_model.pkl')
    
    if not os.path.exists(features_path) or not os.path.exists(model_path):
        logger.error("Missing required files (ml_features.csv or best_model.pkl). Please run supervised_detector.py first.")
        exit(1)
        
    df = pd.read_csv(features_path)
    X = df[get_feature_names()].fillna(0)
    y = df['label']
    
    from sklearn.model_selection import train_test_split
    _, X_test, _, y_test = train_test_split(X, y, test_size=0.2, stratify=y, random_state=42)
    
    # Load model
    logger.info(f"Loading best model from {model_path}")
    best_detector = joblib.load(model_path)
    
    evaluator = AdversarialEvaluator(best_detector, get_feature_names())
    
    logger.info("Running adversarial scenarios...")
    results = evaluator.run_all_scenarios(X_test, y_test)
    
    out_path = os.path.join(proc_dir, 'adversarial_results.json')
    with open(out_path, 'w') as f:
        json.dump(results, f, indent=4)
        
    logger.info(f"Results saved to {out_path}")
    
    for scenario, res in results.items():
        logger.info(f"Scenario: {scenario}")
        for i, lvl in enumerate(res['perturbation_levels']):
            logger.info(f"  Level {lvl:.2f} -> F1: {res['f1_scores'][i]:.4f}")

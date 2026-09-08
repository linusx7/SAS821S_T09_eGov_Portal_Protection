"""
Adversarial Evaluator for robustness testing.
"""
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from sklearn.metrics import f1_score
import logging

logger = logging.getLogger(__name__)

class AdversarialEvaluator:
    def __init__(self, model, feature_names):
        self.model = model
        self.feature_names = feature_names

    def _eval_model(self, X, y):
        try:
            y_pred = self.model.predict(X)
            return f1_score(y, y_pred, zero_division=0)
        except Exception:
            return 0.0

    def scenario_user_agent_spoofing(self, X_test: pd.DataFrame, y_test: pd.Series) -> dict:
        """Modifies user_agent_entropy to mimic legitimate browsers."""
        levels = [0.1, 0.2, 0.3, 0.5, 0.7, 1.0]
        results = {}
        X_adv = X_test.copy()
        
        if 'user_agent_entropy' in self.feature_names:
            for lvl in levels:
                X_adv['user_agent_entropy'] = X_test['user_agent_entropy'] * (1 - lvl)
                results[lvl] = self._eval_model(X_adv, y_test)
        return results

    def scenario_slow_and_low(self, X_test: pd.DataFrame, y_test: pd.Series) -> dict:
        """Reduces request_rate features."""
        levels = [0.1, 0.2, 0.3, 0.5, 0.7, 1.0]
        results = {}
        X_adv = X_test.copy()
        
        rates = [c for c in self.feature_names if 'rate' in c]
        for lvl in levels:
            for col in rates:
                X_adv[col] = X_test[col] * (1 - lvl)
            results[lvl] = self._eval_model(X_adv, y_test)
        return results

    def scenario_payload_padding(self, X_test: pd.DataFrame, y_test: pd.Series) -> dict:
        """Adds noise to payload/bytes features."""
        levels = [0.05, 0.1, 0.2, 0.3, 0.5]
        results = {}
        X_adv = X_test.copy()
        
        byte_cols = [c for c in self.feature_names if 'byte' in c or 'payload' in c]
        for lvl in levels:
            for col in byte_cols:
                noise = np.random.normal(0, lvl * (X_test[col].mean() + 1e-5), size=len(X_test))
                X_adv[col] = X_test[col] + noise
            results[lvl] = self._eval_model(X_adv, y_test)
        return results

    def run_all_scenarios(self, X_test: pd.DataFrame, y_test: pd.Series) -> dict:
        return {
            'user_agent_spoofing': self.scenario_user_agent_spoofing(X_test, y_test),
            'slow_and_low': self.scenario_slow_and_low(X_test, y_test),
            'payload_padding': self.scenario_payload_padding(X_test, y_test)
        }

    def plot_degradation_curves(self, results: dict, save_path=None):
        plt.figure(figsize=(8, 5))
        for scenario, res in results.items():
            if res:
                x = list(res.keys())
                y = list(res.values())
                plt.plot(x, y, marker='o', label=scenario)
        plt.title('Adversarial Robustness Degradation')
        plt.xlabel('Perturbation Level')
        plt.ylabel('F1 Score')
        plt.legend()
        if save_path:
            plt.savefig(save_path)
            plt.close()
        else:
            plt.show()

    def generate_robustness_report(self, results: dict) -> str:
        report = "=== Adversarial Robustness Report ===\n"
        for scenario, res in results.items():
            report += f"\nScenario: {scenario}\n"
            for lvl, f1 in res.items():
                report += f"  Perturbation: {lvl:.2f} -> F1 Score: {f1:.4f}\n"
        return report

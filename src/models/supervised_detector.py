"""
Supervised detector for credential stuffing and WAF evasion.
"""
import os
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier
from sklearn.model_selection import GridSearchCV, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score, precision_score, recall_score, f1_score, roc_curve
from imblearn.over_sampling import SMOTE
import matplotlib.pyplot as plt
import seaborn as sns
import joblib
import logging

logger = logging.getLogger(__name__)

class SupervisedSecurityDetector:
    def __init__(self, model_type='random_forest', random_state=42):
        self.model_type = model_type
        self.random_state = random_state
        self.model = None
        self.feature_names_in_ = None
        
        if self.model_type == 'random_forest':
            self.model = RandomForestClassifier(random_state=self.random_state, class_weight='balanced')
        elif self.model_type == 'xgboost':
            self.model = XGBClassifier(random_state=self.random_state, scale_pos_weight=1)
        else:
            raise ValueError(f"Unknown model_type: {model_type}")

    def train(self, X_train: pd.DataFrame, y_train: pd.Series):
        """Trains the model with SMOTE for class imbalance."""
        logger.info(f"Training {self.model_type}...")
        self.feature_names_in_ = X_train.columns.tolist()
        
        smote = SMOTE(random_state=self.random_state)
        X_resampled, y_resampled = smote.fit_resample(X_train, y_train)
        
        if self.model_type == 'random_forest':
            param_grid = {'n_estimators': [100, 200], 'max_depth': [10, 20, None]}
        else:
            param_grid = {'n_estimators': [100, 200], 'max_depth': [3, 6, 9], 'learning_rate': [0.01, 0.1]}
            
        grid_search = GridSearchCV(self.model, param_grid, cv=3, scoring='f1', n_jobs=-1)
        grid_search.fit(X_resampled, y_resampled)
        
        self.model = grid_search.best_estimator_
        logger.info(f"Best parameters: {grid_search.best_params_}")

    def predict(self, X: pd.DataFrame) -> np.ndarray:
        return self.model.predict(X)

    def predict_proba(self, X: pd.DataFrame) -> np.ndarray:
        return self.model.predict_proba(X)

    def evaluate(self, X_test: pd.DataFrame, y_test: pd.Series) -> dict:
        y_pred = self.predict(X_test)
        y_prob = self.predict_proba(X_test)[:, 1] if len(np.unique(y_test)) > 1 else np.zeros(len(y_test))
        
        metrics = {
            'confusion_matrix': confusion_matrix(y_test, y_pred),
            'classification_report': classification_report(y_test, y_pred),
            'roc_auc': roc_auc_score(y_test, y_prob) if len(np.unique(y_test)) > 1 else 0.0,
            'precision': precision_score(y_test, y_pred, zero_division=0),
            'recall': recall_score(y_test, y_pred, zero_division=0),
            'f1': f1_score(y_test, y_pred, zero_division=0)
        }
        return metrics

    def cross_validate(self, X: pd.DataFrame, y: pd.Series, cv=5) -> np.ndarray:
        return cross_val_score(self.model, X, y, cv=cv, scoring='f1')

    def get_feature_importance(self) -> pd.DataFrame:
        if hasattr(self.model, 'feature_importances_'):
            importances = self.model.feature_importances_
            df = pd.DataFrame({'feature': self.feature_names_in_, 'importance': importances})
            return df.sort_values(by='importance', ascending=False)
        return pd.DataFrame()

    def plot_confusion_matrix(self, X_test: pd.DataFrame, y_test: pd.Series, save_path=None):
        y_pred = self.predict(X_test)
        cm = confusion_matrix(y_test, y_pred)
        plt.figure(figsize=(6, 4))
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues')
        plt.title('Confusion Matrix')
        plt.xlabel('Predicted')
        plt.ylabel('Actual')
        if save_path:
            plt.savefig(save_path)
            plt.close()
        else:
            plt.show()

    def plot_roc_curve(self, X_test: pd.DataFrame, y_test: pd.Series, save_path=None):
        if len(np.unique(y_test)) <= 1:
            return
        y_prob = self.predict_proba(X_test)[:, 1]
        fpr, tpr, _ = roc_curve(y_test, y_prob)
        plt.figure(figsize=(6, 4))
        plt.plot(fpr, tpr, label=f'AUC = {roc_auc_score(y_test, y_prob):.2f}')
        plt.plot([0, 1], [0, 1], 'r--')
        plt.title('ROC Curve')
        plt.xlabel('False Positive Rate')
        plt.ylabel('True Positive Rate')
        plt.legend()
        if save_path:
            plt.savefig(save_path)
            plt.close()
        else:
            plt.show()

    def plot_feature_importance(self, top_n=15, save_path=None):
        df_imp = self.get_feature_importance().head(top_n)
        if df_imp.empty:
            return
        plt.figure(figsize=(10, 6))
        sns.barplot(x='importance', y='feature', data=df_imp)
        plt.title('Feature Importance')
        if save_path:
            plt.savefig(save_path)
            plt.close()
        else:
            plt.show()

    def save_model(self, path: str):
        joblib.dump(self.model, path)
        logger.info(f"Model saved to {path}")

    def load_model(self, path: str):
        self.model = joblib.load(path)
        logger.info(f"Model loaded from {path}")

if __name__ == '__main__':
    print("Supervised Detector module ready.")

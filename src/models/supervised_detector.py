"""
Supervised detector for credential stuffing and WAF evasion.
"""
import os
import pandas as pd
import numpy as np
import json
from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier
from sklearn.model_selection import GridSearchCV, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score, precision_score, recall_score, f1_score, roc_curve
from imblearn.over_sampling import SMOTE
import matplotlib.pyplot as plt
import seaborn as sns
import joblib
import logging
import sys

# Ensure src is in python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from src.pipelines.feature_engineering import get_feature_names, create_training_dataset

logging.basicConfig(level=logging.INFO)
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
            'confusion_matrix': confusion_matrix(y_test, y_pred).tolist(),
            'classification_report': classification_report(y_test, y_pred),
            'roc_auc': float(roc_auc_score(y_test, y_prob)) if len(np.unique(y_test)) > 1 else 0.0,
            'precision': float(precision_score(y_test, y_pred, zero_division=0)),
            'recall': float(recall_score(y_test, y_pred, zero_division=0)),
            'f1': float(f1_score(y_test, y_pred, zero_division=0))
        }
        
        if len(np.unique(y_test)) > 1:
            fpr, tpr, _ = roc_curve(y_test, y_prob)
            metrics['fpr'] = fpr.tolist()
            metrics['tpr'] = tpr.tolist()
        else:
            metrics['fpr'] = []
            metrics['tpr'] = []
            
        return metrics

    def cross_validate(self, X: pd.DataFrame, y: pd.Series, cv=5) -> np.ndarray:
        return cross_val_score(self.model, X, y, cv=cv, scoring='f1')

    def get_feature_importance(self) -> pd.DataFrame:
        if hasattr(self.model, 'feature_importances_'):
            importances = self.model.feature_importances_
            df = pd.DataFrame({'feature': self.feature_names_in_, 'importance': importances})
            return df.sort_values(by='importance', ascending=False)
        return pd.DataFrame()

    def save_model(self, path: str):
        joblib.dump(self, path)
        logger.info(f"Model saved to {path}")

    def load_model(self, path: str):
        loaded = joblib.load(path)
        self.model = loaded.model
        self.feature_names_in_ = loaded.feature_names_in_
        logger.info(f"Model loaded from {path}")

if __name__ == '__main__':
    base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    data_dir = os.path.join(base_dir, 'data')
    proc_dir = os.path.join(data_dir, 'processed')
    features_path = os.path.join(proc_dir, 'ml_features.csv')
    
    if not os.path.exists(features_path):
        logger.error(f"Features file not found at {features_path}. Please run feature_engineering.py first.")
        exit(1)
        
    df = pd.read_csv(features_path)
    logger.info(f"Loaded {len(df)} samples.")
    
    X_train, X_test, y_train, y_test = create_training_dataset(df, df['label'])
    
    logger.info("Training Random Forest...")
    rf_detector = SupervisedSecurityDetector(model_type='random_forest')
    rf_detector.train(X_train, y_train)
    rf_metrics = rf_detector.evaluate(X_test, y_test)
    rf_cv = rf_detector.cross_validate(X_train, y_train).tolist()
    
    logger.info("Training XGBoost...")
    xgb_detector = SupervisedSecurityDetector(model_type='xgboost')
    xgb_detector.train(X_train, y_train)
    xgb_metrics = xgb_detector.evaluate(X_test, y_test)
    xgb_cv = xgb_detector.cross_validate(X_train, y_train).tolist()
    
    best_detector = rf_detector if rf_metrics['f1'] > xgb_metrics['f1'] else xgb_detector
    best_model_name = 'Random Forest' if rf_metrics['f1'] > xgb_metrics['f1'] else 'XGBoost'
    best_metrics = best_detector.evaluate(X_test, y_test)
    
    logger.info(f"Best model is {best_model_name} with F1: {best_metrics['f1']:.4f}")
    
    # Save the best model
    best_model_path = os.path.join(proc_dir, 'best_model.pkl')
    best_detector.save_model(best_model_path)
    
    # Save metrics
    metrics_out = {
        'best_model': best_model_name,
        'metrics': best_metrics,
        'cv_scores': rf_cv if best_model_name == 'Random Forest' else xgb_cv,
        'feature_importances': best_detector.get_feature_importance().set_index('feature')['importance'].to_dict()
    }
    
    metrics_path = os.path.join(proc_dir, 'model_metrics.json')
    with open(metrics_path, 'w') as f:
        json.dump(metrics_out, f, indent=4)
        
    logger.info(f"Metrics saved to {metrics_path}")
    logger.info(best_metrics['classification_report'])

"""
NLP Ticket Miner module.
Performs text mining on citizen complaint tickets.
"""

import pandas as pd
import numpy as np
import re
import nltk
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.model_selection import train_test_split
import matplotlib.pyplot as plt
from typing import Dict, List, Any, Tuple

# Download necessary NLTK data if not already present
try:
    nltk.data.find('corpora/stopwords')
except LookupError:
    nltk.download('stopwords', quiet=True)
try:
    nltk.data.find('tokenizers/punkt')
except LookupError:
    nltk.download('punkt', quiet=True)
try:
    nltk.data.find('corpora/wordnet')
except LookupError:
    nltk.download('wordnet', quiet=True)
    nltk.download('omw-1.4', quiet=True)

from nltk.corpus import stopwords
from nltk.tokenize import word_tokenize
from nltk.stem import WordNetLemmatizer

class CitizenTicketMiner:
    """Performs text mining and NLP on citizen complaint tickets."""
    
    def __init__(self):
        self.stop_words = set(stopwords.words('english'))
        self.lemmatizer = WordNetLemmatizer()
        self.vectorizer = TfidfVectorizer(max_features=1000)
        self.classifier = MultinomialNB()
        self.is_fitted = False
        
        self.neg_words = {'locked', 'unauthorized', 'breach', 'stolen', 'hack', 'suspicious', 'fraud', 'compromised', 'attack', 'unable'}
        self.urg_words = {'immediately', 'urgent', 'emergency', 'critical', 'asap'}
        self.pos_words = {'resolved', 'thank', 'working', 'fixed', 'restored'}

    def preprocess_text(self, text: str) -> str:
        """Preprocess text: lowercase, remove special chars (keep IPs/IDs), tokenize, remove stopwords, lemmatize."""
        if not isinstance(text, str):
            return ""
            
        text = text.lower()
        # Keep IPs and CIT-IDs intact, remove other punctuation
        text = re.sub(r'[^a-z0-9\.\-\s]', ' ', text)
        
        tokens = word_tokenize(text)
        cleaned = [self.lemmatizer.lemmatize(t) for t in tokens if t not in self.stop_words and len(t) > 1]
        return ' '.join(cleaned)

    def extract_iocs(self, text: str) -> Dict[str, List[str]]:
        """Extract Indicators of Compromise from text."""
        if not isinstance(text, str):
            text = ""
            
        iocs = {
            'ip_addresses': re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', text),
            'citizen_ids': re.findall(r'CIT-\d{6}', text, re.IGNORECASE),
            'email_addresses': re.findall(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+', text)
        }
        # uppercase CIT ids
        iocs['citizen_ids'] = [c.upper() for c in iocs['citizen_ids']]
        return iocs

    def extract_iocs_from_corpus(self, complaints_df: pd.DataFrame) -> pd.DataFrame:
        """Extract IOCs for a whole dataframe and append columns."""
        df = complaints_df.copy()
        
        extracted = df['complaint_text'].apply(self.extract_iocs)
        df['extracted_ips'] = extracted.apply(lambda x: x['ip_addresses'])
        df['extracted_citizen_ids'] = extracted.apply(lambda x: x['citizen_ids'])
        df['extracted_emails'] = extracted.apply(lambda x: x['email_addresses'])
        
        return df

    def build_tfidf_matrix(self, texts: List[str]) -> np.ndarray:
        """Build and fit TF-IDF vectorizer."""
        preprocessed = [self.preprocess_text(t) for t in texts]
        matrix = self.vectorizer.fit_transform(preprocessed)
        return matrix

    def classify_tickets(self, complaints_df: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray]:
        """Train classifier and return predictions and probabilities."""
        texts = complaints_df['complaint_text'].tolist()
        labels = complaints_df['category'].tolist()
        
        preprocessed = [self.preprocess_text(t) for t in texts]
        X = self.vectorizer.fit_transform(preprocessed)
        self.is_fitted = True
        
        self.classifier.fit(X, labels)
        preds = self.classifier.predict(X)
        probs = self.classifier.predict_proba(X)
        
        return preds, probs

    def analyze_sentiment(self, texts: List[str]) -> List[str]:
        """Rule-based sentiment analysis."""
        sentiments = []
        for text in texts:
            if not isinstance(text, str):
                sentiments.append('neutral')
                continue
                
            text_lower = text.lower()
            tokens = set(word_tokenize(text_lower))
            
            neg_score = len(tokens.intersection(self.neg_words))
            pos_score = len(tokens.intersection(self.pos_words))
            
            if neg_score > pos_score:
                sentiments.append('negative')
            elif pos_score > neg_score:
                sentiments.append('positive')
            else:
                sentiments.append('neutral')
                
        return sentiments

    def get_top_terms(self, n: int = 20) -> Dict[str, List[Tuple[str, float]]]:
        """Get top TF-IDF terms per category (assuming Naive Bayes is fitted)."""
        if not self.is_fitted:
            return {}
            
        feature_names = self.vectorizer.get_feature_names_out()
        top_terms = {}
        
        for i, class_label in enumerate(self.classifier.classes_):
            # Sort log probabilities
            top_indices = np.argsort(self.classifier.feature_log_prob_[i])[-n:]
            terms = [(feature_names[j], np.exp(self.classifier.feature_log_prob_[i][j])) for j in reversed(top_indices)]
            top_terms[class_label] = terms
            
        return top_terms

    def correlate_iocs_with_logs(self, iocs_df: pd.DataFrame, attacker_ips: List[str], compromised_citizens: List[str]) -> Dict[str, Any]:
        """Match extracted IOCs against known threat entities."""
        matched_ips = set()
        matched_citizens = set()
        
        for ips in iocs_df['extracted_ips']:
            for ip in ips:
                if ip in attacker_ips:
                    matched_ips.add(ip)
                    
        for cits in iocs_df['extracted_citizen_ids']:
            for cit in cits:
                if cit in compromised_citizens:
                    matched_citizens.add(cit)
                    
        return {
            'matched_attacker_ips': list(matched_ips),
            'matched_compromised_citizens': list(matched_citizens)
        }

    def generate_ticket_intel_report(self, complaints_df: pd.DataFrame) -> str:
        """Generate formatted summary report."""
        df = complaints_df.copy()
        
        total = len(df)
        categories = df['category'].value_counts().to_dict() if 'category' in df.columns else {}
        urgencies = df['urgency_level'].value_counts().to_dict() if 'urgency_level' in df.columns else {}
        
        report = "# Citizen Ticket Intelligence Report\n\n"
        report += f"**Total Tickets Analyzed:** {total}\n\n"
        
        report += "**Category Distribution:**\n"
        for k, v in categories.items():
            report += f"- {k}: {v}\n"
            
        report += "\n**Urgency Distribution:**\n"
        for k, v in urgencies.items():
            report += f"- {k}: {v}\n"
            
        if 'sentiment' in df.columns:
            sents = df['sentiment'].value_counts().to_dict()
            report += "\n**Sentiment Analysis:**\n"
            for k, v in sents.items():
                report += f"- {k}: {v}\n"
                
        return report

    def plot_category_distribution(self, complaints_df: pd.DataFrame, save_path: str = None) -> None:
        """Plot ticket categories."""
        if 'category' not in complaints_df.columns:
            return
            
        plt.figure(figsize=(10, 6))
        complaints_df['category'].value_counts().plot(kind='bar')
        plt.title('Ticket Categories Distribution')
        plt.xlabel('Category')
        plt.ylabel('Count')
        plt.xticks(rotation=45)
        plt.tight_layout()
        if save_path:
            plt.savefig(save_path)
        else:
            plt.show()
        plt.close()

    def plot_urgency_heatmap(self, complaints_df: pd.DataFrame, save_path: str = None) -> None:
        """Plot urgency vs category."""
        if 'category' not in complaints_df.columns or 'urgency_level' not in complaints_df.columns:
            return
            
        crosstab = pd.crosstab(complaints_df['category'], complaints_df['urgency_level'])
        
        plt.figure(figsize=(10, 6))
        # Simple imshow for heatmap
        plt.imshow(crosstab, cmap='Reds')
        plt.colorbar(label='Count')
        plt.title('Urgency by Category Heatmap')
        plt.xticks(np.arange(len(crosstab.columns)), crosstab.columns, rotation=45)
        plt.yticks(np.arange(len(crosstab.index)), crosstab.index)
        plt.tight_layout()
        if save_path:
            plt.savefig(save_path)
        else:
            plt.show()
        plt.close()

    def plot_wordcloud(self, texts: List[str], save_path: str = None) -> None:
        """Bar chart of top words."""
        preprocessed = [self.preprocess_text(t) for t in texts]
        all_words = ' '.join(preprocessed).split()
        
        if not all_words:
            return
            
        word_freq = pd.Series(all_words).value_counts().head(20)
        
        plt.figure(figsize=(12, 6))
        word_freq.plot(kind='bar')
        plt.title('Top 20 Words in Complaints')
        plt.xlabel('Word')
        plt.ylabel('Frequency')
        plt.xticks(rotation=45)
        plt.tight_layout()
        if save_path:
            plt.savefig(save_path)
        else:
            plt.show()
        plt.close()

if __name__ == '__main__':
    print("NLP Ticket Miner initialized.")

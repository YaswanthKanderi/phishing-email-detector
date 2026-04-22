"""
Phishing Email Detector — Hybrid Model
---------------------------------------
Combines TF-IDF text features with hand-crafted security heuristics,
trained via Logistic Regression for interpretability.

Why hybrid? TF-IDF alone struggles with novel phishing wording it hasn't seen.
Security heuristics (URL analysis, urgency keywords, link mismatches) catch
the structural red flags that phishing emails share regardless of phrasing.
"""

import joblib
import numpy as np
from pathlib import Path
from scipy.sparse import hstack, csr_matrix
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

from detector.features import SecurityFeatureExtractor
from detector.preprocessor import EmailPreprocessor


class PhishingDetector:
    """Hybrid phishing detector: TF-IDF + security heuristics + Logistic Regression."""

    def __init__(self):
        self.preprocessor = EmailPreprocessor()
        self.feature_extractor = SecurityFeatureExtractor()
        self.vectorizer = TfidfVectorizer(
            max_features=5000,
            ngram_range=(1, 2),
            min_df=2,
            max_df=0.95,
            stop_words='english',
        )
        self.scaler = StandardScaler()
        self.model = LogisticRegression(
            max_iter=1000,
            C=1.0,
            class_weight='balanced',
            random_state=42,
        )
        self.feature_names = None
        self._is_fitted = False

    def _build_feature_matrix(self, texts, fit=False):
        """Combine TF-IDF vectors with numeric security features."""
        cleaned = [self.preprocessor.clean(t) for t in texts]

        if fit:
            tfidf_matrix = self.vectorizer.fit_transform(cleaned)
        else:
            tfidf_matrix = self.vectorizer.transform(cleaned)

        # Extract security features as a dense matrix
        security_features = [self.feature_extractor.extract(t) for t in texts]
        if self.feature_names is None:
            self.feature_names = list(security_features[0].keys())
        security_matrix = np.array([
            [f[name] for name in self.feature_names]
            for f in security_features
        ], dtype=float)

        if fit:
            security_matrix = self.scaler.fit_transform(security_matrix)
        else:
            security_matrix = self.scaler.transform(security_matrix)

        # Combine into a single sparse matrix
        combined = hstack([tfidf_matrix, csr_matrix(security_matrix)])
        return combined

    def train(self, emails, labels, test_size=0.2):
        """
        Train the detector.

        Args:
            emails: list of raw email texts
            labels: list of 0 (legitimate) or 1 (phishing)
            test_size: fraction for test split

        Returns:
            dict of evaluation metrics
        """
        X_train_raw, X_test_raw, y_train, y_test = train_test_split(
            emails, labels, test_size=test_size, random_state=42, stratify=labels
        )

        print(f"Training set: {len(X_train_raw)} emails")
        print(f"Test set:     {len(X_test_raw)} emails")
        print(f"Phishing ratio in training: {sum(y_train)/len(y_train):.2%}")

        print("\n→ Building feature matrix...")
        X_train = self._build_feature_matrix(X_train_raw, fit=True)
        X_test = self._build_feature_matrix(X_test_raw, fit=False)

        print(f"→ Feature matrix shape: {X_train.shape}")
        print(f"  (TF-IDF features + {len(self.feature_names)} security features)")

        print("\n→ Training Logistic Regression...")
        self.model.fit(X_train, y_train)
        self._is_fitted = True

        # Evaluate
        y_pred = self.model.predict(X_test)
        y_proba = self.model.predict_proba(X_test)[:, 1]

        print("\n" + "=" * 60)
        print("EVALUATION RESULTS")
        print("=" * 60)
        print(classification_report(y_test, y_pred, target_names=['Legitimate', 'Phishing']))
        print(f"ROC-AUC Score: {roc_auc_score(y_test, y_proba):.4f}")

        cm = confusion_matrix(y_test, y_pred)
        print("\nConfusion Matrix:")
        print(f"              Predicted Legit  Predicted Phish")
        print(f"Actual Legit     {cm[0][0]:6d}           {cm[0][1]:6d}")
        print(f"Actual Phish     {cm[1][0]:6d}           {cm[1][1]:6d}")

        return {
            'accuracy': (y_pred == y_test).mean(),
            'roc_auc': roc_auc_score(y_test, y_proba),
            'confusion_matrix': cm.tolist(),
        }

    def predict(self, email_text):
        """
        Classify a single email.

        Returns:
            dict with prediction, confidence, and contributing signals
        """
        if not self._is_fitted:
            raise RuntimeError("Model is not trained yet. Call .train() or .load() first.")

        X = self._build_feature_matrix([email_text], fit=False)
        proba = self.model.predict_proba(X)[0]
        prediction = int(self.model.predict(X)[0])

        # Extract the raw security features for explanation
        security_features = self.feature_extractor.extract(email_text)

        return {
            'is_phishing': bool(prediction),
            'phishing_probability': float(proba[1]),
            'confidence': float(max(proba)),
            'verdict': 'PHISHING' if prediction == 1 else 'LEGITIMATE',
            'security_signals': security_features,
        }

    def save(self, path):
        """Persist the trained model to disk."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump({
            'vectorizer': self.vectorizer,
            'scaler': self.scaler,
            'model': self.model,
            'feature_names': self.feature_names,
        }, path)
        print(f"✓ Model saved to {path}")

    def load(self, path):
        """Load a previously trained model."""
        data = joblib.load(path)
        self.vectorizer = data['vectorizer']
        self.scaler = data['scaler']
        self.model = data['model']
        self.feature_names = data['feature_names']
        self._is_fitted = True
        print(f"✓ Model loaded from {path}")
        return self

"""
ML-based False Positive Classifier
Uses trained Random Forest model to filter false positives
"""

import json
import joblib
from pathlib import Path
from typing import List, Dict, Any, Tuple

try:
    import numpy as np
    from sklearn.ensemble import RandomForestClassifier
    ML_DEPS_AVAILABLE = True
except ImportError:
    ML_DEPS_AVAILABLE = False

from security_audit.ml.feature_extraction import FeatureExtractor


class MLFPClassifier:
    """
    Machine Learning-based False Positive Classifier

    Uses trained Random Forest model to classify findings as
    real vulnerabilities or false positives.

    Performance (validated on unseen data):
    - Overall: 57.8% FP reduction
    - .NET: 72.4% FP reduction
    - Python: 66.7% FP reduction
    - Java: 55.8% FP reduction
    - PHP/Node.js: ~47% FP reduction
    """

    def __init__(self, model_path: str = None):
        """
        Initialize ML classifier

        Args:
            model_path: Path to trained model file (.pkl)
                       Default: trained_models/fp_classifier_rf.pkl
        """
        if not ML_DEPS_AVAILABLE:
            raise ImportError(
                "ML dependencies not available. "
                "Install: pip install scikit-learn numpy joblib"
            )

        # Default model path
        if model_path is None:
            repo_root = Path(__file__).parent.parent.parent
            model_path = repo_root / "trained_models" / "fp_classifier_rf.pkl"

        self.model_path = Path(model_path)

        # Load model
        if not self.model_path.exists():
            raise FileNotFoundError(
                f"Trained model not found: {self.model_path}\n"
                f"Train model first: python3 security_audit/ml/model_training.py"
            )

        self.model = joblib.load(self.model_path)

        # Initialize feature extractor
        self.feature_extractor = FeatureExtractor()

    def classify_finding(self, finding: Dict[str, Any]) -> Tuple[int, float]:
        """
        Classify a single finding

        Args:
            finding: Finding dictionary

        Returns:
            Tuple of (label, confidence):
            - label: 0 = Real vulnerability, 1 = False positive
            - confidence: Probability (0.0 - 1.0)
        """
        # Extract features
        features = self.feature_extractor.extract(finding)

        # Reshape for single prediction
        X = np.array(features).reshape(1, -1)

        # Predict
        label = self.model.predict(X)[0]

        # Get probability
        probabilities = self.model.predict_proba(X)[0]
        confidence = probabilities[label]

        return label, confidence

    def filter_findings(
        self,
        findings: List[Dict[str, Any]],
        confidence_threshold: float = 0.5
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """
        Filter findings using ML model

        Args:
            findings: List of finding dictionaries
            confidence_threshold: Minimum confidence (default: 0.5)

        Returns:
            Tuple of (real_vulnerabilities, false_positives)
        """
        real_vulnerabilities = []
        false_positives = []

        for finding in findings:
            label, confidence = self.classify_finding(finding)

            # Add metadata
            finding['ml_classification'] = {
                'label': 'false_positive' if label == 1 else 'real_vulnerability',
                'confidence': float(confidence),
                'model': str(self.model_path.name)
            }

            # Classify
            if label == 1 and confidence >= confidence_threshold:
                # False positive with high confidence
                false_positives.append(finding)
            else:
                # Real vulnerability
                real_vulnerabilities.append(finding)

        return real_vulnerabilities, false_positives

    def get_statistics(self, total_findings: int, filtered_findings: int) -> Dict[str, Any]:
        """
        Get statistics (for compatibility with FalsePositiveClassifier)

        Args:
            total_findings: Total number of findings before filtering
            filtered_findings: Number of findings after filtering

        Returns:
            Dictionary with statistics
        """
        filtered_count = total_findings - filtered_findings
        filtered_percentage = (filtered_count / total_findings * 100) if total_findings > 0 else 0

        return {
            'total_findings': total_findings,
            'filtered_count': filtered_count,
            'filtered_percentage': filtered_percentage,
            'remaining_findings': filtered_findings
        }

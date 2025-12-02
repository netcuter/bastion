"""
ML Model Training for FP Classification
Trenuje Random Forest model do klasyfikacji False Positives

Requirements:
    pip install scikit-learn numpy

Usage:
    python3 model_training.py --dataset validation_dataset_auto_labeled.json
"""
import json
import sys
from pathlib import Path
from typing import List, Dict, Tuple, Any

# Import feature extractor
from feature_extraction import FeatureExtractor


class MLModelTrainer:
    """
    Trenuje ML model do klasyfikacji False Positives
    """

    def __init__(self, dataset_path: str):
        self.dataset_path = Path(dataset_path)
        self.extractor = FeatureExtractor()
        self.model = None
        self.metrics = {}

    def load_dataset(self) -> Tuple[List[List[float]], List[int]]:
        """
        Load dataset and extract features

        Returns:
            (X, y) where X = feature matrix, y = labels
        """
        print(f"📂 Loading dataset: {self.dataset_path}")

        with open(self.dataset_path, 'r') as f:
            data = json.load(f)

        print(f"   Total samples: {len(data)}")

        # Extract features and labels
        X = []
        y = []

        for sample in data:
            finding = sample['finding']
            label = sample['label']  # 0 = real vuln, 1 = FP

            # Extract features
            features = self.extractor.extract(finding)
            X.append(features)
            y.append(label)

        print(f"   Features per sample: {len(X[0])}")
        print(f"   Real vulnerabilities: {y.count(0)}")
        print(f"   False positives: {y.count(1)}")

        return X, y

    def train_random_forest(self, X_train, y_train, X_test, y_test):
        """
        Train Random Forest classifier
        """
        try:
            from sklearn.ensemble import RandomForestClassifier
            from sklearn.model_selection import cross_val_score
            from sklearn.metrics import classification_report, confusion_matrix
        except ImportError:
            print("❌ scikit-learn not installed!")
            print("   Install with: pip install scikit-learn")
            return None

        print("\n" + "="*70)
        print("TRAINING RANDOM FOREST MODEL")
        print("="*70)

        # Initialize model
        print("\n[1/5] Initializing Random Forest...")
        self.model = RandomForestClassifier(
            n_estimators=100,      # 100 trees
            max_depth=10,          # Max depth 10
            min_samples_split=5,   # Require 5 samples to split
            min_samples_leaf=2,    # Require 2 samples in leaf
            class_weight='balanced',  # Handle imbalanced data
            random_state=42,       # Reproducibility
            n_jobs=-1              # Use all CPU cores
        )

        # Cross-validation on training set
        print("\n[2/5] Running 5-fold cross-validation...")
        cv_scores = cross_val_score(
            self.model, X_train, y_train,
            cv=5, scoring='f1', n_jobs=-1
        )
        print(f"   CV F1-scores: {cv_scores}")
        print(f"   Mean F1: {cv_scores.mean():.3f} (+/- {cv_scores.std():.3f})")

        # Train on full training set
        print("\n[3/5] Training on full training set...")
        self.model.fit(X_train, y_train)
        print("   ✅ Training complete!")

        # Evaluate on test set
        print("\n[4/5] Evaluating on test set...")
        y_pred = self.model.predict(X_test)

        print("\n" + classification_report(
            y_test, y_pred,
            target_names=['Real Vulnerability', 'False Positive'],
            digits=3
        ))

        # Confusion matrix
        cm = confusion_matrix(y_test, y_pred)
        print("Confusion Matrix:")
        print(f"                   Predicted")
        print(f"                   Real    FP")
        print(f"  Actual Real    {cm[0][0]:5d}  {cm[0][1]:5d}")
        print(f"  Actual FP      {cm[1][0]:5d}  {cm[1][1]:5d}")

        # Feature importance
        print("\n[5/5] Feature Importance (Top 15):")
        feature_names = self.extractor.get_feature_names()
        importances = self.model.feature_importances_

        # Sort by importance
        indices = sorted(range(len(importances)), key=lambda i: importances[i], reverse=True)

        for i in indices[:15]:
            print(f"   {feature_names[i]:40s} {importances[i]:.4f}")

        # Save metrics
        from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

        self.metrics = {
            'accuracy': accuracy_score(y_test, y_pred),
            'precision': precision_score(y_test, y_pred),
            'recall': recall_score(y_test, y_pred),
            'f1_score': f1_score(y_test, y_pred),
            'cv_mean_f1': cv_scores.mean(),
            'cv_std_f1': cv_scores.std(),
            'confusion_matrix': cm.tolist()
        }

        print("\n" + "="*70)
        print(f"FINAL METRICS:")
        print(f"  Accuracy:  {self.metrics['accuracy']:.3f}")
        print(f"  Precision: {self.metrics['precision']:.3f}")
        print(f"  Recall:    {self.metrics['recall']:.3f}")
        print(f"  F1-Score:  {self.metrics['f1_score']:.3f}")
        print("="*70 + "\n")

        return self.model

    def save_model(self, output_path: str):
        """
        Save trained model to file
        """
        try:
            import joblib
        except ImportError:
            print("⚠️  joblib not installed - cannot save model")
            print("   Install with: pip install joblib")
            return

        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        # Save model
        model_file = output_path / 'fp_classifier_rf.pkl'
        joblib.dump(self.model, model_file)
        print(f"✅ Model saved: {model_file}")

        # Save feature extractor
        extractor_file = output_path / 'feature_extractor.pkl'
        joblib.dump(self.extractor, extractor_file)
        print(f"✅ Feature extractor saved: {extractor_file}")

        # Save metrics
        metrics_file = output_path / 'model_metrics.json'
        with open(metrics_file, 'w') as f:
            json.dump(self.metrics, f, indent=2)
        print(f"✅ Metrics saved: {metrics_file}")

    def run_training(self, test_size: float = 0.2, output_dir: str = 'trained_models'):
        """
        Run full training pipeline
        """
        try:
            from sklearn.model_selection import train_test_split
        except ImportError:
            print("❌ scikit-learn not installed!")
            print("   Install with: pip install scikit-learn")
            return

        print("🚀 ML Model Training Pipeline")
        print("="*70)

        # Load dataset
        X, y = self.load_dataset()

        # Split train/test
        print(f"\n📊 Splitting dataset ({int((1-test_size)*100)}% train / {int(test_size*100)}% test)...")
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_size, random_state=42, stratify=y
        )
        print(f"   Training set: {len(X_train)} samples")
        print(f"   Test set: {len(X_test)} samples")

        # Train model
        model = self.train_random_forest(X_train, y_train, X_test, y_test)

        if model is None:
            print("❌ Training failed!")
            return

        # Save model
        print(f"\n💾 Saving model to {output_dir}...")
        self.save_model(output_dir)

        # Print summary
        print("\n" + "="*70)
        print("✅ TRAINING COMPLETE!")
        print("="*70)
        print(f"Model: Random Forest (100 trees)")
        print(f"Features: {len(X[0])}")
        print(f"Training samples: {len(X_train)}")
        print(f"Test F1-Score: {self.metrics['f1_score']:.3f}")
        print(f"CV F1-Score: {self.metrics['cv_mean_f1']:.3f} (+/- {self.metrics['cv_std_f1']:.3f})")
        print("\nNext steps:")
        print("  1. Review model_metrics.json")
        print("  2. Test on real scans")
        print("  3. Integrate into security_audit_cli.py")
        print("="*70 + "\n")


def main():
    """CLI interface"""
    import argparse

    parser = argparse.ArgumentParser(description='Train ML model for FP classification')
    parser.add_argument('--dataset', type=str, default='validation_dataset_auto_labeled.json',
                       help='Path to labeled dataset')
    parser.add_argument('--output', type=str, default='trained_models',
                       help='Output directory for trained model')
    parser.add_argument('--test-size', type=float, default=0.2,
                       help='Test set size (default: 0.2 = 20%%)')

    args = parser.parse_args()

    trainer = MLModelTrainer(args.dataset)
    trainer.run_training(test_size=args.test_size, output_dir=args.output)


if __name__ == '__main__':
    main()

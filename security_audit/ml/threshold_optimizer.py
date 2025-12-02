"""
Threshold Optimizer
Znajduje optymalny threshold dla FP Classifier poprzez testowanie na validation dataset

Output:
- Precision/Recall/F1 dla każdego threshold
- ROC curve (wymaga matplotlib - optional)
- Optimal threshold recommendation
"""
import json
from pathlib import Path
from typing import List, Dict, Tuple, Any
import sys

# Import existing classifier
sys.path.append(str(Path(__file__).parent.parent))
from ml.fp_classifier import FalsePositiveClassifier


class ThresholdOptimizer:
    """
    Optymalizuje threshold dla FP Classifier
    """

    def __init__(self, validation_dataset_path: str):
        self.validation_dataset_path = Path(validation_dataset_path)
        self.classifier = FalsePositiveClassifier()
        self.validation_data = self._load_validation_data()

    def _load_validation_data(self) -> List[Dict[str, Any]]:
        """Load validation dataset"""
        with open(self.validation_dataset_path, 'r') as f:
            data = json.load(f)

        print(f"✅ Loaded {len(data)} validation samples")

        # Check for labels
        labeled = [d for d in data if d.get('label') is not None]
        print(f"   Labeled: {len(labeled)}/{len(data)}")

        if len(labeled) < len(data):
            print(f"⚠️  WARNING: {len(data) - len(labeled)} samples without labels!")
            print(f"   Using only labeled samples")

        return labeled

    def evaluate_threshold(self, threshold: float) -> Dict[str, Any]:
        """
        Evaluate classifier performance at given threshold

        Returns metrics: precision, recall, F1, accuracy
        """
        true_positives = 0   # Correctly predicted FP
        false_positives = 0  # Incorrectly predicted as FP (actually real vuln)
        true_negatives = 0   # Correctly predicted real vuln
        false_negatives = 0  # Incorrectly predicted as real (actually FP)

        predictions = []

        for sample in self.validation_data:
            finding = sample['finding']
            true_label = sample['label']  # 0 = real vuln, 1 = FP

            # Predict with current threshold
            is_fp, confidence, reason = self.classifier.predict_false_positive(finding)

            # Override threshold
            is_fp_at_threshold = confidence >= threshold
            predicted_label = 1 if is_fp_at_threshold else 0

            predictions.append({
                'true_label': true_label,
                'predicted_label': predicted_label,
                'confidence': confidence,
                'threshold': threshold
            })

            # Update confusion matrix
            if true_label == 1 and predicted_label == 1:
                true_positives += 1
            elif true_label == 0 and predicted_label == 1:
                false_positives += 1
            elif true_label == 0 and predicted_label == 0:
                true_negatives += 1
            elif true_label == 1 and predicted_label == 0:
                false_negatives += 1

        # Calculate metrics
        total = len(self.validation_data)

        # Precision: Of all predicted FPs, how many were actually FP?
        precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0

        # Recall: Of all actual FPs, how many did we catch?
        recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0

        # F1-Score: Harmonic mean of precision and recall
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0

        # Accuracy: Overall correctness
        accuracy = (true_positives + true_negatives) / total if total > 0 else 0

        return {
            'threshold': threshold,
            'precision': precision,
            'recall': recall,
            'f1_score': f1,
            'accuracy': accuracy,
            'true_positives': true_positives,
            'false_positives': false_positives,
            'true_negatives': true_negatives,
            'false_negatives': false_negatives,
            'total_samples': total
        }

    def test_multiple_thresholds(self, thresholds: List[float] = None) -> List[Dict]:
        """
        Test multiple thresholds and return results
        """
        if thresholds is None:
            # Default: test from 0.40 to 0.85 in 0.05 steps
            thresholds = [round(t, 2) for t in [i * 0.05 for i in range(8, 18)]]

        print(f"\n{'='*70}")
        print(f"THRESHOLD OPTIMIZATION")
        print(f"{'='*70}")
        print(f"Testing {len(thresholds)} thresholds: {thresholds}")
        print(f"Validation samples: {len(self.validation_data)}\n")

        results = []

        for threshold in thresholds:
            metrics = self.evaluate_threshold(threshold)
            results.append(metrics)

            print(f"Threshold {threshold:.2f}:")
            print(f"  Precision: {metrics['precision']:.3f}")
            print(f"  Recall:    {metrics['recall']:.3f}")
            print(f"  F1-Score:  {metrics['f1_score']:.3f}")
            print(f"  Accuracy:  {metrics['accuracy']:.3f}")
            print()

        return results

    def find_optimal_threshold(self, results: List[Dict]) -> Dict:
        """
        Find optimal threshold based on F1-score
        """
        best = max(results, key=lambda x: x['f1_score'])

        print(f"\n{'='*70}")
        print(f"OPTIMAL THRESHOLD")
        print(f"{'='*70}")
        print(f"Best threshold: {best['threshold']:.2f}")
        print(f"F1-Score:       {best['f1_score']:.3f}")
        print(f"Precision:      {best['precision']:.3f}")
        print(f"Recall:         {best['recall']:.3f}")
        print(f"Accuracy:       {best['accuracy']:.3f}")
        print(f"\nConfusion Matrix:")
        print(f"  True Positives:  {best['true_positives']}")
        print(f"  False Positives: {best['false_positives']}")
        print(f"  True Negatives:  {best['true_negatives']}")
        print(f"  False Negatives: {best['false_negatives']}")
        print(f"{'='*70}\n")

        return best

    def plot_roc_curve(self, results: List[Dict], output_file: str = None):
        """
        Plot ROC curve and metrics vs threshold

        Requires matplotlib (optional)
        """
        try:
            import matplotlib.pyplot as plt
        except ImportError:
            print("⚠️  matplotlib not installed - skipping plot")
            print("   Install with: pip install matplotlib")
            return

        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(14, 10))

        thresholds = [r['threshold'] for r in results]
        precisions = [r['precision'] for r in results]
        recalls = [r['recall'] for r in results]
        f1_scores = [r['f1_score'] for r in results]
        accuracies = [r['accuracy'] for r in results]

        # Plot 1: Precision vs Threshold
        ax1.plot(thresholds, precisions, 'b-o', label='Precision')
        ax1.set_xlabel('Threshold')
        ax1.set_ylabel('Precision')
        ax1.set_title('Precision vs Threshold')
        ax1.grid(True, alpha=0.3)
        ax1.legend()

        # Plot 2: Recall vs Threshold
        ax2.plot(thresholds, recalls, 'r-o', label='Recall')
        ax2.set_xlabel('Threshold')
        ax2.set_ylabel('Recall')
        ax2.set_title('Recall vs Threshold')
        ax2.grid(True, alpha=0.3)
        ax2.legend()

        # Plot 3: F1-Score vs Threshold
        ax3.plot(thresholds, f1_scores, 'g-o', label='F1-Score')
        ax3.set_xlabel('Threshold')
        ax3.set_ylabel('F1-Score')
        ax3.set_title('F1-Score vs Threshold')
        ax3.grid(True, alpha=0.3)
        ax3.legend()

        # Mark optimal
        best = max(results, key=lambda x: x['f1_score'])
        ax3.axvline(x=best['threshold'], color='r', linestyle='--', alpha=0.5, label=f"Optimal: {best['threshold']:.2f}")
        ax3.legend()

        # Plot 4: All metrics together
        ax4.plot(thresholds, precisions, 'b-o', label='Precision', alpha=0.7)
        ax4.plot(thresholds, recalls, 'r-o', label='Recall', alpha=0.7)
        ax4.plot(thresholds, f1_scores, 'g-o', label='F1-Score', alpha=0.7)
        ax4.plot(thresholds, accuracies, 'm-o', label='Accuracy', alpha=0.7)
        ax4.set_xlabel('Threshold')
        ax4.set_ylabel('Score')
        ax4.set_title('All Metrics vs Threshold')
        ax4.grid(True, alpha=0.3)
        ax4.legend()
        ax4.axvline(x=best['threshold'], color='k', linestyle='--', alpha=0.3)

        plt.suptitle('Threshold Optimization - FP Classifier', fontsize=14, fontweight='bold')
        plt.tight_layout()

        if output_file:
            plt.savefig(output_file, dpi=150, bbox_inches='tight')
            print(f"✅ Plot saved: {output_file}")
        else:
            plt.show()

    def generate_report(self, results: List[Dict], output_file: str):
        """
        Generate detailed optimization report
        """
        report = {
            'validation_dataset': str(self.validation_dataset_path),
            'total_samples': len(self.validation_data),
            'thresholds_tested': [r['threshold'] for r in results],
            'results': results,
            'optimal_threshold': max(results, key=lambda x: x['f1_score'])
        }

        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)

        print(f"✅ Detailed report saved: {output_file}")

    def run_optimization(self, output_dir: str = '.'):
        """
        Run full optimization pipeline
        """
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        # 1. Test thresholds
        results = self.test_multiple_thresholds()

        # 2. Find optimal
        optimal = self.find_optimal_threshold(results)

        # 3. Generate report
        report_file = output_dir / 'threshold_optimization_report.json'
        self.generate_report(results, report_file)

        # 4. Plot (if matplotlib available)
        plot_file = output_dir / 'threshold_optimization_plot.png'
        self.plot_roc_curve(results, plot_file)

        # 5. Print recommendation
        print("\n" + "="*70)
        print("RECOMMENDATION")
        print("="*70)
        print(f"Update fp_classifier.py threshold from 0.65 to {optimal['threshold']:.2f}")
        print(f"\nExpected improvement:")
        current_f1 = next((r['f1_score'] for r in results if r['threshold'] == 0.65), 0)
        improvement = ((optimal['f1_score'] - current_f1) / current_f1 * 100) if current_f1 > 0 else 0
        print(f"  F1-Score: {current_f1:.3f} → {optimal['f1_score']:.3f} (+{improvement:.1f}%)")
        print("="*70)

        return optimal


def main():
    """CLI interface"""
    import argparse

    parser = argparse.ArgumentParser(description='Optimize FP Classifier threshold')
    parser.add_argument('--dataset', type=str, default='validation_dataset_auto_labeled.json',
                       help='Path to validation dataset')
    parser.add_argument('--output', type=str, default='threshold_optimization_results',
                       help='Output directory for results')

    args = parser.parse_args()

    optimizer = ThresholdOptimizer(args.dataset)
    optimizer.run_optimization(args.output)


if __name__ == '__main__':
    main()

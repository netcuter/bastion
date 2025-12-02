"""
Test ML Model on UNSEEN Data
Prawdziwy test generalizacji - aplikacje których model NIGDY nie widział!

Unseen apps:
1. OWASP Juice Shop (Node.js/Angular)
2. OWASP WebGoat (Java/Spring)
3. ASP.NET Vulnerable Lab (C#/.NET)
"""
import json
import sys
from pathlib import Path

# Import ML components
sys.path.append('security_audit/ml')
from feature_extraction import FeatureExtractor
import joblib


def test_on_unseen_data(model_path: str, test_results_files: list):
    """
    Test trained model on unseen vulnerable applications
    """
    print(" TESTING ML MODEL ON UNSEEN DATA")
    print("="*70)

    # Load model
    print(f"\n[1/4] Loading trained model...")
    model = joblib.load(model_path)
    extractor = joblib.load('trained_models/feature_extractor.pkl')
    print(f"   ✅ Model loaded: {model_path}")

    all_results = []

    for test_file in test_results_files:
        print(f"\n[2/4] Loading test data: {test_file}")

        with open(test_file, 'r') as f:
            data = json.load(f)

        findings = data.get('findings', [])
        app_name = test_file.replace('test_results_', '').replace('.json', '')

        print(f"   Total findings: {len(findings)}")

        # Extract features
        print(f"\n[3/4] Extracting features...")
        X = extractor.extract_batch(findings)
        print(f"   Features extracted: {len(X)} samples, {len(X[0]) if X else 0} features each")

        # Predict
        print(f"\n[4/4] Running predictions...")
        predictions = model.predict(X)
        probabilities = model.predict_proba(X)

        # Count results
        real_vulns = sum(1 for p in predictions if p == 0)
        false_positives = sum(1 for p in predictions if p == 1)

        # Calculate average confidence
        fp_confidences = [prob[1] for i, prob in enumerate(probabilities) if predictions[i] == 1]
        real_confidences = [prob[0] for i, prob in enumerate(probabilities) if predictions[i] == 0]

        avg_confidence_fp = sum(fp_confidences) / len(fp_confidences) if fp_confidences else 0
        avg_confidence_real = sum(real_confidences) / len(real_confidences) if real_confidences else 0

        results = {
            'app': app_name,
            'total_findings': len(findings),
            'predicted_real_vulns': real_vulns,
            'predicted_false_positives': false_positives,
            'fp_reduction_pct': round(false_positives / len(findings) * 100, 1),
            'avg_confidence_fp': round(avg_confidence_fp, 3),
            'avg_confidence_real': round(avg_confidence_real, 3)
        }

        all_results.append(results)

        print(f"\n   📊 RESULTS FOR {app_name.upper()}:")
        print(f"      Total findings:        {results['total_findings']}")
        print(f"      → Real vulnerabilities: {results['predicted_real_vulns']} ({100-results['fp_reduction_pct']:.1f}%)")
        print(f"      → False positives:      {results['predicted_false_positives']} ({results['fp_reduction_pct']:.1f}%)")
        print(f"      FP Reduction:          {results['fp_reduction_pct']:.1f}%")
        print(f"      Avg confidence (FP):   {results['avg_confidence_fp']:.1%}")
        print(f"      Avg confidence (Real): {results['avg_confidence_real']:.1%}")

    # Summary
    print(f"\n" + "="*70)
    print("AGGREGATE RESULTS - UNSEEN DATA")
    print("="*70)

    total_findings = sum(r['total_findings'] for r in all_results)
    total_fp = sum(r['predicted_false_positives'] for r in all_results)
    total_real = sum(r['predicted_real_vulns'] for r in all_results)

    print(f"\nTotal findings across all apps: {total_findings}")
    print(f"Predicted real vulnerabilities: {total_real} ({total_real/total_findings*100:.1f}%)")
    print(f"Predicted false positives:      {total_fp} ({total_fp/total_findings*100:.1f}%)")
    print(f"\nOverall FP Reduction:           {total_fp/total_findings*100:.1f}%")

    print(f"\n" + "="*70)
    print("COMPARISON WITH TRAINING DATA PERFORMANCE")
    print("="*70)

    with open('trained_models/model_metrics.json', 'r') as f:
        training_metrics = json.load(f)

    print(f"\nTraining data metrics:")
    print(f"  F1-Score:  {training_metrics['f1_score']:.1%}")
    print(f"  Precision: {training_metrics['precision']:.1%}")
    print(f"  Recall:    {training_metrics['recall']:.1%}")

    print(f"\nUnseen data metrics:")
    print(f"  FP Reduction: {total_fp/total_findings*100:.1f}%")
    print(f"  (Note: Cannot calculate F1/Precision/Recall without manual labels)")

    print(f"\n⚠️  IMPORTANT: To validate true performance, we need manual labeling!")
    print(f"   Recommendation: Manually review sample of {min(100, total_findings)} findings")

    # Save results
    output_file = 'ml_model_unseen_test_results.json'
    with open(output_file, 'w') as f:
        json.dump({
            'model': str(model_path),
            'test_apps': [r['app'] for r in all_results],
            'results': all_results,
            'aggregate': {
                'total_findings': total_findings,
                'predicted_real_vulns': total_real,
                'predicted_false_positives': total_fp,
                'fp_reduction_pct': round(total_fp/total_findings*100, 1)
            }
        }, f, indent=2)

    print(f"\n✅ Results saved: {output_file}")
    print("="*70 + "\n")

    return all_results


if __name__ == '__main__':
    # Test on UNSEEN applications (50% split per language - testing apps)
    unseen_apps = [
        # PHP (1 app)
        'test_results_mutillidae.json',    # Mutillidae II (PHP) - NOT in training!

        # Python (2 apps)
        'test_results_vulnpy.json',        # Vulnpy (Python) - NOT in training!
        'test_results_dvpwa.json',         # DVPWA (Python) - NOT in training!

        # Node.js (1 app)
        'test_results_dvna.json',          # DVNA (Node.js) - NOT in training!

        # Java (1 app)
        'test_results_vulnerableapp.json', # VulnerableApp (Java) - NOT in training!

        # .NET (1 app)
        'test_results_webgoatnet.json',    # WebGoat.NET (C#/.NET) - NOT in training!
    ]

    results = test_on_unseen_data('trained_models/fp_classifier_rf.pkl', unseen_apps)

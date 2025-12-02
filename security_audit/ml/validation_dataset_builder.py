"""
Validation Dataset Builder
Tworzy zbiór walidacyjny z prawdziwych skanów do threshold optimization

Proces:
1. Ładuje findings z JSON test results
2. Filtruje przykłady do ręcznego labelowania
3. Zapisuje validation dataset
"""
import json
import random
from pathlib import Path
from typing import List, Dict, Any


class ValidationDatasetBuilder:
    """
    Buduje validation dataset z rzeczywistych skanów
    """

    def __init__(self, project_root: Path = None):
        self.project_root = project_root or Path(__file__).parent.parent.parent

        # 50% apps for TRAINING (1-2 apps PER LANGUAGE)
        self.training_apps = [
            # PHP (2 apps)
            'test_results_dvwa_php.json',      # PHP - DVWA (643 findings)
            'test_results_bwapp.json',         # PHP - bWAPP (2,527 findings)

            # Python (2 apps)
            'test_results_pygoat.json',        # Python - Django (456 findings)
            'test_results_flask.json',         # Python - Flask (94 findings)

            # Node.js (2 apps)
            'test_results_juiceshop.json',     # Node.js - Juice Shop (6,266 findings)
            'test_results_nodegoat.json',      # Node.js - NodeGoat (278 findings)

            # Java (2 apps)
            'test_results_webgoat.json',       # Java - WebGoat (1,601 findings)
            'test_results_javaseccode.json',   # Java - Java Sec Code (328 findings)

            # .NET (1 app - only have 2 total)
            'test_results_aspnet.json',        # C#/.NET - ASP.NET Lab (120 findings)
        ]

        # 50% apps for TESTING (at least 1 app PER LANGUAGE)
        self.testing_apps = [
            # PHP (1 app)
            'test_results_mutillidae.json',    # PHP - Mutillidae II (1,253 findings)

            # Python (2 apps)
            'test_results_vulnpy.json',        # Python - Vulnpy (222 findings)
            'test_results_dvpwa.json',         # Python - DVPWA (150 findings)

            # Node.js (1 app)
            'test_results_dvna.json',          # Node.js - DVNA (55 findings)

            # Java (1 app)
            'test_results_vulnerableapp.json', # Java - VulnerableApp (394 findings)

            # .NET (1 app)
            'test_results_webgoatnet.json',    # C#/.NET - WebGoat.NET (771 findings)
        ]

        # Default: use training apps
        self.test_results_files = self.training_apps

    def load_findings_from_tests(self) -> List[Dict[str, Any]]:
        """
        Ładuje wszystkie findings z test results
        """
        all_findings = []

        for filename in self.test_results_files:
            filepath = self.project_root / filename

            if not filepath.exists():
                print(f"⚠️  Skipping {filename} (not found)")
                continue

            try:
                with open(filepath, 'r') as f:
                    data = json.load(f)
                    findings = data.get('findings', [])
                    all_findings.extend(findings)
                    print(f"✅ Loaded {len(findings)} findings from {filename}")
            except Exception as e:
                print(f"❌ Error loading {filename}: {e}")

        return all_findings

    def sample_diverse_findings(self, findings: List[Dict], n_samples: int = 200) -> List[Dict]:
        """
        Wybiera różnorodną próbkę findings do labelowania

        Strategie:
        - Balance by severity (Critical, High, Medium, Low)
        - Balance by vulnerability type
        - Include edge cases (test files, docs, config)
        """
        # Group by severity
        by_severity = {}
        for finding in findings:
            severity = finding.get('severity', 'UNKNOWN')
            if severity not in by_severity:
                by_severity[severity] = []
            by_severity[severity].append(finding)

        # Sample proportionally
        samples = []
        samples_per_severity = n_samples // len(by_severity)

        for severity, severity_findings in by_severity.items():
            n_to_sample = min(samples_per_severity, len(severity_findings))
            sampled = random.sample(severity_findings, n_to_sample)
            samples.extend(sampled)
            print(f"  {severity}: sampled {n_to_sample}/{len(severity_findings)}")

        # Shuffle
        random.shuffle(samples)

        return samples[:n_samples]

    def export_for_labeling(self, samples: List[Dict], output_file: str):
        """
        Eksportuje samples do pliku do ręcznego labelowania

        Format:
        [
            {
                "id": 1,
                "finding": {...},
                "label": null,  # To fill: 0 = real vuln, 1 = false positive
                "notes": ""     # Optional notes
            }
        ]
        """
        labeled_dataset = []

        for i, finding in enumerate(samples, 1):
            labeled_dataset.append({
                'id': i,
                'finding': {
                    'title': finding.get('title', 'Unknown'),
                    'severity': finding.get('severity', 'Unknown'),
                    'file_path': finding.get('file_path', ''),
                    'line_number': finding.get('line_number', 0),
                    'code_snippet': finding.get('code_snippet', ''),
                    'description': finding.get('description', ''),
                },
                'label': None,  # 0 = real vuln, 1 = false positive
                'notes': ''
            })

        output_path = self.project_root / output_file

        with open(output_path, 'w') as f:
            json.dump(labeled_dataset, f, indent=2)

        print(f"\n✅ Exported {len(labeled_dataset)} samples to {output_file}")
        print(f"📝 Manual labeling needed:")
        print(f"   - Open {output_file}")
        print(f"   - For each finding, set 'label': 0 (real) or 1 (FP)")
        print(f"   - Save and use for threshold optimization")

    def create_quick_labeled_subset(self, findings: List[Dict]) -> List[Dict]:
        """
        Tworzy szybki labeled subset bazując na prostych heurystykach
        (dla szybkiego prototypowania - później zastąp ręcznym labelowaniem)

        Heurystyki dla vulnerable apps (DVWA, PyGoat, etc.):
        - DEFAULT: likely REAL (these are intentionally vulnerable!)
        - Exception: Comment examples, obvious FP patterns → FP

        FP indicators:
        - Empty code snippets (ASVS headers often FP)
        - "Example:" in code
        - URLs in credits/about pages
        """
        labeled = []

        for finding in findings:
            file_path = finding.get('file_path', '').lower()
            title = finding.get('title', '').lower()
            code = finding.get('code_snippet', '').strip()
            description = finding.get('description', '').lower()

            # Auto-label based on heuristics
            label = 0  # Default: REAL vulnerability (vulnerable apps!)

            # FALSE POSITIVE indicators:

            # 1. Empty code snippet (often ASVS "missing headers" - file-level, not code-level)
            if not code or len(code) < 10:
                label = 1  # FP

            # 2. ASVS "Missing Security Headers" - often FP (generic file-level finding)
            elif 'missing security headers' in title:
                label = 1

            # 3. "Weak Cryptography" generic without actual crypto code
            elif 'weak cryptography' in title and 'crypto' not in code.lower() and 'hash' not in code.lower():
                label = 1

            # 4. HTTP URLs in about/credits pages (not real vuln, just links)
            elif 'insecure http' in title and ('about.php' in file_path or 'credits' in file_path):
                label = 1

            # 5. Comment/documentation examples
            elif '# Example' in code or '// Example' in code or '"""Example' in code:
                label = 1

            # 6. Missing CSRF on GET endpoints (CSRF only affects POST/PUT/DELETE)
            elif 'csrf' in title and 'GET' in code and 'POST' not in code:
                label = 1

            # REAL VULNERABILITY strong indicators (even though default is 0):

            # SQL Injection with string formatting/concat
            if 'sql injection' in title and any(p in code for p in ['f"', "f'", ' + ', ' % ', '.format(']):
                label = 0

            # XSS with innerHTML/dangerouslySetInnerHTML
            elif ('xss' in title or 'cross-site scripting' in title) and ('innerhtml' in code.lower() or 'dangerouslysetinnerhtml' in code.lower()):
                label = 0

            # Command Injection with os.system/exec/shell=True
            elif 'command injection' in title and any(p in code.lower() for p in ['os.system', 'subprocess.', 'exec(', 'shell=true']):
                label = 0

            # Deserialization with pickle/yaml.load
            elif 'deserialization' in title and any(p in code.lower() for p in ['pickle.load', 'yaml.load', 'unserialize']):
                label = 0

            # Path Traversal with file operations
            elif 'path traversal' in title and any(p in code.lower() for p in ['open(', 'file(', 'read(', '../']):
                label = 0

            # Hardcoded credentials (actual secrets)
            elif 'hardcoded' in title and any(p in code for p in ['password =', 'api_key =', 'secret =', 'token =']):
                label = 0

            labeled.append({
                'finding': finding,
                'label': label,
                'auto_labeled': True
            })

        return labeled

    def build(self, n_samples: int = 200, output_file: str = 'validation_dataset_unlabeled.json'):
        """
        Main method: build validation dataset
        """
        print("🔨 Building Validation Dataset")
        print("="*60)

        # 1. Load findings
        print("\n[1/3] Loading findings from test results...")
        all_findings = self.load_findings_from_tests()
        print(f"   Total findings loaded: {len(all_findings)}")

        # 2. Sample diverse subset
        print(f"\n[2/3] Sampling {n_samples} diverse findings...")
        samples = self.sample_diverse_findings(all_findings, n_samples)

        # 3. Export for labeling
        print(f"\n[3/3] Exporting to {output_file}...")
        self.export_for_labeling(samples, output_file)

        print("\n✅ Validation dataset ready!")
        print(f"   Next step: Manually label {output_file}")
        print(f"   Then use for threshold optimization\n")

        return samples

    def build_auto_labeled(self, max_samples: int = 500):
        """
        Buduje auto-labeled dataset (heurystyki) dla szybkiego prototypowania
        """
        print("🤖 Building Auto-Labeled Dataset (Heuristics)")
        print("="*60)

        # Load all findings
        all_findings = self.load_findings_from_tests()
        print(f"Total findings: {len(all_findings)}")

        # Auto-label
        print("\nAuto-labeling based on heuristics...")
        labeled = self.create_quick_labeled_subset(all_findings)
        print(f"Auto-labeled: {len(labeled)} findings")

        # Balance
        real_vulns = [x for x in labeled if x['label'] == 0]
        false_positives = [x for x in labeled if x['label'] == 1]

        print(f"  Real vulnerabilities: {len(real_vulns)}")
        print(f"  False positives: {len(false_positives)}")

        # Limit to max_samples (balanced)
        n_per_class = min(max_samples // 2, len(real_vulns), len(false_positives))
        balanced = (
            random.sample(real_vulns, n_per_class) +
            random.sample(false_positives, n_per_class)
        )
        random.shuffle(balanced)

        # Save
        output_file = self.project_root / 'validation_dataset_auto_labeled.json'
        with open(output_file, 'w') as f:
            json.dump(balanced, f, indent=2)

        print(f"\n✅ Auto-labeled dataset saved: {output_file}")
        print(f"   Total samples: {len(balanced)}")
        print(f"   Real vulnerabilities: {n_per_class}")
        print(f"   False positives: {n_per_class}")
        print(f"\n⚠️  WARNING: Auto-labeling is approximate!")
        print(f"   For production: manually review and correct labels\n")

        return balanced


def main():
    """CLI interface"""
    import argparse

    parser = argparse.ArgumentParser(description='Build validation dataset for ML optimization')
    parser.add_argument('--samples', type=int, default=200, help='Number of samples')
    parser.add_argument('--auto-label', action='store_true', help='Use auto-labeling (heuristics)')

    args = parser.parse_args()

    builder = ValidationDatasetBuilder()

    if args.auto_label:
        builder.build_auto_labeled(max_samples=args.samples)
    else:
        builder.build(n_samples=args.samples)


if __name__ == '__main__':
    main()

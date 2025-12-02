# 🧠 ML Model Optimization - Propozycje Rozwoju

**Data utworzenia:** 2025-11-15
**Wersja:** 1.0

---

## 📋 Spis Treści

1. [Wprowadzenie](#wprowadzenie)
2. [Aktualny Stan Systemu](#aktualny-stan-systemu)
3. [Propozycje Optymalizacji](#propozycje-optymalizacji)
4. [Rekomendowany Plan Wdrożenia](#rekomendowany-plan-wdrożenia)
5. [Szczegóły Techniczne](#szczegóły-techniczne)

---

## 📖 Wprowadzenie

### Co to jest ML Model Optimization?

**UWAGA:** NIE chodzi o trening dużego modelu LLM (jak GPT)!

System Security Scanner v2.5.1 składa się z **3 warstw detekcji**:

```
┌─────────────────────────────────────────────────────────────┐
│  WARSTWA 1: SAST Scanner                                    │
│  └─ Znajduje potencjalne podatności (high recall)           │
│     Output: ~9,552 findings w testach                       │
└─────────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────────┐
│  WARSTWA 2: ML Classifier (fp_classifier.py) ← DO TRENINGU  │
│  └─ Filtruje false positives (precision improvement)        │
│     Output: ~70% redukcja FP (rule-based)                   │
└─────────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────────┐
│  WARSTWA 3: AI Assistant (LLM via LM Studio) - JUŻ GOTOWY   │
│  └─ Deep analysis pozostałych findings                      │
│     Output: Final verification z uzasadnieniem              │
└─────────────────────────────────────────────────────────────┘
```

**Cel optymalizacji:** Ulepszyć **WARSTWĘ 2** (mały ML classifier)

---

## 🔍 Aktualny Stan Systemu

### 1. False Positive Classifier (`security_audit/ml/fp_classifier.py`)

**Architektura:**
- **Typ:** Rule-based hybrid system (nie prawdziwy ML model)
- **Metoda:** Heuristic scoring (0.0 - 1.0)
- **Decision threshold:** 0.65
- **Model size:** ~10KB (kod Python)
- **Prediction time:** <0.001s per finding

**Features wykorzystywane do klasyfikacji:**

| Feature | Weight | Przykład Detection |
|---------|--------|-------------------|
| Test file detection | +0.6 | `/tests/`, `test_*.py`, `__tests__/` |
| Documentation | +0.5 | `/docs/`, `# Example:`, `"""Example` |
| Safe patterns | +0.5 | `.filter()`, `prepare()`, ORM methods |
| Sanitization | +0.4 | `escape()`, `DOMPurify`, `shlex.quote` |
| Safe variables | +0.3 | `safe_`, `_clean`, `sanitized_` |
| Framework methods | +0.4 | Django ORM, parameterized queries |

**Decision logic:**
```python
score = 0.0
score += 0.6 if is_test_file else 0
score += 0.5 if is_documentation else 0
score += 0.5 if has_safe_patterns else 0
score += 0.4 if has_sanitization else 0
score += 0.3 if has_safe_variables else 0
score += 0.4 if has_framework_safety else 0

is_false_positive = (score >= 0.65)
```

**⚠️ Problemy:**
- Threshold 0.65 wybrany arbitralnie (nie optymalnie)
- Brak uczenia się z danych (fixed rules)
- Ograniczone features (tylko 6 kategorii)
- Brak adaptacji do nowych wzorców

---

### 2. Training Data Generator (`security_audit/ml/training_data.py`)

**Statystyki obecnych danych:**
```
Total examples:        40
Real vulnerabilities:  20 (50%)
False positives:       20 (50%)
```

**Coverage by vulnerability type:**
- **SQL Injection:** 7 examples (3 real + 4 FP)
- **XSS:** 6 examples (3 real + 3 FP)
- **Command Injection:** 6 examples (3 real + 3 FP)
- **Path Traversal:** 4 examples (2 real + 2 FP)
- **Hardcoded Secrets:** 5 examples (2 real + 3 FP)

**⚠️ Problemy:**
- **Za mało danych!** 40 przykładów to ekstremalnie mało dla ML
- Brak pokrycia dla wielu typów podatności (SSRF, XXE, CSRF, etc.)
- Brak różnorodności języków programowania
- Statyczne przykłady (nie z rzeczywistych projektów)

---

### 3. AI Assistant (`security_audit/ai/assistant.py`)

**Status:** ✅ **Gotowy i działający!**

**Capabilities:**
- LM Studio integration (100% local)
- Auto-detect model type (DeepHat / Qwen Coder / Generic)
- Optimized prompts per model
- Code anonymization
- User consent system

**To NIE wymaga treningu** - używamy gotowych modeli LLM!

---

## 🚀 Propozycje Optymalizacji

### Opcja A: Enhanced Training Data 📚

**Co:** Zwiększenie zbioru treningowego z 40 → 500+ przykładów

**Implementacja:**

1. **Ekstrakcja z rzeczywistych skanów**
   ```bash
   # Mamy 8 przetestowanych vulnerable apps
   - PyGoat: 456 findings
   - DVWA: 643 findings
   - Juice Shop: 6,266 findings
   - WebGoat: 1,601 findings
   - DVPWA: 150 findings
   - Vulnpy: 222 findings
   - ASP Vulnerable Lab: 120 findings
   - Vulnerable-Flask-App: 94 findings

   Total: 9,552 findings
   ```

2. **Ręczne oznaczenie próbki**
   - Wybierz random sample 500 findings
   - Ręcznie oznacz każdy jako TP (True Positive) lub FP (False Positive)
   - Użyj AI Assistant do wsparcia procesu labelowania
   - Validation: 2 osoby niezależnie, consensus needed

3. **Data augmentation**
   - Variations: zmiana nazw zmiennych
   - Different languages: ten sam pattern w Python/JS/PHP
   - Different frameworks: Django → Flask → FastAPI

4. **Balance dataset**
   - Target: 50/50 ratio TP/FP
   - Stratified by vulnerability type
   - Stratified by language

**Expected Results:**
```
Dataset Size: 500+ examples
Validation Split: 80/20 (400 train / 100 test)
Expected Accuracy: 75-80% (vs current ~65%)
Training Time: ~5 minutes on CPU
Model Size: ~100KB (.pkl file)
```

**Effort:** 🔨🔨🔨 Medium (6-10 hours)
- 4h: ręczne labelowanie 500 findings
- 2h: data cleaning + augmentation
- 2h: validation + documentation

---

### Opcja B: Threshold Optimization 🎯

**Co:** Znalezienie optymalnego threshold zamiast arbitrary 0.65

**Implementacja:**

1. **Create validation dataset**
   ```python
   # Użyj ręcznie zwalidowanych findings
   validation_set = [
       {'finding': {...}, 'true_label': 0},  # 0 = real vuln
       {'finding': {...}, 'true_label': 1},  # 1 = false positive
       # ... 200+ examples
   ]
   ```

2. **Test multiple thresholds**
   ```python
   thresholds = [0.40, 0.45, 0.50, 0.55, 0.60, 0.65, 0.70, 0.75, 0.80]

   for threshold in thresholds:
       predictions = classifier.predict(validation_set, threshold)
       metrics = calculate_metrics(predictions, true_labels)
       print(f"Threshold {threshold}: {metrics}")
   ```

3. **Metrics to optimize**
   - **Precision:** % of FP predictions that are actually FP
   - **Recall:** % of actual FPs that we catch
   - **F1-Score:** harmonic mean of precision & recall
   - **ROC-AUC:** area under ROC curve

4. **Find optimal point**
   ```
   Example results:

   Threshold  Precision  Recall   F1-Score  Remarks
   ────────────────────────────────────────────────────
   0.50       0.68       0.92     0.78      Too many FPs caught
   0.55       0.71       0.88     0.79      Better balance
   0.60       0.74       0.85     0.79      Good option
   0.65       0.78       0.78     0.78      ← CURRENT (balanced)
   0.70       0.82       0.71     0.76      Conservative
   0.75       0.86       0.64     0.73      Too conservative
   0.80       0.89       0.58     0.70      Missing real FPs

   OPTIMAL: 0.60 or 0.65 (depending on business needs)
   ```

5. **Business decision**
   - **Security-first:** Lower threshold (0.55-0.60) → catch more FPs, but keep real vulns
   - **Noise reduction:** Higher threshold (0.70-0.75) → fewer FPs, but might miss some
   - **Balanced:** 0.65 (current) seems reasonable

**Expected Results:**
- 5-10% improvement in F1-score
- Data-driven threshold selection
- Configurable per use case

**Effort:** 🔨 Low (2-3 hours)
- 1h: prepare validation dataset
- 1h: run threshold experiments
- 0.5h: ROC curve analysis
- 0.5h: documentation

**Quick Win!** ⚡ Najmniejszy effort, immediate improvement.

---

### Opcja C: Feature Engineering 🔬

**Co:** Dodanie nowych features do klasyfikacji (beyond current 6)

**Nowe features do dodania:**

#### 1. Code Complexity Metrics
```python
def extract_complexity_features(code: str) -> dict:
    return {
        'cyclomatic_complexity': count_branches(code),  # if/for/while
        'nesting_depth': max_indentation_level(code),
        'line_count': len(code.split('\n')),
        'function_length': detect_function_length(code),
    }

# Logic: Complex code more likely to have real vulns
```

#### 2. Function Context Analysis
```python
def extract_context_features(code: str) -> dict:
    return {
        'in_validator_function': bool(re.search(r'def\s+(validate|sanitize|clean)', code)),
        'in_helper_function': bool(re.search(r'def\s+_[a-z_]+', code)),
        'has_input_validation': detect_validation_logic(code),
    }

# Logic: Code in validator functions likely safe (intentionally handles untrusted input)
```

#### 3. Import Analysis
```python
def extract_import_features(file_content: str) -> dict:
    return {
        'imports_sanitization_libs': bool(re.search(r'from\s+.*\s+import\s+(escape|sanitize)', file_content)),
        'imports_security_libs': bool(re.search(r'import\s+(bleach|html|werkzeug\.security)', file_content)),
        'imports_crypto_libs': bool(re.search(r'import\s+(cryptography|hashlib|secrets)', file_content)),
    }
```

#### 4. Comment Sentiment Analysis
```python
def extract_comment_features(code: str) -> dict:
    return {
        'has_todo_comment': bool(re.search(r'#\s*TODO', code, re.I)),
        'has_fixme_comment': bool(re.search(r'#\s*FIXME', code, re.I)),
        'has_security_comment': bool(re.search(r'#.*(security|vuln|safe)', code, re.I)),
    }

# Logic: TODO/FIXME might indicate known issues (real vulns)
```

#### 5. Historical FP Rate by Type
```python
def extract_historical_features(vuln_type: str) -> dict:
    # Based on past scans
    historical_fp_rates = {
        'sql_injection': 0.15,  # 15% of SQLi findings are FP
        'xss': 0.25,            # 25% of XSS findings are FP
        'hardcoded_secret': 0.50,  # 50% of secrets are FP (examples, docs)
    }
    return {
        'historical_fp_rate': historical_fp_rates.get(vuln_type, 0.3)
    }
```

#### 6. Framework Version Detection
```python
def extract_framework_features(file_path: str, project_root: str) -> dict:
    # Check requirements.txt, package.json, etc.
    return {
        'django_version': detect_django_version(project_root),
        'has_old_dependencies': check_dependency_age(project_root),
        'framework_has_security_patch': check_security_updates(project_root),
    }
```

**Updated scoring function:**
```python
def predict_false_positive_v2(self, finding: Dict[str, Any]) -> Tuple[bool, float, str]:
    score = 0.0

    # Existing features (weight: 60%)
    score += 0.3 * self._is_test_file(...)
    score += 0.2 * self._is_documentation(...)
    score += 0.1 * self._check_safe_patterns(...)

    # NEW features (weight: 40%)
    score += 0.1 * self._code_complexity_score(...)
    score += 0.1 * self._context_analysis_score(...)
    score += 0.08 * self._import_analysis_score(...)
    score += 0.07 * self._comment_sentiment_score(...)
    score += 0.05 * self._historical_fp_score(...)

    is_fp = score >= self.threshold
    return is_fp, score, reasons
```

**Expected Results:**
- 10-15% improvement in precision
- Better separation between TP and FP
- More robust to edge cases

**Effort:** 🔨🔨 Medium (4-6 hours)
- 2h: implement new feature extractors
- 1h: integrate into classifier
- 1h: test on validation set
- 1h: weight tuning + documentation

---

### Opcja D: Real ML Model 🤖

**Co:** Zamiana rule-based → prawdziwy ML model (sklearn)

**Architektura:**

```
┌─────────────────────────────────────────────────┐
│  CURRENT: Rule-Based Classifier                 │
│  └─ if score >= 0.65: return FP                 │
└─────────────────────────────────────────────────┘
                     ↓ UPGRADE TO
┌─────────────────────────────────────────────────┐
│  NEW: Trained ML Model                          │
│  └─ Random Forest / XGBoost / SVM               │
│     - Trained on 500+ labeled examples          │
│     - Auto-learns feature weights                │
│     - Cross-validated (5-fold)                   │
└─────────────────────────────────────────────────┘
```

**Model Candidates:**

1. **Random Forest** (RECOMMENDED)
   ```python
   from sklearn.ensemble import RandomForestClassifier

   model = RandomForestClassifier(
       n_estimators=100,
       max_depth=10,
       min_samples_split=5,
       class_weight='balanced'  # Handle imbalanced data
   )
   ```
   - ✅ Works well with small datasets (500 examples OK)
   - ✅ Fast training (<1 minute)
   - ✅ Interpretable (feature importance)
   - ✅ No need for feature scaling

2. **XGBoost** (Alternative)
   ```python
   from xgboost import XGBClassifier

   model = XGBClassifier(
       n_estimators=100,
       max_depth=6,
       learning_rate=0.1
   )
   ```
   - ✅ State-of-the-art performance
   - ⚠️ Needs more data (1000+ better)
   - ✅ Handles missing values

3. **Naive Bayes** (Baseline)
   ```python
   from sklearn.naive_bayes import GaussianNB

   model = GaussianNB()
   ```
   - ✅ Very fast
   - ✅ Works with tiny datasets
   - ⚠️ Lower accuracy

4. **SVM** (Not recommended)
   - ⚠️ Needs feature scaling
   - ⚠️ Slow on large datasets
   - ⚠️ Less interpretable

**Implementation Pipeline:**

```python
# Step 1: Prepare data
X_train, y_train = prepare_training_data()  # 400 examples
X_test, y_test = prepare_test_data()        # 100 examples

# Step 2: Feature extraction
def extract_features(finding: dict) -> list:
    return [
        1 if is_test_file(finding) else 0,
        1 if is_documentation(finding) else 0,
        count_sanitization_calls(finding['code']),
        code_complexity_score(finding['code']),
        # ... 20+ features total
    ]

X_train_features = [extract_features(f) for f in X_train]

# Step 3: Train model
from sklearn.ensemble import RandomForestClassifier
model = RandomForestClassifier(n_estimators=100)
model.fit(X_train_features, y_train)

# Step 4: Evaluate
from sklearn.metrics import classification_report
y_pred = model.predict(X_test_features)
print(classification_report(y_test, y_pred))

# Step 5: Save model
import joblib
joblib.dump(model, 'fp_classifier_model.pkl')
```

**Expected Results:**
```
Model Performance (estimated):

Metric              Rule-Based    ML Model (RF)
────────────────────────────────────────────────
Accuracy            65-70%        75-85%
Precision (FP)      78%           85%
Recall (FP)         78%           82%
F1-Score            0.78          0.83
Training time       0s            30s
Prediction time     <0.001s       <0.01s
Model size          10KB          100KB
```

**Effort:** 🔨🔨🔨🔨 High (10-15 hours)
- 6h: labeling 500+ examples
- 2h: feature extraction implementation
- 2h: model training + hyperparameter tuning
- 2h: cross-validation + testing
- 2h: integration into scanner
- 1h: documentation

**Highest Impact!** 🏆 Największy improvement w accuracy.

---

### Opcja E: Ensemble Method 🎭

**Co:** Połączenie 3 niezależnych systemów w jeden (voting)

**Architecture:**

```
                    ┌─────────────────────┐
                    │   FINDING INPUT     │
                    └──────────┬──────────┘
                               │
                ┌──────────────┼──────────────┐
                │              │              │
                ▼              ▼              ▼
    ┌────────────────┐ ┌────────────┐ ┌───────────────┐
    │ Rule-Based     │ │ ML Model   │ │ AI Assistant  │
    │ Classifier     │ │ (Random    │ │ (LLM)         │
    │                │ │  Forest)   │ │               │
    │ Score: 0.7     │ │ Score: 0.8 │ │ Score: 0.9    │
    └────────┬───────┘ └──────┬─────┘ └───────┬───────┘
             │                │                │
             └────────────────┼────────────────┘
                              │
                              ▼
                    ┌──────────────────┐
                    │  WEIGHTED VOTING │
                    │                  │
                    │  0.2 * 0.7 +     │
                    │  0.3 * 0.8 +     │
                    │  0.5 * 0.9       │
                    │  = 0.83          │
                    └────────┬─────────┘
                             │
                             ▼
                    ┌─────────────────┐
                    │  FINAL SCORE    │
                    │  Threshold: 0.7 │
                    │  → FALSE POS ✓  │
                    └─────────────────┘
```

**Implementation:**

```python
class EnsembleClassifier:
    def __init__(self):
        self.rule_based = FalsePositiveClassifier()
        self.ml_model = load_trained_model('fp_classifier_model.pkl')
        self.ai_assistant = AIAssistant(server_url="http://localhost:1234")

        # Weights (sum to 1.0)
        self.weights = {
            'rule_based': 0.2,  # Fast, reliable baseline
            'ml_model': 0.3,    # Learned patterns
            'ai_assistant': 0.5  # Deep understanding (but slow)
        }

    def predict(self, finding: dict) -> tuple:
        # Get predictions from all 3 systems
        rule_is_fp, rule_score, _ = self.rule_based.predict_false_positive(finding)
        ml_score = self.ml_model.predict_proba(extract_features(finding))[0][1]
        ai_result = self.ai_assistant.analyze_finding(finding, ask_permission=False)
        ai_score = ai_result.get('confidence', 0.5) if ai_result else 0.5

        # Weighted voting
        final_score = (
            self.weights['rule_based'] * rule_score +
            self.weights['ml_model'] * ml_score +
            self.weights['ai_assistant'] * ai_score
        )

        is_fp = final_score >= 0.7

        return is_fp, final_score, {
            'rule_based_score': rule_score,
            'ml_model_score': ml_score,
            'ai_assistant_score': ai_score,
            'final_score': final_score,
            'method': 'ensemble'
        }
```

**Voting Strategies:**

1. **Weighted Average** (as above)
   - Most flexible
   - Can tune weights based on performance

2. **Majority Voting**
   ```python
   votes = [rule_is_fp, ml_is_fp, ai_is_fp]
   is_fp = sum(votes) >= 2  # At least 2/3 agree
   ```

3. **Confidence-Weighted**
   ```python
   # Higher confidence = more weight
   weighted_vote = (
       rule_score * rule_confidence +
       ml_score * ml_confidence +
       ai_score * ai_confidence
   ) / sum([rule_confidence, ml_confidence, ai_confidence])
   ```

4. **Hierarchical**
   ```python
   # Fast → Slow cascade
   if rule_score > 0.9:  # Very confident FP
       return True
   elif rule_score < 0.3:  # Very confident real vuln
       return False
   else:  # Uncertain → ask ML
       if ml_score > 0.8:
           return True
       elif ml_score < 0.4:
           return False
       else:  # Still uncertain → ask AI
           return ai_assistant.analyze(finding)
   ```

**Expected Results:**
```
Single Models vs Ensemble:

Method              Accuracy   Precision   Recall   F1
────────────────────────────────────────────────────────
Rule-based only     68%        0.76        0.72     0.74
ML model only       78%        0.82        0.79     0.80
AI assistant only   85%        0.88        0.84     0.86
ENSEMBLE (all 3)    88%        0.91        0.87     0.89  ← BEST
```

**Benefits:**
- ✅ Best accuracy (90%+ possible)
- ✅ Redundancy (if one fails, others compensate)
- ✅ Adaptable (can disable AI if slow/unavailable)
- ✅ Interpretable (see contribution of each method)

**Drawbacks:**
- ⚠️ Slower (needs all 3 predictions)
- ⚠️ More complex to maintain
- ⚠️ Requires tuning weights

**Effort:** 🔨🔨🔨 Medium-High (8-12 hours)
- 4h: implement ensemble logic
- 2h: weight tuning (grid search)
- 2h: testing different strategies
- 2h: performance optimization
- 2h: documentation

---

## 🎯 Rekomendowany Plan Wdrożenia

### 3-Step Progressive Enhancement

#### **PHASE 1: Quick Win** (Week 1 - 3h)
✅ **Threshold Optimization** (Opcja B)

**Tasks:**
1. Prepare validation dataset (100-200 manually labeled findings)
2. Test thresholds 0.50 → 0.80 (step 0.05)
3. Plot ROC curve
4. Select optimal threshold
5. Update code + document

**Deliverables:**
- `threshold_optimization_report.md`
- Updated `fp_classifier.py` with data-driven threshold
- ROC curve visualization

**Expected Improvement:** +5-10% F1-score

---

#### **PHASE 2: Feature Enhancement** (Week 2-3 - 6h)
✅ **Feature Engineering** (Opcja C)

**Tasks:**
1. Implement 5 new features:
   - Code complexity metrics
   - Function context analysis
   - Import analysis
   - Comment sentiment
   - Historical FP rates

2. Test feature importance
3. Optimize feature weights
4. A/B test: old vs new features

**Deliverables:**
- Enhanced `fp_classifier.py` v2.0
- Feature importance analysis
- Performance comparison report

**Expected Improvement:** +10-15% precision

---

#### **PHASE 3: ML Model Training** (Week 4-6 - 15h)
✅ **Real ML Model** (Opcja D)

**Tasks:**
1. Label 500+ findings from test projects
2. Feature extraction pipeline
3. Train Random Forest model
4. Cross-validation (5-fold)
5. Hyperparameter tuning
6. Model deployment

**Deliverables:**
- `fp_classifier_model.pkl` (trained model)
- Training notebook with metrics
- Model performance report
- Integration into scanner

**Expected Improvement:** +15-20% accuracy (total: 80-85%)

---

#### **PHASE 4: Ensemble (Optional)** (Week 7+ - 10h)
✅ **Ensemble Method** (Opcja E)

**Tasks:**
1. Implement ensemble classifier
2. Test voting strategies
3. Weight optimization
4. Performance comparison
5. Production deployment

**Deliverables:**
- `ensemble_classifier.py`
- Ensemble performance benchmarks
- Production-ready integration

**Expected Improvement:** 90%+ accuracy (best possible)

---

## 🛠️ Szczegóły Techniczne

### Required Libraries

```python
# requirements.txt additions for ML model

# Data manipulation
numpy>=1.21.0
pandas>=1.3.0

# Machine Learning
scikit-learn>=1.0.0
xgboost>=1.5.0  # Optional: for XGBoost model

# Model persistence
joblib>=1.1.0

# Metrics & Visualization
matplotlib>=3.4.0
seaborn>=0.11.0

# Already have (no changes needed):
# - requests (for AI assistant)
# - json, re, pathlib (stdlib)
```

### File Structure

```
security_audit/ml/
├── __init__.py
├── fp_classifier.py          # Current rule-based (KEEP)
├── fp_classifier_v2.py       # Enhanced features (NEW)
├── fp_classifier_ml.py       # Trained ML model (NEW)
├── ensemble_classifier.py    # Ensemble method (NEW)
├── training_data.py          # Current 40 examples
├── training_data_extended.py # 500+ examples (NEW)
├── feature_extraction.py     # Feature engineering (NEW)
├── model_training.py         # Training pipeline (NEW)
└── models/
    ├── fp_classifier_rf.pkl  # Random Forest model
    ├── fp_classifier_xgb.pkl # XGBoost model (optional)
    └── scaler.pkl            # Feature scaler (if needed)
```

### Training Pipeline Example

```python
# model_training.py

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import cross_val_score, GridSearchCV
from sklearn.metrics import classification_report
import joblib

from .training_data_extended import get_extended_training_data
from .feature_extraction import FeatureExtractor

def train_fp_classifier():
    """
    Train False Positive Classifier using Random Forest
    """

    # 1. Load data
    print("[1/6] Loading training data...")
    data = get_extended_training_data()  # 500+ examples
    X_raw = [item['finding'] for item in data]
    y = [item['label'] for item in data]  # 0=real, 1=FP

    # 2. Extract features
    print("[2/6] Extracting features...")
    extractor = FeatureExtractor()
    X = [extractor.extract(finding) for finding in X_raw]

    # 3. Split data
    from sklearn.model_selection import train_test_split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # 4. Hyperparameter tuning
    print("[3/6] Hyperparameter tuning...")
    param_grid = {
        'n_estimators': [50, 100, 200],
        'max_depth': [5, 10, 15, None],
        'min_samples_split': [2, 5, 10],
        'class_weight': ['balanced', None]
    }

    rf = RandomForestClassifier(random_state=42)
    grid_search = GridSearchCV(
        rf, param_grid, cv=5, scoring='f1', n_jobs=-1
    )
    grid_search.fit(X_train, y_train)

    best_model = grid_search.best_estimator_
    print(f"   Best params: {grid_search.best_params_}")

    # 5. Cross-validation
    print("[4/6] Cross-validation...")
    cv_scores = cross_val_score(
        best_model, X_train, y_train, cv=5, scoring='f1'
    )
    print(f"   CV F1-scores: {cv_scores}")
    print(f"   Mean F1: {cv_scores.mean():.3f} (+/- {cv_scores.std():.3f})")

    # 6. Final evaluation
    print("[5/6] Evaluating on test set...")
    y_pred = best_model.predict(X_test)
    print("\n" + classification_report(y_test, y_pred,
                                        target_names=['Real Vuln', 'False Positive']))

    # 7. Feature importance
    print("[6/6] Feature importance:")
    feature_names = extractor.get_feature_names()
    importances = best_model.feature_importances_
    for name, importance in sorted(zip(feature_names, importances),
                                   key=lambda x: x[1], reverse=True)[:10]:
        print(f"   {name:30s} {importance:.3f}")

    # 8. Save model
    print("\n[✓] Saving model...")
    joblib.dump(best_model, 'security_audit/ml/models/fp_classifier_rf.pkl')
    joblib.dump(extractor, 'security_audit/ml/models/feature_extractor.pkl')

    print("[✓] Training complete!")

    return best_model

if __name__ == '__main__':
    train_fp_classifier()
```

### Integration into Scanner

```python
# security_audit_cli.py

# Add new CLI option
parser.add_argument(
    '--fp-reduction',
    type=str,
    choices=['rule-based', 'ml', 'ensemble'],
    default='rule-based',
    help='False positive reduction method'
)

# In main():
if args.fp_reduction == 'ml':
    from security_audit.ml import MLClassifier
    fp_classifier = MLClassifier(model_path='security_audit/ml/models/fp_classifier_rf.pkl')
elif args.fp_reduction == 'ensemble':
    from security_audit.ml import EnsembleClassifier
    fp_classifier = EnsembleClassifier()
else:
    from security_audit.ml import FalsePositiveClassifier
    fp_classifier = FalsePositiveClassifier()

# Filter findings
findings_filtered, false_positives = fp_classifier.filter_findings(findings)
```

---

## 📊 Expected Impact Summary

| Metric | Current | After Phase 1 | After Phase 2 | After Phase 3 | After Phase 4 |
|--------|---------|---------------|---------------|---------------|---------------|
| **FP Reduction** | 65% | 70% | 75% | 80% | 85% |
| **Precision** | 0.78 | 0.82 | 0.85 | 0.88 | 0.91 |
| **Recall** | 0.78 | 0.80 | 0.82 | 0.85 | 0.87 |
| **F1-Score** | 0.78 | 0.81 | 0.83 | 0.86 | 0.89 |
| **Accuracy** | 68% | 73% | 77% | 82% | 88% |

**Business Impact:**
- Developer time saved: 50-70% reduction in FP noise
- Faster security reviews
- Higher confidence in findings
- Better prioritization of real vulnerabilities

---

## 🎓 Learning Resources

### Understanding ML for Security

1. **False Positive vs False Negative**
   - FP: Scanner says "vulnerability!" but it's safe code → noise, wastes time
   - FN: Scanner misses real vulnerability → dangerous!
   - Goal: Minimize FP while keeping FN at 0%

2. **ML vs Rule-Based**
   ```
   Rule-Based:
   IF code contains "eval(" AND user_input THEN vulnerability
   → Fixed rules, doesn't learn

   ML-Based:
   Train on 500 examples → learns patterns automatically
   → Can discover new patterns, adapts to data
   ```

3. **Why NOT train LLM?**
   - LLM training needs: GPU cluster, weeks, millions of examples, $$$
   - Our ML model needs: CPU, minutes, 500 examples, $0
   - LLM is already trained (we use it via LM Studio)
   - We're training a SMALL classifier (like spam filter)

### Recommended Reading

- [Scikit-learn Random Forest Guide](https://scikit-learn.org/stable/modules/ensemble.html#forest)
- [ML for Vulnerability Detection (Paper)](https://arxiv.org/abs/2012.06337)
- [Reducing False Positives in SAST Tools](https://owasp.org/www-community/controls/Static_Code_Analysis)

---

## 📝 TODOs for Implementation

- [ ] **Phase 1: Threshold Optimization**
  - [ ] Create validation dataset (100+ labeled findings)
  - [ ] Implement threshold testing script
  - [ ] Generate ROC curve
  - [ ] Update classifier with optimal threshold
  - [ ] Document results in `threshold_optimization_report.md`

- [ ] **Phase 2: Feature Engineering**
  - [ ] Implement code complexity metrics
  - [ ] Implement function context analysis
  - [ ] Implement import analysis
  - [ ] Implement comment sentiment
  - [ ] Add historical FP rate feature
  - [ ] Test feature importance
  - [ ] Update classifier v2.0

- [ ] **Phase 3: ML Model Training**
  - [ ] Label 500+ findings from test projects
  - [ ] Create `training_data_extended.py`
  - [ ] Implement `feature_extraction.py`
  - [ ] Implement `model_training.py`
  - [ ] Train Random Forest model
  - [ ] 5-fold cross-validation
  - [ ] Hyperparameter tuning (GridSearchCV)
  - [ ] Save model as `.pkl`
  - [ ] Integration testing
  - [ ] Performance benchmarking

- [ ] **Phase 4: Ensemble (Optional)**
  - [ ] Implement `ensemble_classifier.py`
  - [ ] Test voting strategies
  - [ ] Weight optimization
  - [ ] Benchmark vs single models
  - [ ] Production integration

---

## 🤝 Contributing

Aby przyczynić się do rozwoju ML optimization:

1. **Dodawanie training examples:**
   - Edytuj `security_audit/ml/training_data_extended.py`
   - Dodaj prawdziwe przykłady z projektów
   - Upewnij się o balanced dataset (50% TP, 50% FP)

2. **Nowe features:**
   - Dodaj feature extractors w `feature_extraction.py`
   - Przetestuj feature importance
   - Udokumentuj w tym pliku

3. **Nowe modele:**
   - Eksperymentuj z XGBoost, SVM, Neural Networks
   - Porównaj performance z Random Forest
   - Share wyniki w issue/PR

---

## 📞 Questions?

Jeśli masz pytania o ML optimization:

1. Przeczytaj [USAGE_GUIDE.md](USAGE_GUIDE.md)
2. Check existing issues na GitHub
3. Create new issue z tagiem `ml-optimization`

---

**Last Updated:** 2025-11-15
**Author:** netcuter
**Version:** 1.0

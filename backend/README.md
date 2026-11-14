# ScamXRay — Backend

The Flask-based backend powering ScamXRay's multi-layer threat detection pipeline.

## Architecture

```
User Input (Text, URL, or Screenshot OCR)
        │
        ▼
┌───────────────────────┐
│ Layer 1: Rule Engine  │  → Heuristic red-flags & recruitment pattern detection
└───────────────────────┘
        │
        ▼
┌───────────────────────┐
│ Layer 2: ML Model     │  → TF-IDF + Logistic Regression (trained on EMSCAD dataset)
└───────────────────────┘
        │
        ▼
┌───────────────────────┐
│ Layer 3: AI Analysis  │  → Multi-layer LLM threat explanation & actionable safety tips
└───────────────────────┘
        │
        ▼
Unified JSON Threat Intelligence Response
```

## Tech Stack

- **Framework**: Flask + Flask-CORS + Gunicorn
- **ML**: Scikit-learn (TF-IDF + Logistic Regression)
- **LLM**: Groq API
- **Domain Inspection**: tldextract
- **Language**: Python 3.14

## Project Structure

```
backend/
├── app.py                   # Flask server entry point & /analyze route
│
├── services/                # Domain services
│   ├── analyzer.py          # LLM explanation service
│   ├── category_classifier.py # Scam category classifier
│   ├── predictor.py         # ML fraud score prediction
│   ├── rule_engine.py       # Rule-based red flag detection
│   └── url_analyzer.py      # Comprehensive URL threat inspection
│
├── models/                  # Serialized ML model artifacts
│   ├── model.pkl            # Trained Logistic Regression model
│   └── vectorizer.pkl       # Trained TF-IDF vectorizer
│
├── tests/                   # Automated test suite
│   ├── test_regression.py   # Regression test suite (30 tests)
│   ├── fixtures/            # Shared test fixture data
│   │   └── mock_fixtures.py
│   └── unit/                # Unit test suites
│       └── test_domain_correspondence.py (7 domain matching tests)
│
├── scripts/                 # Developer tools & benchmarks
│   ├── check_model.py       # Model coefficient inspection
│   ├── probe_model.py       # Quick text scoring evaluator
│   ├── compare_guard_behavior.py # Guard ON/OFF benchmark runner
│   ├── benchmark_llm_variance.py # LLM scoring variance benchmark
│   └── verify_live_http.py  # Live HTTP server test runner
│
├── requirements.txt         # Pinned Python dependencies
├── Procfile                 # Deployment process command
├── render.yaml              # Render.com deployment configuration
├── .env.example             # Environment variable template
└── .gitignore
```

## Running Locally

```bash
cd backend
pip install -r requirements.txt
python app.py
```

## Running Tests

```bash
python -m unittest discover backend/tests
```

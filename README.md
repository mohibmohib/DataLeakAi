# 🛡️ DataLeak AI

**An AI-powered security gateway that detects sensitive information in prompts *before* they reach an external AI system, then automatically allows, warns, redacts, or blocks the request based on risk.**

> BS Cyber Security — AI semester project

---

## Problem

Employees increasingly use ChatGPT, Gemini, Claude and other generative AI tools for coding, writing, analysis and support. A single careless paste can leak:

- Customer data (names, CNIC, phone, email)
- Passwords, API keys, tokens, private keys
- Financial information (card numbers, bank details)
- Proprietary source code and confidential documents

**DataLeak AI** sits between the employee and the AI service to reduce accidental leakage while still letting people use generative AI.

```
Employee → DataLeak AI → SAFE  → AI
                       → RISKY → Warn / Redact / Block
```

## Features

| # | Feature | Description |
|---|---------|-------------|
| 1 | Sensitive-data detection | Regex/pattern detectors for email, phone, CNIC, credit cards, JWT, API keys, private-key headers |
| 2 | ML classification | TF-IDF + Logistic Regression classifies prompts into `safe`, `pii`, `financial`, `credential`, `source_code`, `confidential` |
| 3 | Risk scoring | Combines detected entities and model confidence into a 0–100 score |
| 4 | Policy engine | Maps score to `ALLOW` / `WARN` / `REDACT` / `BLOCK` (thresholds configurable) |
| 5 | Redaction | Replaces sensitive values with placeholders such as `[CNIC_REDACTED]` |
| 6 | Explainability | Shows *why* a request was warned, redacted or blocked |
| 7 | Security logs | SQLite event log storing category, score, action, confidence and a hash, not raw prompts |
| 8 | Dashboard | Streamlit UI with metrics, charts, event table and model performance |

## Architecture

```
User → Streamlit UI → Input Processor
                          ├─ Rule/Pattern Detection ─┐
                          └─ NLP/ML Classifier ──────┤
                                                     ▼
                                               Risk Engine (0–100)
                                                     ▼
                                               Policy Engine
                                  ┌──────────┬──────┴─────┬──────────┐
                                ALLOW      WARN        REDACT      BLOCK
                                                     ▼
                                               Security Logs → Dashboard
```

## Default policy

| Risk score | Decision |
|-----------:|----------|
| 0–29  | ALLOW  |
| 30–49 | WARN   |
| 50–69 | REDACT |
| 70–100 | BLOCK |

These thresholds are defaults for this project, not an industry standard, and can be changed in the Settings page / policy config.

## Example

**Input**
```
Customer Ahmed Khan has CNIC 35202-1234567-1 and phone 0300-1234567.
```
**Redacted output**
```
Customer [PERSON] has CNIC [CNIC_REDACTED] and phone [PHONE_REDACTED].
```

**Blocked request**
```
🚨 REQUEST BLOCKED
Risk: CRITICAL   Score: 98/100
Reason: Sensitive credential detected
Data type: Cloud credential
Action: BLOCK
```

## Project structure

```
DataLeakAI/
├── data/
│   ├── raw/
│   └── processed/
├── notebooks/            # Colab: dataset analysis, training, evaluation
├── models/               # tfidf.pkl, classifier.pkl, label_encoder.pkl
├── src/
│   ├── preprocessing.py
│   ├── pii_detector.py
│   ├── secret_detector.py
│   ├── classifier.py
│   ├── risk_engine.py
│   ├── policy_engine.py
│   ├── redactor.py
│   ├── explainer.py
│   └── database.py
├── dashboard/
│   └── app.py
├── tests/
│   ├── test_detection.py
│   ├── test_model.py
│   └── test_redaction.py
├── requirements.txt
└── README.md
```

## Tech stack

Python · scikit-learn · pandas · NumPy · spaCy / NLTK · Plotly · Streamlit · SQLite · SHAP (planned) · Google Colab (training) · VS Code · Git/GitHub

## Getting started

### 1. Clone and install

```bash
git clone https://github.com/mohibmohib/DataLeakAi.git
cd DataLeakAI

python -m venv venv
# Windows
venv\Scripts\activate
# Linux / macOS
source venv/bin/activate

pip install -r requirements.txt
```

### 2. Add the trained models

Train in Google Colab (see `notebooks/`) and place the exported files in `models/`:

```
models/tfidf.pkl
models/classifier.pkl
models/label_encoder.pkl
```

> Use the same scikit-learn version for training and inference, otherwise unpickling can fail or behave unexpectedly.

### 3. Run the dashboard

```bash
streamlit run dashboard/app.py
```

### 4. Run the tests

```bash
pytest tests/ -v
```

## Model

| Item | Value |
|------|-------|
| Classes | safe, pii, financial, credential, source_code, confidential |
| Features | TF-IDF |
| Chosen model | Logistic Regression |
| Hand-written real-world test | F1 ≈ 0.86 (20 prompts) |

Model comparison (Logistic Regression, SVM, Random Forest, XGBoost) is in `notebooks/model_evaluation.ipynb`.

> The dataset is synthetic / hand-built, so real-world accuracy will differ from test-set scores. Treat the numbers as a prototype benchmark.

## Privacy and security notes

- Raw prompts are **not** stored by default. Logs keep timestamp, session ID, category, score, action, confidence and a hash/redacted form.
- **Never commit real secrets.** All API keys, card numbers and CNICs in the dataset and tests must be fake.
- `.env` files and database files are excluded via `.gitignore`.

## Limitations

- Regex rules can miss obfuscated or unusual formats; the ML model can misclassify ambiguous prompts.
- Detection is prompt-level only; no browser extension, file/PDF scanning or multi-user roles yet.
- Not a replacement for an enterprise DLP product.

## Roadmap

- [ ] SHAP explainability
- [ ] Real LLM integration (OpenAI / Gemini / Claude / local)
- [ ] PDF / document scanning
- [ ] Code-secret detection
- [ ] Role-based policies and admin dashboard
- [ ] Browser extension

## License

MIT (or as required by your university; update before publishing).

## Author

**Mohib** — BS Cyber Security

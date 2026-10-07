# CyberGuard: AI-Based Phishing URL & Website Detector

[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-3.1.3-000000?style=for-the-badge&logo=flask&logoColor=white)](https://flask.palletsprojects.com)
[![Scikit-Learn](https://img.shields.io/badge/scikit--learn-1.8.0-F7931E?style=for-the-badge&logo=scikitlearn&logoColor=white)](https://scikit-learn.org)
[![Docker](https://img.shields.io/badge/Docker-Enabled-2496ED?style=for-the-badge&logo=docker&logoColor=white)](https://www.docker.com)
[![Pytest](https://img.shields.io/badge/Pytest-28%20Passed-0A9EDC?style=for-the-badge&logo=pytest&logoColor=white)](https://pytest.org)

An end-to-end, production-style Final Year B.Tech Cybersecurity Capstone Project that classifies whether an untrusted URL is **Legitimate, Suspicious, or Phishing**. Powered by a Random Forest machine learning classifier, lexical & entropy feature extraction, a Flask REST API, and a SOC-grade dark dashboard.

---

## 1. Problem Statement & Motivation

Phishing remains the primary initial access vector across cybersecurity breaches, enabling credential theft, banking fraud, session hijacking, and ransomware dissemination. Malicious URLs are distributed at scale through email spear-phishing, SMS (smishing), WhatsApp, Discord, and social media platforms.

Traditional perimeter defenses (such as static signature blacklists) frequently fail against ephemeral domains, newly registered domains (NRDs), domain generation algorithms (DGAs), and URL shortening services.

**CyberGuard** solves this by analyzing the syntactic, domain-structural, heuristic, and entropy properties of a URL before a user or security analyst interacts with it—delivering an instant threat verdict, a calibrated model-based risk score, and transparent explainable indicators.

---

## 2. Key Features

- **String-Safe Feature Extraction**: Extracts 45 numerical and heuristic features without executing HTTP requests, downloading remote DOMs, or triggering drive-by malware.
- **Trained Dual-Model ML Pipeline**:
  - **Primary Model**: Random Forest Classifier (100 estimators, max depth 20).
  - **Baseline Benchmark**: L2 Regularized Logistic Regression.
- **Model-Based Risk Scoring**: Transparent scoring algorithm (0–100) combining Random Forest posterior probabilities with verifiable heuristic indicators.
  - **Legitimate**: 0–30 (Low Threat)
  - **Suspicious**: 31–70 (Medium Threat)
  - **Phishing**: 71–100 (High Threat)
- **Explainable Security Telemetry**: Deconstructs every URL into human-readable indicator cards (e.g., HTTPS status, raw IP detection, high-risk TLDs, entropy anomalies, credential keywords).
- **Dark SOC-Style Dashboard**: Interactive user interface featuring live telemetry cards, Chart.js threat distributions, preset attack test cases, and deep feature matrix inspection.
- **Enterprise CSV Batch Scanning**: Supports uploading multi-row CSV files (up to 1,000 URLs), processing bulk threat assessments, and exporting enriched CSV reports.
- **Persistent Audit Logging**: SQLite database recording scan histories, confidence scores, threat levels, and execution timestamps.
- **Containerized Architecture**: Dockerfile and Docker Compose specification for one-command deployment.
- **Comprehensive Automated Test Suite**: 28 passing unit and integration tests covering feature extraction, model inference, database persistence, and API error boundaries.

---

## 3. System Architecture & Workflow

```text
+-----------------------------------------------------------------------------------------+
|                                    USER INTERACTION                                     |
|  [ Single URL Input ]   OR   [ Batch CSV Upload (up to 1,000 URLs) ]                    |
+-----------------------------------------------------------------------------------------+
                                             |
                                             v
+-----------------------------------------------------------------------------------------+
|                                 REST API & SECURITY LAYER                                |
|  - Request Validation (Length <= 2048, Type Checks, Safe String Sanitization)           |
|  - STRICT SECURITY RULE: ZERO network execution, NO browser rendering, NO SSRF         |
+-----------------------------------------------------------------------------------------+
                                             |
                                             v
+-----------------------------------------------------------------------------------------+
|                                FEATURE EXTRACTION ENGINE                                |
|  - URL Structure: Length, dots, slashes, hyphens, digits, digit_ratio, special_chars    |
|  - Domain Heuristics: IP hostname regex, subdomain depth, high-risk TLDs, port anomalies|
|  - Keywords: 15 credential targets (login, verify, bank, wallet, secure, password)     |
|  - Cryptographic / Statistical: Shannon Entropy H(x), Punycode (xn--), Shorteners       |
+-----------------------------------------------------------------------------------------+
                                             |
                                             v
+-----------------------------------------------------------------------------------------+
|                            MACHINE LEARNING INFERENCE ENGINE                            |
|  - StandardScaler: Normalization applied using training-fitted distribution             |
|  - Random Forest Classifier (100 Trees, max_depth=20)                                   |
|  - Baseline Comparison: L2 Regularized Logistic Regression                              |
+-----------------------------------------------------------------------------------------+
                                             |
                                             v
+-----------------------------------------------------------------------------------------+
|                           MODEL-BASED RISK SCORING ENGINE                               |
|  - Posterior Probability (0-80 base) + Transparent Heuristic Adjustments (+15 Raw IP,   |
|    +10 Shortener, +10 Punycode, +10 Port, +8 Suspicious TLD, -5 HTTPS Benign Domain)    |
|  - Verdicts: Legitimate (0-30), Suspicious (31-70), Phishing (71-100)                   |
+-----------------------------------------------------------------------------------------+
                                             |
                                             v
+-----------------------------------------------------------------------------------------+
|                                    PERSISTENCE & UI                                     |
|  - SQLite Database Audit Log (scan_history table with indexed timestamps)               |
|  - SOC Dark Theme Dashboard (Chart.js distributions, explainable indicator cards)       |
+-----------------------------------------------------------------------------------------+
```

---

## 4. Technology Stack

| Layer | Technologies |
| :--- | :--- |
| **Backend Framework** | Python 3.11+, Flask 3.1.3, Flask-CORS 6.0.5, Werkzeug |
| **Machine Learning** | Scikit-Learn 1.8.0, Pandas 3.0.2, NumPy 2.4.4, Joblib 1.5.3 |
| **Database** | SQLite3 (Persistent connection with indexed scan logs) |
| **Frontend UI** | HTML5, CSS3 (Vanilla design tokens, dark SOC theme), Vanilla JS (ES6+ Fetch API), Chart.js |
| **Testing** | Pytest 9.1.1 (28 automated tests) |
| **Containerization** | Docker, Docker Compose (multi-stage build) |

---

## 5. Dataset Specifications

In strict adherence to academic rigor, the dataset source and parameters are documented:

- **Data Sources**:
  1. **Live Threat Intelligence**: OpenPhish Public Verified Feed (active phishing campaigns).
  2. **Ground Truth Benchmark Corpus**: Verified Legitimate URLs derived from the Tranco/Alexa Top 1 Million list spanning global education (`.edu`), government (`.gov`), international agencies (`.eu`), financial institutions, technology leaders, and developer documentation; paired with verified PhishTank & OpenPhish attack vectors (brand spoofing, raw IP hosts, multi-subdomains, credential harvesting parameters).
- **Total Records**: `10,000` URLs
- **Phishing URLs (Class 1)**: `5,000` URLs (50%)
- **Legitimate URLs (Class 0)**: `5,000` URLs (50%)
- **Train / Test Split**: 80% Training (`8,000` samples), 20% Holdout Testing (`2,000` samples), Stratified.
- **Random Seed**: `42` (Fixed for reproducibility).
- **Storage Location**: `data/raw/urls_dataset.csv` (Raw URLs), `data/processed/features_dataset.csv` (Feature Matrix).

---

## 6. Feature Engineering (45 Features)

Every URL is parsed into 45 structured mathematical and lexical attributes:

### A. URL Structural Features
- `url_length`: Total character count.
- `hostname_length`: Netloc / hostname character length.
- `path_length`: Subpath character length.
- `query_length`: Query string parameter length.
- Character frequencies: `number_of_dots`, `number_of_hyphens`, `number_of_underscores`, `number_of_slashes`, `number_of_question_marks`, `number_of_equal_signs`, `number_of_at_symbols`, `number_of_ampersands`, `number_of_percent_symbols`.
- `number_of_digits`: Absolute count of numerical digits `[0-9]`.
- `digit_ratio`: `number_of_digits / url_length`.
- `special_character_count`: Non-alphanumeric character count.
- `suspicious_char_ratio`: Non-alphanumeric characters to URL length ratio.

### B. Domain & Network Indicators
- `has_ip_address`: Binary flag detecting raw IPv4 hostnames (e.g. `http://192.168.1.1/login`).
- `hostname_present`: Valid domain presence check.
- `subdomain_count`: Number of nested subdomains.
- `excessive_subdomains`: Binary flag triggered when subdomain count $\ge 3$.
- `domain_length`: Length of registered domain.
- `has_https`: Valid HTTPS scheme flag.
- `has_http`: Plain unencrypted HTTP scheme flag.
- `suspicious_port`: Detection of non-standard web ports (outside 80 and 443).
- `unusual_tld`: Detection of abuse-prone TLDs (`.xyz`, `.top`, `.club`, `.work`, `.click`, `.buzz`, `.stream`, `.tk`, `.ml`, `.cf`, `.ga`, etc.).

### C. Heuristic & Cryptographic Features
- `is_shortened_url`: Detection of link shorteners (`bit.ly`, `tinyurl.com`, `t.co`, `cutt.ly`, `rb.gy`, etc.).
- `has_punycode`: Detection of internationalized domain encoding (`xn--`) used for homograph attacks.
- `hostname_entropy`: Shannon Entropy of the hostname:
  $$H(X) = -\sum_{i=1}^{n} P(x_i) \log_2 P(x_i)$$
  Flags algorithmically generated (DGA) domains and randomized subdomains.
- `total_suspicious_keywords`: Total count of detected credential-harvesting tokens.
- Binary flags for 15 targeted keywords: `login`, `signin`, `verify`, `verification`, `account`, `secure`, `update`, `password`, `bank`, `wallet`, `confirm`, `authentication`, `free`, `bonus`, `claim`.

---

## 7. Model Evaluation & Measured Results

The following metrics represent actual, measured holdout evaluation results generated on the 2,000-URL holdout test partition (serialized in `models/model_metadata.json`):

### Holdout Test Set Performance (2,000 Samples)

| Metric | Primary: Random Forest | Baseline: Logistic Regression |
| :--- | :--- | :--- |
| **Overall Accuracy** | **99.40%** | 99.55% |
| **Weighted Precision** | **99.40%** | 99.55% |
| **Weighted Recall** | **99.40%** | 99.55% |
| **F1-Score** | **0.9940** | 0.9955 |
| **ROC-AUC Score** | **0.9990** | 0.9995 |
| **Phishing Precision** | **99.90%** | 100.00% |
| **Phishing Recall** | **98.90%** | 99.10% |
| **Phishing F1-Score** | **0.9940** | 0.9955 |

### Confusion Matrix (Random Forest, Test Size = 2,000)

```text
                         PREDICTED
                     Legitimate   Phishing
ACTUAL  Legitimate       999         1      (True Negatives: 999 | False Positives: 1)
        Phishing          11       989      (False Negatives: 11 | True Positives: 989)
```

- **True Negatives (TN)**: 999 legitimate URLs correctly identified.
- **False Positives (FP)**: 1 legitimate URL falsely flagged as phishing.
- **False Negatives (FN)**: 11 phishing URLs missed.
- **True Positives (TP)**: 989 phishing URLs correctly identified.

### Top 10 Most Influential Decision Features (Gini Importance)
1. `digit_ratio`: `0.1999`
2. `number_of_digits`: `0.1595`
3. `total_suspicious_keywords`: `0.0929`
4. `domain_length`: `0.0807`
5. `hostname_length`: `0.0766`
6. `number_of_hyphens`: `0.0713`
7. `url_length`: `0.0504`
8. `hostname_entropy`: `0.0433`
9. `path_length`: `0.0315`
10. `unusual_tld`: `0.0295`

---

## 8. Installation & Setup

### Prerequisites
- Python 3.11 or higher
- Git
- (Optional) Docker & Docker Compose

### 1. Clone & Set Up Virtual Environment

```bash
cd c:\Users\singh\Downloads\Cyber
python -m venv venv

# Windows (Command Prompt / PowerShell):
venv\Scripts\activate

# Linux / macOS:
source venv/bin/activate
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Pipeline Execution Commands

The project supports complete CLI execution without code modification:

```bash
# Step 1: Download / Generate benchmark dataset
python scripts/download_dataset.py

# Step 2: Train baseline and primary ML models
python scripts/train_model.py

# Step 3: Evaluate model and print academic report
python scripts/evaluate_model.py

# Step 4: Run automated test suite
pytest -v

# Step 5: Start the application
python app.py
```

Open your browser at `http://127.0.0.1:5000/`.

---

## 9. REST API Documentation

### 1. Health Check
- **Endpoint**: `GET /api/health`
- **Response**:
```json
{
  "database_connected": true,
  "model_loaded": true,
  "model_name": "RandomForestClassifier",
  "status": "healthy",
  "timestamp": "2026-10-04T18:57:31.786009"
}
```

### 2. Single URL Prediction
- **Endpoint**: `POST /api/predict`
- **Request Body**:
```json
{
  "url": "https://login.appleid-support-team.xyz/verify.php?token=auth99"
}
```
- **Response**:
```json
{
  "confidence": 91.0,
  "detection_time_ms": 2.14,
  "features_summary": {
    "dots": 3,
    "entropy": 4.1069,
    "has_https": true,
    "has_ip": false,
    "is_shortened": false,
    "length": 62,
    "subdomains": 1,
    "suspicious_keywords": 2
  },
  "indicators": [
    {
      "description": "Valid HTTPS transport security protocol detected.",
      "title": "HTTPS Encryption",
      "type": "safe"
    },
    {
      "description": "Standard alphanumeric domain hostname present.",
      "title": "Domain Name",
      "type": "safe"
    },
    {
      "description": "Domain utilizes a TLD frequently associated with spam or phishing campaigns.",
      "title": "High-Risk Top-Level Domain",
      "type": "warning"
    },
    {
      "description": "Detected sensitive social engineering keywords: login, verify.",
      "title": "Targeting Keywords (2)",
      "type": "warning"
    }
  ],
  "phishing_probability": 0.91,
  "prediction": "Phishing",
  "risk_score": 76,
  "threat_level": "HIGH",
  "timestamp": "2026-10-04T19:02:59.687214",
  "url": "https://login.appleid-support-team.xyz/verify.php?token=auth99"
}
```

### 3. Batch CSV Prediction
- **Endpoint**: `POST /api/batch-predict`
- **Method**: Multipart Form Data (`file`: `.csv` file with column header `url`).
- **Query Parameter**: `?format=csv` (Optional: triggers direct file download attachment).
- **Response (JSON default)**:
```json
{
  "legitimate_count": 5,
  "phishing_count": 3,
  "results": [
    {
      "confidence": 84.14,
      "prediction": "Legitimate",
      "risk_score": 8,
      "threat_level": "LOW",
      "url": "https://www.google.com"
    }
  ],
  "suspicious_count": 1,
  "total_processed": 9
}
```

### 4. Scan History
- **Endpoint**: `GET /api/history?limit=50&offset=0&search=bank&prediction=Phishing`
- **Response**: List of audited scan records.

### 5. Statistics Telemetry
- **Endpoint**: `GET /api/statistics`
- **Response**: Aggregated counts for total scans, phishing detections, suspicious detections, and average risk score.

### 6. Model Metadata
- **Endpoint**: `GET /api/model-info`
- **Response**: Measured metrics, confusion matrix, and feature importances.

---

## 10. Automated Tests

Run the test suite using:

```bash
pytest -v
```

### Test Suite Coverage (28 Passing Tests)

1. `tests/test_features.py`:
   - `test_valid_standard_url`
   - `test_malformed_and_schemaless_url`
   - `test_raw_ip_address_url`
   - `test_suspicious_characters_and_at_symbol`
   - `test_excessively_long_url`
   - `test_shannon_entropy`
   - `test_url_shortener_detection`
   - `test_punycode_detection`
2. `tests/test_model.py`:
   - `test_model_artifacts_exist`
   - `test_predictor_singleton_loaded`
   - `test_prediction_output_structure`
   - `test_high_risk_phishing_url_prediction`
   - `test_legitimate_url_prediction`
3. `tests/test_api.py`:
   - `test_api_health`
   - `test_api_predict_valid`
   - `test_api_predict_missing_url`
   - `test_api_predict_empty_url`
   - `test_api_predict_non_json`
   - `test_api_predict_oversized_url`
   - `test_api_batch_predict_valid_csv`
   - `test_api_batch_predict_format_csv_download`
   - `test_api_batch_predict_invalid_extension`
   - `test_api_history`
   - `test_api_statistics`
   - `test_api_model_info`
4. `tests/test_database.py`:
   - `test_save_and_retrieve_scan`
   - `test_database_filtering_and_search`
   - `test_statistics_aggregation`

---

## 11. Docker Deployment

Deploy CyberGuard as a containerized microservice:

```bash
# Build and run with Docker Compose
docker compose up --build -d

# View logs
docker compose logs -f

# Verify container health
curl http://localhost:5000/api/health
```

---

## 12. Security & Defensive Design Considerations

- **Strict No-Execution Sandbox Rule**: The application treats incoming URLs exclusively as immutable strings. It never initiates outbound HTTP handshakes, does not execute client JavaScript, and never downloads binaries.
- **SSRF Prevention**: By eliminating dynamic fetching of untrusted remote URLs, the system cannot be leveraged as an open proxy or Server-Side Request Forgery vector to scan internal private subnets (`127.0.0.1`, `10.0.0.0/8`, `192.168.0.0/16`, AWS metadata `169.254.169.254`).
- **Input Sanitization & Length Caps**: URLs are capped at 2,048 characters to prevent buffer and Regular Expression Denial of Service (ReDoS) resource exhaustion.

---

## 13. Placement & Academic Interview Guide

### 30-Second Elevator Pitch
> *"I designed and built CyberGuard, an AI-based Phishing URL Detector that inspects untrusted links in sub-milliseconds before users click them. It extracts 45 lexical, domain-structural, and entropy features from the URL string, feeds them into a trained Random Forest model, and provides a calibrated risk score with explainable security indicators. It achieved 99.4% test accuracy on 2,000 holdout benchmark URLs, backed by a Flask REST API, SQLite audit logs, and a dark SOC dashboard."*

### Key Interview Q&A
- **Why Random Forest over Deep Learning?**
  *Random Forest provides high sample efficiency, resistance to overfitting, handles tabular mixed features (discrete counts and continuous ratios) without requiring million-sample pretraining, and offers direct feature importance (Gini impurity) for explainable security reporting.*
- **How is Data Leakage Prevented?**
  *The dataset was split using an 80/20 stratified partition BEFORE fitting any transformations. The `StandardScaler` was fit strictly on the 8,000 training samples and only applied to transform the test set and live inference vectors.*
- **What is the Difference Between URL-Based Detection and Webpage DOM Analysis?**
  *URL-based analysis is ultra-fast (<2 ms), requires zero network roundtrips, and eliminates SSRF or drive-by malware risks. Webpage DOM analysis inspects HTML and form targets but requires outbound requests, rendering engines, and is susceptible to cloaking techniques.*

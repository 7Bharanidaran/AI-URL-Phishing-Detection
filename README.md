
# 🛡️ AI-Powered URL Phishing Detection

An AI-powered cybersecurity application that detects malicious URLs using Machine Learning, VirusTotal API integration, and an interactive Streamlit dashboard.

---

## 📌 Overview

Phishing attacks are one of the most common cyber threats used to steal credentials and sensitive information. This project combines machine learning and threat intelligence from VirusTotal to analyze URLs and provide a risk assessment through an intuitive web interface.

---

## 🚀 Features

* Machine Learning-based URL classification
* Random Forest classifier
* URL lexical feature extraction
* VirusTotal reputation analysis
* Risk scoring engine
* Interactive Streamlit dashboard
* Probability-based predictions
* Detection visualization using charts
* Technical analysis panel
* Cybersecurity-focused user interface

---

## 🏗️ Architecture

```text
User URL
    │
    ▼
Feature Extraction
    │
    ▼
Random Forest Model
    │
    ├── Safe Probability
    ├── Phishing Probability
    │
    ▼
VirusTotal API
    │
    ├── Malicious Engines
    ├── Suspicious Engines
    ├── Harmless Engines
    │
    ▼
Risk Engine
    │
    ▼
Final Verdict
```

---

## 📂 Project Structure

```text
AI-URL-Phishing-Detection/
│
├── data/
│
├── models/
│     phishing_model.pkl
│
├── src/
│     app.py
│     feature_extraction.py
│     predict.py
│     risk_engine.py
│     train_model.py
│     virustotal_scan.py
│
├── screenshots/
│
├── requirements.txt
└── README.md
```

---

## ⚙️ Technologies Used

### Programming Language

* Python

### Machine Learning

* Scikit-Learn
* Random Forest Classifier

### Data Processing

* Pandas
* NumPy

### Threat Intelligence

* VirusTotal API

### Visualization

* Plotly

### Web Application

* Streamlit

---

## 🔍 Feature Extraction

The model extracts lexical features from URLs, including:

* URL length
* Number of dots
* Number of hyphens
* Number of slashes
* Number of digits
* Presence of IP address
* HTTPS usage
* Presence of suspicious keywords

Examples:

* login
* verify
* account
* bank
* secure
* update
* paypal

---

## 📊 Risk Levels

| Risk Level  | Description                             |
| ----------- | --------------------------------------- |
| 🟢 LOW      | Benign URL with no malicious detections |
| 🟡 MEDIUM   | Suspicious behavior detected            |
| 🟠 HIGH     | Multiple malicious indicators           |
| 🔴 CRITICAL | Highly malicious URL                    |

---

## 🖥️ Streamlit Dashboard

The dashboard provides:

* AI model predictions
* Probability scores
* VirusTotal analysis
* Risk assessment
* Technical details
* Interactive charts

---



---

## ▶️ Installation

Clone the repository:

```bash
git clone https://github.com/7Bharanidaran/AI-URL-Phishing-Detection.git
```

Move into the project directory:

```bash
cd AI-URL-Phishing-Detection
```

Create a virtual environment:

```bash
python3 -m venv venv
```

Activate the virtual environment:

```bash
source venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

---

## ▶️ Running the Application

Launch the Streamlit dashboard:

```bash
streamlit run src/app.py
```

---

## 🧪 Example URLs

### Benign

```text
https://www.southbankmosaics.com
```

### Phishing

```text
http://www.shprakserf.gq
```

---

## 🔮 Future Enhancements

* XGBoost-based model
* Explainable AI (SHAP)
* Domain age analysis
* WHOIS integration
* PDF report generation
* Scan history
* Risk gauge visualization
* Streamlit cloud deployment

---

## 🎯 Applications

* Cybersecurity awareness
* SOC analyst workflows
* Threat intelligence
* Security operations
* Phishing analysis
* Security education

---


Cybersecurity Undergraduate | Blue Team Enthusiast | SOC Analyst Aspirant

GitHub: https://github.com/7Bharanidaran

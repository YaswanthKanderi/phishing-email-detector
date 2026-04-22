<div align="center">

# 🛡️ Phishing Email Detector

### Hybrid ML + Heuristic Detection for Real-World Email Threats

*A production-style phishing classifier combining TF-IDF NLP features with hand-crafted security heuristics — the same architecture used by enterprise email security gateways.*

[![Python](https://img.shields.io/badge/Python-3.8+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![scikit-learn](https://img.shields.io/badge/scikit--learn-F7931E?style=for-the-badge&logo=scikit-learn&logoColor=white)](https://scikit-learn.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-13%20passing-2ea44f?style=for-the-badge)](tests/)
[![ROC-AUC](https://img.shields.io/badge/ROC--AUC-1.00-2ea44f?style=for-the-badge)](#-results)

</div>

---

## 🎯 Why This Project Matters

Phishing is the **#1 initial access vector** in nearly every major breach report — [Verizon DBIR 2024](https://www.verizon.com/business/resources/reports/dbir/), [Australian Cyber Security Centre](https://www.cyber.gov.au/), and [CrowdStrike Global Threat Report](https://www.crowdstrike.com/global-threat-report/) all confirm it's where most attacks start.

Most academic phishing detectors rely purely on text classification (TF-IDF + Logistic Regression) and fail on novel phrasing they haven't seen in training. **This project does better** by combining:

1. 🧠 **Machine Learning (TF-IDF + Logistic Regression)** — learns linguistic patterns of phishing
2. 🔍 **Hand-crafted security heuristics** — catches structural red flags regardless of wording
3. 📊 **Explainable predictions** — shows *which* signals drove each decision (critical for SOC analyst workflows)

This mirrors how real enterprise email security gateways (Proofpoint, Mimecast, Microsoft Defender for Office 365) combine ML with rule-based heuristics.

---

## 🚀 Quick Demo

```bash
$ python predict.py --email examples/sample_phishing.txt
```

```
============================================================
  ⚠  PHISHING DETECTED
============================================================
  Phishing Probability:  99.9%
  Confidence:            99.9%

Security Signals Detected:
------------------------------------------------------------
  • URLs found:                3
  • Suspicious TLDs (.tk/.ml): 1 ⚠
  • URL shorteners:            1 ⚠
  • Display/link mismatches:   1 ⚠
  • Urgency keywords:          9 ⚠
  • Financial lures:           4 ⚠
  • Brand mentions:            1
  • Generic greeting:          yes ⚠
============================================================
```

The detector didn't just say "phishing" — it **explained why**. This kind of interpretability is what separates a toy classifier from something a SOC analyst can actually trust and triage with.

---

## 🏗️ Architecture

```
        ┌─────────────────────────────────────────────────┐
        │              Raw Email Input                    │
        └─────────────────────┬───────────────────────────┘
                              │
                ┌─────────────┴─────────────┐
                │                           │
                ▼                           ▼
     ┌──────────────────┐       ┌──────────────────────┐
     │ Text Preprocessor│       │ Security Feature     │
     │ • HTML stripping │       │ Extractor (15 feats) │
     │ • URL tokenising │       │ • URL analysis       │
     │ • Normalisation  │       │ • TLD reputation     │
     └────────┬─────────┘       │ • Link mismatch      │
              │                 │ • Urgency keywords   │
              ▼                 │ • Brand impersonation│
     ┌──────────────────┐       │ • Generic greetings  │
     │ TF-IDF Vectoriser│       └──────────┬───────────┘
     │ (5000 features,  │                  │
     │  1-2 n-grams)    │                  │
     └────────┬─────────┘                  │
              │                            │
              └────────────┬───────────────┘
                           │
                           ▼
              ┌─────────────────────────┐
              │  Hybrid Feature Matrix  │
              │    (5000+ features)     │
              └────────────┬────────────┘
                           │
                           ▼
              ┌─────────────────────────┐
              │  Logistic Regression    │
              │  (class-balanced,       │
              │   interpretable)        │
              └────────────┬────────────┘
                           │
                           ▼
              ┌─────────────────────────┐
              │  Prediction + Signals   │
              └─────────────────────────┘
```

---

## 🔬 Security Features Engineered

The 15 hand-crafted features address real phishing tactics documented in MITRE ATT&CK (T1566 — Phishing):

| Feature | What It Catches | Why It Matters |
|---|---|---|
| `url_count` | Email URL density | Phishing often spams multiple links |
| `ip_url_count` | Raw IP URLs (`http://192.168.x.x`) | Legit services use domains, not IPs |
| `suspicious_tld_count` | Free/abused TLDs (.tk, .ml, .xyz) | 30%+ of phishing uses these |
| `url_shortener_count` | bit.ly, tinyurl, etc. | Hides true destination |
| `link_mismatch_count` | `<a href="evil.com">paypal.com</a>` | Classic phishing tell |
| `https_ratio` | HTTPS adoption in links | Modern legit sites are HTTPS-first |
| `urgency_keyword_count` | "URGENT", "immediately", "suspended" | Social engineering pressure |
| `financial_lure_count` | "bank account", "refund", "wire transfer" | Financial phishing markers |
| `brand_mention_count` | PayPal, Microsoft, ATO, Medicare | Brand impersonation check |
| `generic_greeting` | "Dear Customer", "Dear User" | Legit senders use your name |
| `excessive_caps_ratio` | ALL CAPS text | Classic phishing formatting |
| `exclamation_count` | Multiple `!` marks | Urgency signaling |
| `has_html` | HTML-formatted email | HTML enables link obfuscation |
| `attachment_mention` | .zip, .exe, .docm references | Malware delivery vectors |
| `text_length` | Email size | Phishing tends to be shorter |

---

## 📊 Results

On the included sample dataset (60 emails, balanced):

| Metric | Score |
|---|---|
| **Accuracy** | 83.3% |
| **ROC-AUC** | 1.000 |
| **Phishing Precision** | 100% |
| **Phishing Recall** | 67% |
| **Legitimate Precision** | 75% |
| **Legitimate Recall** | 100% |

> **Note on the sample dataset:** The included 60-email dataset is small by design — it lets the project run out-of-the-box in seconds. For production use, train on larger corpora like [Enron + Nazario phishing](https://monkey.org/~jose/phishing/) or the [UCI Phishing Dataset](https://archive.ics.uci.edu/dataset/327/phishing+websites). The hybrid architecture scales directly.

---

## 🚀 Getting Started

### 1. Clone and Install

```bash
git clone https://github.com/YaswanthKanderi/phishing-email-detector.git
cd phishing-email-detector
pip install -r requirements.txt
```

### 2. Train the Model

```bash
python train.py
```

This uses the included sample dataset and saves a trained model to `models/phishing_detector.pkl`.

### 3. Classify an Email

```bash
# From a file
python predict.py --email examples/sample_phishing.txt

# From a string
python predict.py --text "URGENT: Verify your account at http://bit.ly/xyz"

# From stdin (useful in pipelines)
cat suspicious_email.txt | python predict.py --stdin
```

### 4. Run the Tests

```bash
python -m unittest tests.test_detector -v
```

---

## 📁 Project Structure

```
phishing-email-detector/
├── detector/
│   ├── __init__.py
│   ├── features.py          # Security heuristic extractor (15 features)
│   ├── preprocessor.py      # Email text cleaning
│   └── model.py             # Hybrid ML model
├── data/
│   └── sample_emails.csv    # 60 labeled example emails
├── examples/
│   ├── sample_phishing.txt
│   └── sample_legitimate.txt
├── tests/
│   └── test_detector.py     # 13 unit tests
├── models/                   # Trained models saved here
├── train.py                 # Training pipeline
├── predict.py               # CLI prediction tool
├── requirements.txt
├── LICENSE
└── README.md
```

---

## 🧪 Technical Decisions

**Why Logistic Regression instead of deep learning?**
- **Interpretability.** Every prediction must be explainable to a SOC analyst. Neural networks are black boxes; Logistic Regression lets us trace each decision back to specific features.
- **Speed.** Inference runs in ~1ms per email — essential for scanning thousands of emails per second in a real email gateway.
- **Small-data robustness.** Works well even with limited labeled data, which is realistic for internal corporate phishing detection.

**Why hybrid features instead of pure TF-IDF?**
- Pure TF-IDF overfits to training-set phrasing. Novel phishing wording slips through.
- Hand-crafted features encode *structural* red flags (URL patterns, link mismatches) that don't change even when attackers reword their lures.
- This matches how real-world email security products architect their detection stacks.

**Why balanced class weights?**
- Real-world phishing is rare (~0.1–1% of inbox traffic). Class balancing ensures the model doesn't just predict "legitimate" for everything.

---

## 🛣️ Roadmap

Planned enhancements as part of ongoing Cyber Security Master's coursework:

- [ ] Integrate with IMAP/Graph API for live inbox scanning
- [ ] Add header analysis (SPF, DKIM, DMARC validation)
- [ ] Expand feature set with WHOIS domain age lookups
- [ ] Benchmark against Nazario phishing corpus (large-scale)
- [ ] SIEM integration — export predictions as Splunk/ELK-compatible events
- [ ] Adversarial robustness testing

---

## 🎓 Academic Context

This project was developed as part of the **Master of Cyber Security program at La Trobe University, Melbourne**, aligning with coursework in:

- Network Security & Threat Intelligence
- Applied Machine Learning for Security
- Incident Detection & Response
- Secure Software Development

It demonstrates practical application of defensive security concepts to one of the most prevalent threat vectors facing modern organisations.

---

## 👨‍💻 Author

**Yaswanth Kanderi**
Master of Cyber Security — La Trobe University, Melbourne

[![LinkedIn](https://img.shields.io/badge/LinkedIn-0A66C2?style=for-the-badge&logo=linkedin&logoColor=white)](https://linkedin.com/in/yaswanthkanderi/)
[![GitHub](https://img.shields.io/badge/GitHub-100000?style=for-the-badge&logo=github&logoColor=white)](https://github.com/YaswanthKanderi)
[![Email](https://img.shields.io/badge/Email-0078D4?style=for-the-badge&logo=microsoft-outlook&logoColor=white)](mailto:yaswanthchowdary01@outlook.com)

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

<div align="center">

*"The best defenders think like attackers — and build tools that explain themselves."*

</div>

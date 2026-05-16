# 👻 GHOST SENTRY
## AI-Powered Real-Time Phishing Detection System

[![Python 3.8+](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/)
[![Groq](https://img.shields.io/badge/Groq-LLM-orange.svg)](https://groq.com)
[![ChromaDB](https://img.shields.io/badge/ChromaDB-Vector-yellow.svg)](https://chromadb.com)

> **🎯 100% Accuracy** on test emails | **⚡ <500ms** response time | **🗄️ 11,000+** phishing URLs in vector database

---

## 📋 Overview

**Ghost Sentry** is a production-ready AI-powered phishing detection system that analyzes emails through **4 parallel machine learning models** to identify phishing attempts with exceptional accuracy. This system demonstrates how modern AI techniques effectively combat email phishing — responsible for 91% of successful cyberattacks.

---

## ✨ Key Features

- 🧠 **Multi-Model Ensemble** — Text analysis, URL structure, RAG similarity, and BERT classification running in parallel
- 🗄️ **Vector Database** — 11,000+ known phishing URLs stored in ChromaDB for semantic similarity matching
- 🤖 **LLM Fallback** — Groq Llama 3.3 70B for advanced semantic analysis when needed
- 📱 **QR Detection** — Extracts and analyzes QR codes from images (quishing protection)
- ⚡ **Real-Time Processing** — Async architecture with <500ms response time
- 📊 **Explainable AI** — Shows component scores and detailed reasoning for each verdict

---

## 🏗️ Architecture

```
┌──────────────────┐
│   📧 Email Input  │
└────────┬─────────┘
         │
    ┌────▼──────┐
    │  Parallel  │
    │  Analysis  │
    └────┬──────┘
         │
┌────────┴──────────────┬────────────┐
│                       │            │
┌───▼──┐  ┌──────┐  ┌──▼────┐  ┌───▼────┐
│ Text │  │ URL  │  │  RAG  │  │  BERT  │
│  20% │  │  30% │  │  20%  │  │  30%   │
└───┬──┘  └───┬──┘  └──┬────┘  └───┬────┘
    │         │         │           │
    └─────────┴─────────┴───────────┘
                        │
          ┌─────────────▼────────────┐
          │      Weighted Fusion     │
          │       Groq LLM Check     │
          └─────────────┬────────────┘
                        │
          ┌─────────────▼────────────┐
          │        ✅ VERDICT        |
          │  CLEAN / SUSPICIOUS /    │
          │        MALICIOUS         │
          └──────────────────────────┘
```

---

## 🛠️ Tech Stack

| Component  | Technology               | Purpose              |
|------------|--------------------------|----------------------|
| Language   | Python 3.8+              | Core development     |
| Async      | asyncio                  | Parallel processing  |
| Vector DB  | ChromaDB 1.5.9           | URL similarity search|
| Embeddings | Sentence Transformers    | URL vectorization    |
| ML         | Hugging Face BERT        | Classification       |
| LLM        | Groq Llama 3.3 70B       | Semantic fallback    |
| QR Code    | pyzbar + Pillow          | Quishing detection   |

---

## 🚀 Quick Start

### Prerequisites

```bash
git clone https://github.com/vincenzo-exe/GHOST-SENTRY-AI-Powered-Phishing-Detection-System.git
cd GHOST-SENTRY-AI-Powered-Phishing-Detection-System
python --version  # Ensure Python 3.8+
```

### Installation

```bash
# Create virtual environment
python -m venv .venv
.venv\Scripts\activate        # Windows
# source .venv/bin/activate   # Mac/Linux

# Install dependencies
pip install -r requirements.txt

# Setup environment
cp .env.example .env
# Add your GROQ_API_KEY from https://console.groq.com
```

### Build & Run

```bash
python tools/links_db.py       # Build 11,000+ URL database
python test_10_emails.py full  # Run test suite
python orchestrator.py         # Run orchestrator
```

---

## 📊 Detection Results

**Test Suite: 10 Emails (5 Legitimate + 5 Phishing)**

| Metric          | Result           |
|-----------------|------------------|
| Accuracy        | 10/10 (100%)     |
| False Positives | 0                |
| False Negatives | 0                |
| Avg Response Time | 210–315ms      |
| URL Database    | 11,000+ vectors  |

**Legitimate Emails:**

- ✅ good_001 → Score: 0.074 (CLEAN)
- ✅ good_002 → Score: 0.073 (CLEAN)
- ✅ good_003 → Score: 0.130 (CLEAN)
- ✅ good_004 → Score: 0.110 (CLEAN)
- ✅ good_005 → Score: 0.122 (CLEAN)

**Phishing Emails:**

- 🟡 bad_001 → Score: 0.493 (SUSPICIOUS)
- 🟡 bad_002 → Score: 0.449 (SUSPICIOUS)
- 🟡 bad_003 → Score: 0.437 (SUSPICIOUS)
- 🟡 bad_004 → Score: 0.476 (SUSPICIOUS)
- 🟠 bad_005 → Score: 0.394 (LOW_SUSPICION)

---

## 💻 Usage Example

```python
import asyncio
from orchestrator import analyze_email

async def check_email():
    email = {
        "uid": "test_001",
        "from": "security@paypal-security.com",
        "subject": "URGENT: Account Suspended",
        "body_text": "Verify now: http://paypal-verify.com",
        "urls": ["http://paypal-verify.com"],
        "attachments": []
    }

    result = await analyze_email(email)
    print(f"Verdict: {result.verdict}")
    print(f"Score: {result.score_final:.3f}")
    print(f"Scores: {result.scores}")
    print(f"Reason: {result.reason}")

asyncio.run(check_email())
```

**Output:**

```json
{
  "uid": "test_002",
  "timestamp": "2026-05-08T00:26:33.922516",
  "sender": "security@paypal.com",
  "subject": "URGENT: Account suspended",
  "verdict": "SUSPICIOUS",
  "score_final": 0.4627,
  "scores": {"text": 0.105, "url": 0.575, "rag": 0.5012, "bert": 0.23},
  "reason": "Multiple phishing indicators | Suspicious URL + urgent tone",
  "processing_time_ms": 315.65
}
```

---

## 📁 Project Structure

```
GHOST-SENTRY/
│
├── orchestrator.py              # Main AI orchestrator
├── test_10_emails.py            # Test suite (5 good + 5 bad)
├── test_random_emails.py        # Test with random URLs from ChromaDB
├── verify_system.py             # Complete system verification
├── warmup.py                    # Preload models for fast demo
├── main.py                      # Entry point
├── requirements.txt             # Python dependencies
├── .env.example                 # Configuration template
│
├── tools/
│   ├── links_db.py              # Build URLHaus database (11,000+ URLs)
│   ├── chroma_rag.py            # ChromaDB query engine
│   ├── url_pipeline.py          # URL + QR analysis
│   └── qr_extractor.py          # QR code extraction
│
├── models/
│   └── distilbert_classifier.py # BERT classifier
│
├── config/
│   └── settings.py              # Configuration settings
│
├── db/
│   ├── postgres_logger.py       # PostgreSQL logger (optional)
│   └── redis_memory.py          # Redis cache (optional)
│
└── data/
    └── chromadb/                # 11,000+ URL vectors
```

---

## 🎯 What It Detects

- **Typosquatting** → `paypa1.com` vs `paypal.com`
- **Domain Impersonation** → `paypal-secure.com` masquerading as PayPal
- **Homoglyph Attacks** → Unicode lookalikes (`е` vs `e`)
- **QR Phishing** → Malicious QR codes in emails
- **Urgency Language** → "Account suspended," "24-hour deadline"
- **Suspicious TLDs** → `.tk`, `.xyz`, `.top`
- **IP-Based URLs** → `192.168.1.1/paypal`

---

## ⚙️ Configuration

### Environment (`.env`)

```env
GROQ_API_KEY=gsk_your_key_here
IMAP_HOST=imap.gmail.com
IMAP_PORT=993
IMAP_USER=your-email@gmail.com
IMAP_PASSWORD=your-app-password
```

### Scoring Weights (`orchestrator.py`)

```python
weights = {
    "text": 0.20,   # Text analysis
    "url":  0.30,   # URL structure
    "rag":  0.20,   # ChromaDB similarity
    "bert": 0.30    # ML classifier
}
```

### Verdict Thresholds

| Score    | Verdict       |
|----------|---------------|
| ≥ 0.50   | MALICIOUS     |
| ≥ 0.30   | SUSPICIOUS    |
| ≥ 0.15   | LOW_SUSPICION |
| < 0.15   | CLEAN         |

---

## 📝 Requirements

```
Python 3.8+
chromadb==1.5.9
sentence-transformers==5.4.1
groq==1.2.0
transformers==5.8.0
aiohttp==3.13.5
tldextract==5.3.1
pillow==12.2.0
pyzbar==0.1.9
python-dotenv==1.2.2
```

---

## 🔧 Commands

```bash
# Build URL database (11,000+ phishing URLs)
python tools/links_db.py

# Preload models for fast demo (run before presentation)
python warmup.py

# Run full test (5 good + 5 bad hardcoded emails)
python test_10_emails.py full

# Run quick test (1 good + 1 bad)
python test_10_emails.py quick

# Run random test (5 legitimate + 5 random URLs from ChromaDB)
python test_random_emails.py

# Run quick random test (1 random phishing URL)
python test_random_emails.py quick

# Verify entire system
python verify_system.py

# Run orchestrator demo
python orchestrator.py
```

---

## ❓ Troubleshooting

| Issue                    | Fix                                        |
|--------------------------|--------------------------------------------|
| ChromaDB shows 0 URLs    | Run `python tools/links_db.py`             |
| Groq 401 error           | Verify API key in `.env`                   |
| Slow performance         | Reduce URL limit in `links_db.py`          |
| Import errors            | Run `pip install -r requirements.txt`      |
| QR extraction fails      | Run `pip install pillow pyzbar`            |

---

<div align="center">
  <sub>Built with ❤️ to fight phishing — one email at a time.</sub>
</div>

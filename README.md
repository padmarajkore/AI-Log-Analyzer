# 🛡️ TypeSafe AI Log Analyzer & Guardian

> Real-time AI Log Analyzer and Early Warning System powered by **TypeSafe System One (Jev)**. 
> Evaluates 100+ logs/sec across distributed microservices using a **Batch Window Architecture**, catching credential leaks, cascading outages, and architectural degradation in sub-second time.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.7-blue.svg)](https://www.typescriptlang.org/)
[![TypeSafe](https://img.shields.io/badge/AI-TypeSafe%20Jev-6366f1.svg)](https://typesafe.ai)

---

## 📖 Related Reading
- 📝 **Deep-Dive Article on Medium:** [Jev Is Not a Chatbot. It's a Judgment Engine — And I Built a Real-Time Log Guardian With It](https://medium.com/@padmaraj.com/jev-is-not-a-chatbot-its-a-judgment-engine-and-i-built-a-real-time-log-guardian-with-it-716bde2de5e1?sharedUserId=padmaraj.com)

---

## 🌟 What Makes This Different?

Most AI observability tools send unstructured log blobs to conversational LLMs (like GPT or Claude) asking for paragraph explanations. This is slow, expensive, prone to parsing errors, and blind to real-time streams.

**Jev is not a chatbot — it's a System One Decision Engine.**
- **Zero Output Tokens:** Computes structured answers and calibrated probabilities without generating text. Output tokens = 0.
- **Typed Judgments:** Outputs exact probabilities and choices into your code rather than strings you have to regex.
- **Batch Window Architecture:** Ingests high-frequency logs (100+/sec) and analyzes entire time windows (e.g. 2 seconds) in **one single model call**.
- **Cross-Service Correlation:** Detects multi-service cascades (e.g. DB connection exhaustion + queue backpressure + memory spike) that individual line-by-line rules miss.

---

## ⚡ Key Features

- 🔍 **Sensitive Secret Leak Detection:** Detects cleartext passwords, raw JWTs, private keys, and PII embedded in arbitrary log formats.
- ✂️ **Automatic Redaction:** Flags and sanitizes sensitive data on the fly before forwarding or storing.
- 🚨 **Outage Probability Scoring (`noul`):** Mathematical probability (0.00 – 1.00) of an imminent system crash.
- 📊 **System Health & Severity (`score`):** Holistic health rating across the entire distributed window.
- 🛠️ **Recommended Action (`choice`):** Automated operational triage (`suppress`, `record_metric`, `notify_devops`, or `emergency_pager_alert`).
- ⚡ **Interactive Cockpit UI:** Real-time dashboard with Server-Sent Events (SSE), health gauges, telemetry metrics, and customizable simulator speeds.
- 🧪 **Built-In Traffic Generator:** Simulates 12 microservices with 80+ realistic log scenarios (routine traffic, database deadlocks, memory thrashing, and security breaches).

---

## 📐 Architecture

```
[ Microservices / Apps ]
           │ (HTTP POST 100+ logs/sec)
           ▼
┌────────────────────────────────────────────────────────┐
│ Express Log Ingestion Engine                           │
│                                                        │
│  ┌──────────────────────────────────────────────────┐  │
│  │ Accumulator / Batch Window (e.g., 2000ms window) │  │
│  └─────────────────────────┬────────────────────────┘  │
└────────────────────────────┼───────────────────────────┘
                             │ One API call with compact digest
                             ▼
              ┌─────────────────────────────┐
              │    TypeSafe Jev API         │
              │  (System One Judgment)      │
              │                             │
              │  • system_health_score      │
              │  • highest_urgency          │
              │  • batch_outage_risk        │
              │  • batch_leak_detected      │
              └──────────────┬──────────────┘
                             │ Typed JSON Responses
                             ▼
┌────────────────────────────────────────────────────────┐
│ Redaction & Alerting Engine                            │
│                                                        │
│  • Sanitizes Credentials & PII                         │
│  • Computes Failure Domains                            │
│  • Broadcasts via Server-Sent Events (SSE)             │
└────────────────────────────┬───────────────────────────┘
                             │ SSE Stream
                             ▼
                 [ Real-Time Cockpit UI ]
```

---

## 🚀 Quick Start

### 1. Prerequisites
- **Node.js**: v18.0.0 or higher
- **TypeSafe API Key**: Obtain one from [typesafe.ai](https://typesafe.ai)

### 2. Installation

```bash
# Clone the repository
git clone https://github.com/padmarajkore/AI-Log-Analyzer.git
cd AI-Log-Analyzer

# Install dependencies
npm install
```

### 3. Environment Setup

Create a `.env` file in the root directory:

```env
PORT=3000
TYPESAFE_API_KEY=your_typesafe_api_key_here
```

### 4. Run the Dev Server

```bash
npm run dev
```

Visit **[http://localhost:3000](http://localhost:3000)** to open the Real-Time Cockpit UI!

---

## 🧪 Testing & Simulation

### A. Run the Live Traffic Generator (CLI)
To start streaming realistic microservice logs from the terminal:

```bash
npm run simulate
```

### B. Run Pre-Configured Test Scenarios
To run targeted test cases (e.g., credential leaks, cascading crashes):

```bash
npm run test:analyze
```

### C. Sending Custom Logs via cURL

#### Single-Log Analysis:
```bash
curl -X POST http://localhost:3000/api/logs/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "service": "auth-service",
    "level": "ERROR",
    "message": "DB connection failed: postgresql://admin:super_secret_password_123@db.prod:5432/users"
  }'
```

#### Batch Window Ingestion:
```bash
curl -X POST http://localhost:3000/api/logs/batch \
  -H "Content-Type: application/json" \
  -d '{
    "windowMs": 2000,
    "logs": [
      { "service": "payment-api", "level": "WARN", "message": "Connection pool timeout: active=50 idle=0 waiting=280" },
      { "service": "order-service", "level": "ERROR", "message": "Heap memory usage reached 94.8%, triggering aggressive GC" },
      { "service": "auth-service", "level": "INFO", "message": "Session token generated for user usr_49201" }
    ]
  }'
```

---

## 📂 Project Structure

```
├── public/
│   ├── index.html          # Cockpit dashboard HTML
│   ├── style.css           # Modern dark-mode UI styling
│   └── app.js              # Real-time SSE client & interactive controls
├── src/
│   ├── typesafe-analyzer.ts # Jev integration, question definitions & redaction
│   ├── server.ts           # Express API, SSE streaming & batch engine
│   ├── log-simulator.ts    # Multi-service realistic log generator
│   └── simulate-cli.ts     # CLI-based simulation runner
├── test/
│   └── test-scenarios.ts   # Edge-case test suites (leaks, crashes, healthy)
├── package.json
├── tsconfig.json
└── README.md
```

---

## 🛡️ License

Distributed under the MIT License. See `LICENSE` for more information.

---

## 🤝 Contributing

Contributions, issues, and feature requests are welcome! Feel free to open an issue or submit a pull request.

# ScamShield

**ScamShield** is a full-stack AI scam and phishing detection web platform and REST API tailored for Indian digital fraud patterns—including **Bank KYC phishing**, **UPI Collect / PIN traps**, **Digital Arrest impersonation**, **Fake Job lures**, suspicious links, and screenshots—built on a zero-cost cloud architecture.

- **Live Web App:** [scamshield-fric.vercel.app](https://scamshield-fric.vercel.app)
- **Live API & Swagger Docs:** [scamshield-api-zvb4.onrender.com/docs](https://scamshield-api-zvb4.onrender.com/docs)
- **Repository:** [github.com/CleanCoder-arch/scamshield](https://github.com/CleanCoder-arch/scamshield)

---

## Key Features

- **Multi-Mode Scanner:** Inspect suspicious **Text / SMS**, **Screenshots** (with OCR transcription), **URLs**, and **Phone / UPI IDs** from a single interface.
- **Hybrid Detection Engine:** Combines staged **CyberGuard** Scikit-learn models (`.joblib`), handcrafted URL/entity extraction, Indian scam rule scoring (`entity_rules.py`), external threat intelligence checks (Google Safe Browsing, VirusTotal, RDAP/domain age), and **Gemini (`gemini-3.5-flash-lite`)** structured verdict & OCR analysis.
- **Real-Time Streaming Progress:** Uses Server-Sent Events (`POST /api/v1/scan/stream`) to stream live step-by-step progress across entity extraction, CyberGuard scoring, threat intelligence, and AI verdict assessment.
- **Tailored Indian Action Playbooks:** Maps detected scam categories (`bank_kyc`, `upi_fraud`, `digital_arrest`, `fake_job`, suspicious links, and low-risk scans) to concrete safety actions and golden-hour cybercrime reporting guidance (`1930` helpline and `cybercrime.gov.in`).
- **Shareable Warning Cards & Incident PDFs:**
  - **Download PNG:** Generates a high-contrast warning card for medium/high-risk scans (`score >= 40`) with the risk badge, scam category, key indicators, safety checklist, and `1930` / `cybercrime.gov.in` contacts.
  - **Download PDF:** Exports a one-page Incident & Safety Report PDF with IST timestamp, curated evidence, and reporting steps.
- **Privacy-First Architecture:** Raw messages, uploaded screenshots, and sensitive identifiers are processed transiently in memory—never persisted to disk or database. Only anonymized scan metadata is logged for telemetry.
- **Developer API & Docs (`/developers`):** Interactive API reference with `curl`, Python, and JavaScript examples plus SSE event schemas.

---

## Tech Stack

| Layer | Technologies |
| :--- | :--- |
| **Frontend** | Next.js, TypeScript, Tailwind CSS (deployed on **Vercel**) |
| **Backend** | Python 3.11, FastAPI, Uvicorn, Pydantic (deployed via Docker on **Render**) |
| **ML & AI** | Scikit-learn (`1.7.2`), NumPy, SciPy, Joblib, Google GenAI SDK (`gemini-3.5-flash-lite`), Pillow |
| **Threat Intel** | Google Safe Browsing API, VirusTotal API, RDAP domain checks |
| **Cache & Storage** | **Upstash Redis** (rate limiting & deduplication), **Neon PostgreSQL** (`asyncpg`, anonymized metadata only) |
| **Testing** | `pytest` (75 backend tests), frontend unit tests, ESLint, Next.js production build |

---

## Project Structure

```text
scamshield/
├── backend/
│   ├── app/
│   │   ├── core/          # Card generator, rate limiting, security & helpers
│   │   ├── engines/       # CyberGuard ML, entity rules, threat intel, Gemini vision/text, playbooks
│   │   ├── main.py        # FastAPI routes (/api/v1/scan, /scan/stream, /scan/image, /health)
│   │   ├── scan_service.py
│   │   └── schemas.py
│   ├── models/            # Trained CyberGuard .joblib artifacts
│   ├── tests/             # Pytest suite
│   ├── Dockerfile
│   └── requirements.txt
├── frontend/
│   ├── src/               # Next.js App Router pages (/, /developers), scanner UI, PDF export
│   └── package.json
├── render.yaml            # Render deployment blueprint
└── README.md
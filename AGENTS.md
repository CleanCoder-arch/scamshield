# AGENTS.md

## Project Overview
Web-only AI scam & phishing detection platform (Next.js Web UI + FastAPI REST API, no WhatsApp bot) powered by existing CyberGuard .joblib ML models, async threat intelligence, and Gemini multimodal classification.

## Repository Layout
- backend/: Python 3.11+ FastAPI app (app/main.py, app/schemas.py, app/engines/, app/core/), models/ (CyberGuard .joblib artifacts), tests/ (pytest).
- frontend/: Next.js (App Router) + TypeScript + Tailwind CSS.
- docs/scam_detection_platform_roadmap.pdf: Reference architecture and build milestones.

## Hard Constraints
- Zero-cost / Free-tier only: Stay under Render's 512 MB RAM limit on the backend. Do NOT install PyTorch, TensorFlow, PaddleOCR, or EasyOCR; use gemini-3.5-flash-lite via google-genai for both screenshot OCR and scam classification.
- Privacy by design: Never store raw user messages, phone numbers, UPI IDs, or uploaded screenshots in PostgreSQL. Only persist anonymized scan metadata (scan_id, risk_score, risk_level, scam_type, created_at).
- Secrets: Never hardcode keys or modify .env. Load settings via pydantic-settings.

## Verification Commands
- Backend tests: cd backend; pytest -v
- Frontend lint & build: cd frontend; npm run lint; npm run build
- Always run the relevant verification command after editing files and summarize changed files and test results.

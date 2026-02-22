# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Running the App

```bash
# Activate virtual environment
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run development server (port 5050, debug mode)
python app.py
```

Access at https://localhost:5050 (if cert.pem/key.pem exist) or http://localhost:5050.

Override port with `PORT` env var. Production uses `gunicorn app:app --bind 0.0.0.0:$PORT` (see Procfile).

There is no test suite.

## Architecture

Flask app with WebAuthn passkey authentication and two blueprint-based mini-apps. All HTML/CSS/JS is embedded in Python files via `render_template_string` — there are no separate template or static asset files.

### Core Files

- **app.py** — Main Flask app: WebAuthn registration/login flow, session management, landing page. Authentication guard (`@app.before_request`) protects all routes except `/auth`, `/register`, `/login`, `/logout`, `/robots.txt`.
- **flags.py** — `flags_bp` blueprint mounted at `/flags/`. Educational flag game with 3 modes (quiz, match, explore). Entirely client-side JS logic.
- **miami_sky.py** — `miami_sky_bp` blueprint mounted at `/miami-sky/`. Sunset countdown and moon tracker for Miami using client-side astronomical calculations (no external APIs).

### Authentication

WebAuthn/FIDO2 passkey auth with file-based credential storage (`credentials.json`). RP ID is derived from the request Host header for multi-domain support. Registration locks after the first credential (`.registration_locked` file). Credentials can alternatively be provided via `CREDENTIALS` env var (read-only mode).

### Deployment

Production deployment on Railway via Procfile with Gunicorn. Supports `X-Forwarded-Proto` for HTTPS detection behind reverse proxy.

from flask import Flask, render_template_string, session, redirect, url_for, request, jsonify
import json
import os
import secrets
import base64
from pathlib import Path

from webauthn import (
    generate_registration_options,
    verify_registration_response,
    generate_authentication_options,
    verify_authentication_response,
    options_to_json,
)
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    AuthenticatorAttachment,
    ResidentKeyRequirement,
    UserVerificationRequirement,
    PublicKeyCredentialDescriptor,
    AuthenticatorTransport,
)

app = Flask(__name__)

# --- Configuration ---
RP_NAME = "Flag Explorer"
CREDENTIALS_FILE = Path(__file__).parent / "credentials.json"
REGISTRATION_LOCK = Path(__file__).parent / ".registration_locked"


def _get_rp_id():
    """Derive RP ID from the request's Host header."""
    return request.host.split(":")[0]


def _get_origin():
    """Derive the expected origin from the request."""
    scheme = request.headers.get("X-Forwarded-Proto", request.scheme)
    return f"{scheme}://{request.host}"

# Persist secret key so sessions survive restarts
_secret_key_file = Path(__file__).parent / ".secret_key"
if _secret_key_file.exists():
    app.secret_key = _secret_key_file.read_text()
else:
    app.secret_key = secrets.token_hex(32)
    _secret_key_file.write_text(app.secret_key)


# --- Helpers ---
def _b64encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64decode(s: str) -> bytes:
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


def load_credentials() -> list:
    if CREDENTIALS_FILE.exists():
        return json.loads(CREDENTIALS_FILE.read_text())
    return []


def save_credentials(creds: list):
    CREDENTIALS_FILE.write_text(json.dumps(creds, indent=2))

AUTH_TEMPLATE = r"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Flag Explorer - Login</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Fredoka+One&family=Nunito:wght@400;700;800&display=swap');
  * { margin: 0; padding: 0; box-sizing: border-box; }
  :root {
    --pink: #FF6B9D; --purple: #C44DFF; --blue: #4DA6FF;
    --green: #4DDB7F; --yellow: #FFD93D; --orange: #FF8C42;
    --bg: #1a1a2e; --card: #16213e;
  }
  body {
    font-family: 'Nunito', sans-serif;
    background: var(--bg); color: white;
    min-height: 100vh; display: flex;
    align-items: center; justify-content: center;
    overflow: hidden;
  }
  .bg-shapes { position: fixed; inset: 0; pointer-events: none; z-index: 0; overflow: hidden; }
  .bg-shapes span { position: absolute; display: block; border-radius: 50%; opacity: 0.07; animation: floatShape 20s infinite linear; }
  .bg-shapes span:nth-child(1) { width: 200px; height: 200px; background: var(--pink); top: 10%; left: 5%; animation-duration: 25s; }
  .bg-shapes span:nth-child(2) { width: 300px; height: 300px; background: var(--blue); top: 60%; left: 80%; animation-duration: 30s; animation-delay: -5s; }
  .bg-shapes span:nth-child(3) { width: 150px; height: 150px; background: var(--yellow); top: 80%; left: 20%; animation-duration: 22s; animation-delay: -10s; }
  .bg-shapes span:nth-child(4) { width: 250px; height: 250px; background: var(--green); top: 20%; left: 70%; animation-duration: 28s; animation-delay: -3s; }
  @keyframes floatShape {
    0%, 100% { transform: translate(0, 0) rotate(0deg); }
    25% { transform: translate(30px, -40px) rotate(90deg); }
    50% { transform: translate(-20px, 20px) rotate(180deg); }
    75% { transform: translate(40px, 30px) rotate(270deg); }
  }
  .auth-card {
    background: var(--card); border-radius: 30px; padding: 50px 40px;
    text-align: center; max-width: 440px; width: 90%;
    border: 2px solid rgba(255,255,255,0.05); position: relative; z-index: 1;
  }
  .auth-card h1 {
    font-family: 'Fredoka One', cursive; font-size: 2.5em;
    background: linear-gradient(135deg, var(--yellow), var(--orange), var(--pink));
    -webkit-background-clip: text; -webkit-text-fill-color: transparent;
    background-clip: text; margin-bottom: 10px;
  }
  .auth-card p { color: #aaa; font-size: 1.1em; margin-bottom: 30px; }
  .auth-btn {
    font-family: 'Nunito', sans-serif; font-weight: 800; font-size: 1.2em;
    padding: 16px 40px; border: none; border-radius: 50px;
    cursor: pointer; color: white; transition: all 0.3s;
    background: linear-gradient(135deg, var(--purple), #7B2FBE);
  }
  .auth-btn:hover { transform: translateY(-3px); box-shadow: 0 8px 25px rgba(0,0,0,0.3); }
  .auth-btn:active { transform: translateY(0); }
  .auth-btn:disabled { opacity: 0.5; cursor: not-allowed; transform: none; }
  .status { margin-top: 20px; font-size: 1em; color: #aaa; min-height: 1.5em; }
  .status.error { color: var(--pink); }
  .status.success { color: var(--green); }
  .lock-icon { font-size: 4em; margin-bottom: 15px; }
</style>
</head>
<body>
<div class="bg-shapes"><span></span><span></span><span></span><span></span></div>
<div class="auth-card">
  <div class="lock-icon">&#128274;</div>
  <h1>Flag Explorer</h1>
  {% if registration_locked and not has_credentials %}
  <p>Access denied. No passkey registered for this device.</p>
  {% elif has_credentials %}
  <p>Welcome back! Authenticate to continue.</p>
  <button class="auth-btn" id="loginBtn" onclick="doLogin()">&#128275; Login with Passkey</button>
  {% else %}
  <p>Create a passkey to get started.</p>
  <button class="auth-btn" id="registerBtn" onclick="doRegister()">&#128273; Create Passkey</button>
  {% endif %}
  <div class="status" id="status"></div>
</div>
<script>
const statusEl = document.getElementById('status');
function setStatus(msg, type) {
  statusEl.textContent = msg;
  statusEl.className = 'status' + (type ? ' ' + type : '');
}

function bufferToBase64url(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  bytes.forEach(b => binary += String.fromCharCode(b));
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64urlToBuffer(base64url) {
  const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
  const pad = base64.length % 4;
  const padded = pad ? base64 + '===='.slice(pad) : base64;
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

async function doRegister() {
  const btn = document.getElementById('registerBtn');
  btn.disabled = true;
  setStatus('Starting registration...', '');
  try {
    const optRes = await fetch('/register/options', { method: 'POST' });
    if (!optRes.ok) { const e = await optRes.json(); throw new Error(e.error || 'Failed to get options'); }
    const options = await optRes.json();

    // Decode challenge and user.id
    options.challenge = base64urlToBuffer(options.challenge);
    options.user.id = base64urlToBuffer(options.user.id);
    if (options.excludeCredentials) {
      options.excludeCredentials = options.excludeCredentials.map(c => ({
        ...c, id: base64urlToBuffer(c.id)
      }));
    }

    setStatus('Touch ID prompt...', '');
    const credential = await navigator.credentials.create({ publicKey: options });

    const body = {
      id: credential.id,
      rawId: bufferToBase64url(credential.rawId),
      type: credential.type,
      response: {
        attestationObject: bufferToBase64url(credential.response.attestationObject),
        clientDataJSON: bufferToBase64url(credential.response.clientDataJSON),
      }
    };

    const verifyRes = await fetch('/register/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });
    if (!verifyRes.ok) { const e = await verifyRes.json(); throw new Error(e.error || 'Verification failed'); }

    setStatus('Passkey created! Redirecting...', 'success');
    setTimeout(() => window.location.href = '/', 500);
  } catch (err) {
    console.error(err);
    setStatus(err.message || 'Registration failed', 'error');
    btn.disabled = false;
  }
}

async function doLogin() {
  const btn = document.getElementById('loginBtn');
  btn.disabled = true;
  setStatus('Starting authentication...', '');
  try {
    const optRes = await fetch('/login/options', { method: 'POST' });
    if (!optRes.ok) { const e = await optRes.json(); throw new Error(e.error || 'Failed to get options'); }
    const options = await optRes.json();

    options.challenge = base64urlToBuffer(options.challenge);
    if (options.allowCredentials) {
      options.allowCredentials = options.allowCredentials.map(c => ({
        ...c, id: base64urlToBuffer(c.id)
      }));
    }

    setStatus('Touch ID prompt...', '');
    const credential = await navigator.credentials.get({ publicKey: options });

    const body = {
      id: credential.id,
      rawId: bufferToBase64url(credential.rawId),
      type: credential.type,
      response: {
        authenticatorData: bufferToBase64url(credential.response.authenticatorData),
        clientDataJSON: bufferToBase64url(credential.response.clientDataJSON),
        signature: bufferToBase64url(credential.response.signature),
        userHandle: credential.response.userHandle
          ? bufferToBase64url(credential.response.userHandle)
          : null
      }
    };

    const verifyRes = await fetch('/login/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });
    if (!verifyRes.ok) { const e = await verifyRes.json(); throw new Error(e.error || 'Verification failed'); }

    setStatus('Authenticated! Redirecting...', 'success');
    setTimeout(() => window.location.href = '/', 500);
  } catch (err) {
    console.error(err);
    setStatus(err.message || 'Authentication failed', 'error');
    btn.disabled = false;
  }
}

// Auto-trigger login for returning users
{% if has_credentials %}
window.addEventListener('load', () => setTimeout(doLogin, 300));
{% endif %}
</script>
</body>
</html>
"""


# --- Auth Routes ---
@app.route("/auth")
def auth_page():
    rp_id = _get_rp_id()
    creds = load_credentials()
    rp_creds = [c for c in creds if c.get("rp_id") == rp_id]
    return render_template_string(
        AUTH_TEMPLATE,
        has_credentials=len(rp_creds) > 0,
        registration_locked=REGISTRATION_LOCK.exists(),
    )


@app.route("/register/options", methods=["POST"])
def register_options():
    if REGISTRATION_LOCK.exists():
        return jsonify({"error": "Registration is locked."}), 403
    rp_id = _get_rp_id()
    creds = load_credentials()
    rp_creds = [c for c in creds if c.get("rp_id") == rp_id]
    if len(rp_creds) > 0:
        return jsonify({"error": "Already registered on this device. Use Login."}), 403

    exclude = [
        PublicKeyCredentialDescriptor(id=_b64decode(c["credential_id"]))
        for c in rp_creds
    ]
    options = generate_registration_options(
        rp_id=rp_id,
        rp_name=RP_NAME,
        user_id=b"flag-explorer-user",
        user_name="explorer",
        user_display_name="Flag Explorer User",
        authenticator_selection=AuthenticatorSelectionCriteria(
            authenticator_attachment=AuthenticatorAttachment.PLATFORM,
            resident_key=ResidentKeyRequirement.PREFERRED,
            user_verification=UserVerificationRequirement.REQUIRED,
        ),
        exclude_credentials=exclude,
    )
    session["registration_challenge"] = _b64encode(options.challenge)
    return jsonify(json.loads(options_to_json(options)))


@app.route("/register/verify", methods=["POST"])
def register_verify():
    challenge_b64 = session.pop("registration_challenge", None)
    if not challenge_b64:
        return jsonify({"error": "No registration challenge found"}), 400

    body = request.get_json()
    try:
        verification = verify_registration_response(
            credential=body,
            expected_challenge=_b64decode(challenge_b64),
            expected_rp_id=_get_rp_id(),
            expected_origin=_get_origin(),
            require_user_verification=True,
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 400

    creds = load_credentials()
    creds.append({
        "credential_id": _b64encode(verification.credential_id),
        "public_key": _b64encode(verification.credential_public_key),
        "sign_count": verification.sign_count,
        "rp_id": _get_rp_id(),
    })
    save_credentials(creds)
    REGISTRATION_LOCK.touch()

    session["authenticated"] = True
    return jsonify({"status": "ok"})


@app.route("/login/options", methods=["POST"])
def login_options():
    rp_id = _get_rp_id()
    creds = load_credentials()
    rp_creds = [c for c in creds if c.get("rp_id") == rp_id]
    if not rp_creds:
        return jsonify({"error": "No credentials registered for this device"}), 400

    allow_credentials = [
        PublicKeyCredentialDescriptor(
            id=_b64decode(c["credential_id"]),
            transports=[AuthenticatorTransport.INTERNAL],
        )
        for c in rp_creds
    ]
    options = generate_authentication_options(
        rp_id=_get_rp_id(),
        allow_credentials=allow_credentials,
        user_verification=UserVerificationRequirement.REQUIRED,
    )
    session["authentication_challenge"] = _b64encode(options.challenge)
    return jsonify(json.loads(options_to_json(options)))


@app.route("/login/verify", methods=["POST"])
def login_verify():
    challenge_b64 = session.pop("authentication_challenge", None)
    if not challenge_b64:
        return jsonify({"error": "No authentication challenge found"}), 400

    body = request.get_json()
    creds = load_credentials()

    # Find the credential being used
    matching_cred = None
    for c in creds:
        if c["credential_id"] == body.get("id", ""):
            matching_cred = c
            break

    if not matching_cred:
        return jsonify({"error": "Unknown credential"}), 400

    try:
        verification = verify_authentication_response(
            credential=body,
            expected_challenge=_b64decode(challenge_b64),
            expected_rp_id=_get_rp_id(),
            expected_origin=_get_origin(),
            credential_public_key=_b64decode(matching_cred["public_key"]),
            credential_current_sign_count=matching_cred["sign_count"],
            require_user_verification=True,
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 400

    # Update sign count for replay protection
    matching_cred["sign_count"] = verification.new_sign_count
    save_credentials(creds)

    session["authenticated"] = True
    return jsonify({"status": "ok"})


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("auth_page"))


COUNTRIES = [
    {"name": "United States", "code": "US", "emoji": "\U0001F1FA\U0001F1F8", "fun_fact": "Has 50 stars on its flag!"},
    {"name": "China", "code": "CN", "emoji": "\U0001F1E8\U0001F1F3", "fun_fact": "Has big yellow stars!"},
    {"name": "Japan", "code": "JP", "emoji": "\U0001F1EF\U0001F1F5", "fun_fact": "A red circle for the sun!"},
    {"name": "Germany", "code": "DE", "emoji": "\U0001F1E9\U0001F1EA", "fun_fact": "Black, red, and gold stripes!"},
    {"name": "India", "code": "IN", "emoji": "\U0001F1EE\U0001F1F3", "fun_fact": "Has a spinning wheel in the middle!"},
    {"name": "United Kingdom", "code": "GB", "emoji": "\U0001F1EC\U0001F1E7", "fun_fact": "Called the Union Jack!"},
    {"name": "France", "code": "FR", "emoji": "\U0001F1EB\U0001F1F7", "fun_fact": "Blue, white, and red!"},
    {"name": "Italy", "code": "IT", "emoji": "\U0001F1EE\U0001F1F9", "fun_fact": "Green, white, and red!"},
    {"name": "Brazil", "code": "BR", "emoji": "\U0001F1E7\U0001F1F7", "fun_fact": "Has a starry sky on it!"},
    {"name": "Canada", "code": "CA", "emoji": "\U0001F1E8\U0001F1E6", "fun_fact": "Has a maple leaf!"},
    {"name": "Russia", "code": "RU", "emoji": "\U0001F1F7\U0001F1FA", "fun_fact": "White, blue, and red stripes!"},
    {"name": "South Korea", "code": "KR", "emoji": "\U0001F1F0\U0001F1F7", "fun_fact": "Has a cool yin-yang circle!"},
    {"name": "Australia", "code": "AU", "emoji": "\U0001F1E6\U0001F1FA", "fun_fact": "Has the Southern Cross stars!"},
    {"name": "Spain", "code": "ES", "emoji": "\U0001F1EA\U0001F1F8", "fun_fact": "Has a coat of arms on it!"},
    {"name": "Mexico", "code": "MX", "emoji": "\U0001F1F2\U0001F1FD", "fun_fact": "Has an eagle eating a snake!"},
    {"name": "Indonesia", "code": "ID", "emoji": "\U0001F1EE\U0001F1E9", "fun_fact": "Simple red and white!"},
    {"name": "Netherlands", "code": "NL", "emoji": "\U0001F1F3\U0001F1F1", "fun_fact": "Red, white, and blue stripes!"},
    {"name": "Saudi Arabia", "code": "SA", "emoji": "\U0001F1F8\U0001F1E6", "fun_fact": "Has a sword on green!"},
    {"name": "Turkey", "code": "TR", "emoji": "\U0001F1F9\U0001F1F7", "fun_fact": "A crescent moon and star!"},
    {"name": "Switzerland", "code": "CH", "emoji": "\U0001F1E8\U0001F1ED", "fun_fact": "A white cross on red!"},
    {"name": "Armenia", "code": "AM", "emoji": "\U0001F1E6\U0001F1F2", "fun_fact": "Red, blue, and orange stripes!"},
    {"name": "Georgia", "code": "GE", "emoji": "\U0001F1EC\U0001F1EA", "fun_fact": "A big red cross with four small crosses!"},
]


@app.route("/")
def index():
    if not session.get("authenticated"):
        return redirect(url_for("auth_page"))
    return render_template_string(HTML_TEMPLATE, countries=json.dumps(COUNTRIES))


HTML_TEMPLATE = r"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Flag Explorer!</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Fredoka+One&family=Nunito:wght@400;700;800&display=swap');

  * { margin: 0; padding: 0; box-sizing: border-box; }

  :root {
    --pink: #FF6B9D;
    --purple: #C44DFF;
    --blue: #4DA6FF;
    --green: #4DDB7F;
    --yellow: #FFD93D;
    --orange: #FF8C42;
    --bg: #1a1a2e;
    --card: #16213e;
  }

  body {
    font-family: 'Nunito', sans-serif;
    background: var(--bg);
    color: white;
    min-height: 100vh;
    overflow-x: hidden;
  }

  /* Floating background shapes */
  .bg-shapes {
    position: fixed; inset: 0; pointer-events: none; z-index: 0; overflow: hidden;
  }
  .bg-shapes span {
    position: absolute;
    display: block;
    border-radius: 50%;
    opacity: 0.07;
    animation: floatShape 20s infinite linear;
  }
  .bg-shapes span:nth-child(1) { width: 200px; height: 200px; background: var(--pink); top: 10%; left: 5%; animation-duration: 25s; }
  .bg-shapes span:nth-child(2) { width: 300px; height: 300px; background: var(--blue); top: 60%; left: 80%; animation-duration: 30s; animation-delay: -5s; }
  .bg-shapes span:nth-child(3) { width: 150px; height: 150px; background: var(--yellow); top: 80%; left: 20%; animation-duration: 22s; animation-delay: -10s; }
  .bg-shapes span:nth-child(4) { width: 250px; height: 250px; background: var(--green); top: 20%; left: 70%; animation-duration: 28s; animation-delay: -3s; }

  @keyframes floatShape {
    0%, 100% { transform: translate(0, 0) rotate(0deg); }
    25% { transform: translate(30px, -40px) rotate(90deg); }
    50% { transform: translate(-20px, 20px) rotate(180deg); }
    75% { transform: translate(40px, 30px) rotate(270deg); }
  }

  .container {
    max-width: 900px;
    margin: 0 auto;
    padding: 20px;
    position: relative;
    z-index: 1;
  }

  /* Header */
  header {
    text-align: center;
    padding: 30px 0 20px;
  }
  header h1 {
    font-family: 'Fredoka One', cursive;
    font-size: 3em;
    background: linear-gradient(135deg, var(--yellow), var(--orange), var(--pink));
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
    text-shadow: none;
    margin-bottom: 5px;
  }
  header p {
    font-size: 1.2em;
    color: #aaa;
  }

  /* Score bar */
  .score-bar {
    display: flex;
    justify-content: center;
    gap: 30px;
    margin: 15px 0 25px;
    flex-wrap: wrap;
  }
  .score-item {
    background: var(--card);
    border-radius: 20px;
    padding: 10px 25px;
    display: flex;
    align-items: center;
    gap: 10px;
    font-weight: 700;
    font-size: 1.1em;
    border: 2px solid rgba(255,255,255,0.05);
  }
  .score-item .icon { font-size: 1.5em; }
  .streak-fire { color: var(--orange); }
  .stars-display { color: var(--yellow); }

  /* Mode selector */
  .mode-selector {
    display: flex;
    gap: 12px;
    justify-content: center;
    margin-bottom: 30px;
    flex-wrap: wrap;
  }
  .mode-btn {
    font-family: 'Nunito', sans-serif;
    font-weight: 800;
    font-size: 1em;
    padding: 12px 28px;
    border: none;
    border-radius: 50px;
    cursor: pointer;
    transition: all 0.3s;
    color: white;
    position: relative;
    overflow: hidden;
  }
  .mode-btn:hover { transform: translateY(-3px); box-shadow: 0 8px 25px rgba(0,0,0,0.3); }
  .mode-btn:active { transform: translateY(0); }
  .mode-btn.active { transform: translateY(-3px); box-shadow: 0 8px 25px rgba(0,0,0,0.3); }
  .mode-btn-quiz { background: linear-gradient(135deg, var(--purple), #7B2FBE); }
  .mode-btn-match { background: linear-gradient(135deg, var(--blue), #2E86DE); }
  .mode-btn-explore { background: linear-gradient(135deg, var(--green), #27AE60); }

  /* Game area */
  .game-area {
    background: var(--card);
    border-radius: 30px;
    padding: 35px;
    min-height: 400px;
    border: 2px solid rgba(255,255,255,0.05);
    position: relative;
  }

  /* QUIZ MODE */
  .quiz-flag {
    font-size: 8em;
    text-align: center;
    margin: 10px 0 15px;
    animation: flagBounce 2s ease-in-out infinite;
    line-height: 1.2;
  }
  @keyframes flagBounce {
    0%, 100% { transform: scale(1); }
    50% { transform: scale(1.05); }
  }
  .quiz-prompt {
    text-align: center;
    font-size: 1.5em;
    font-weight: 700;
    margin-bottom: 25px;
    color: #ccc;
  }
  .quiz-options {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 15px;
    max-width: 600px;
    margin: 0 auto;
  }
  .quiz-option {
    font-family: 'Nunito', sans-serif;
    font-weight: 700;
    font-size: 1.15em;
    padding: 18px 20px;
    border: 3px solid rgba(255,255,255,0.1);
    border-radius: 20px;
    background: rgba(255,255,255,0.03);
    color: white;
    cursor: pointer;
    transition: all 0.2s;
  }
  .quiz-option:hover {
    border-color: var(--blue);
    background: rgba(77, 166, 255, 0.1);
    transform: scale(1.03);
  }
  .quiz-option.correct {
    border-color: var(--green) !important;
    background: rgba(77, 219, 127, 0.2) !important;
    animation: correctPop 0.5s ease;
  }
  .quiz-option.wrong {
    border-color: var(--pink) !important;
    background: rgba(255, 107, 157, 0.2) !important;
    animation: wrongShake 0.5s ease;
  }
  @keyframes correctPop {
    0% { transform: scale(1); }
    50% { transform: scale(1.08); }
    100% { transform: scale(1); }
  }
  @keyframes wrongShake {
    0%, 100% { transform: translateX(0); }
    20% { transform: translateX(-10px); }
    40% { transform: translateX(10px); }
    60% { transform: translateX(-6px); }
    80% { transform: translateX(6px); }
  }

  /* Fun fact */
  .fun-fact {
    text-align: center;
    margin-top: 20px;
    padding: 15px 25px;
    background: rgba(255, 217, 61, 0.1);
    border: 2px solid rgba(255, 217, 61, 0.2);
    border-radius: 20px;
    font-size: 1.1em;
    color: var(--yellow);
    animation: fadeInUp 0.4s ease;
  }

  /* Progress bar */
  .progress-wrap {
    margin-top: 25px;
  }
  .progress-label {
    font-weight: 700;
    margin-bottom: 8px;
    color: #aaa;
    font-size: 0.95em;
  }
  .progress-bar {
    height: 14px;
    background: rgba(255,255,255,0.05);
    border-radius: 20px;
    overflow: hidden;
  }
  .progress-fill {
    height: 100%;
    background: linear-gradient(90deg, var(--purple), var(--pink));
    border-radius: 20px;
    transition: width 0.5s ease;
  }

  /* MATCH MODE */
  .match-grid {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 12px;
    max-width: 800px;
    margin: 0 auto;
  }
  .match-card {
    aspect-ratio: 1;
    border-radius: 18px;
    display: flex;
    align-items: center;
    justify-content: center;
    cursor: pointer;
    transition: all 0.3s;
    font-size: 1em;
    font-weight: 700;
    text-align: center;
    perspective: 600px;
    position: relative;
    border: 3px solid rgba(255,255,255,0.08);
    background: rgba(255,255,255,0.03);
    padding: 8px;
    user-select: none;
  }
  .match-card:hover { transform: translateY(-4px); border-color: rgba(255,255,255,0.2); }
  .match-card .card-content { font-size: 4.5em; line-height: 1; }
  .match-card .card-text { font-size: 1.05em; line-height: 1.2; }
  .match-card.selected { border-color: var(--yellow); background: rgba(255, 217, 61, 0.1); box-shadow: 0 0 20px rgba(255,217,61,0.2); }
  .match-card.matched {
    border-color: var(--green);
    background: rgba(77, 219, 127, 0.15);
    pointer-events: none;
    animation: matchPop 0.5s ease;
  }
  .match-card.wrong-match {
    animation: wrongShake 0.5s ease;
    border-color: var(--pink);
    background: rgba(255, 107, 157, 0.15);
  }
  @keyframes matchPop {
    0% { transform: scale(1); }
    40% { transform: scale(1.12); }
    100% { transform: scale(1); }
  }

  /* EXPLORE MODE */
  .explore-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
    gap: 18px;
  }
  .explore-card {
    background: rgba(255,255,255,0.03);
    border: 2px solid rgba(255,255,255,0.08);
    border-radius: 20px;
    padding: 25px 20px;
    text-align: center;
    cursor: pointer;
    transition: all 0.3s;
  }
  .explore-card:hover {
    transform: translateY(-5px);
    border-color: var(--purple);
    background: rgba(196, 77, 255, 0.08);
  }
  .explore-card .flag { font-size: 7em; margin-bottom: 10px; line-height: 1.1; }
  .explore-card .name { font-weight: 800; font-size: 1.3em; }
  .explore-card .fact { color: #aaa; font-size: 1em; margin-top: 8px; }
  .explore-card.expanded {
    grid-column: 1 / -1;
    border-color: var(--yellow);
    background: rgba(255, 217, 61, 0.05);
  }
  .explore-card.expanded .flag { font-size: 10em; }
  .explore-card.expanded .fact { color: var(--yellow); font-size: 1.2em; }

  /* Celebration overlay */
  .celebration {
    display: none;
    position: fixed;
    inset: 0;
    z-index: 100;
    background: rgba(0,0,0,0.7);
    align-items: center;
    justify-content: center;
    flex-direction: column;
  }
  .celebration.active { display: flex; }
  .celebration h2 {
    font-family: 'Fredoka One', cursive;
    font-size: 3.5em;
    margin-bottom: 10px;
    animation: celebBounce 0.8s ease;
  }
  .celebration .sub {
    font-size: 1.5em;
    margin-bottom: 30px;
    color: #ccc;
  }
  .celebration .play-again {
    font-family: 'Nunito', sans-serif;
    font-weight: 800;
    font-size: 1.3em;
    padding: 16px 50px;
    border: none;
    border-radius: 50px;
    background: linear-gradient(135deg, var(--yellow), var(--orange));
    color: #1a1a2e;
    cursor: pointer;
    transition: all 0.3s;
  }
  .celebration .play-again:hover { transform: scale(1.08); }
  @keyframes celebBounce {
    0% { transform: scale(0); opacity: 0; }
    60% { transform: scale(1.2); }
    100% { transform: scale(1); opacity: 1; }
  }

  /* Confetti */
  .confetti-piece {
    position: fixed;
    width: 12px;
    height: 12px;
    z-index: 101;
    pointer-events: none;
    border-radius: 3px;
    animation: confettiFall 3s ease-in forwards;
  }
  @keyframes confettiFall {
    0% { transform: translateY(-20px) rotate(0deg); opacity: 1; }
    100% { transform: translateY(110vh) rotate(720deg); opacity: 0; }
  }

  /* Feedback popup */
  .feedback {
    position: fixed;
    top: 50%;
    left: 50%;
    transform: translate(-50%, -50%) scale(0);
    font-family: 'Fredoka One', cursive;
    font-size: 4em;
    z-index: 50;
    pointer-events: none;
    animation: feedbackPop 1s ease forwards;
  }
  @keyframes feedbackPop {
    0% { transform: translate(-50%, -50%) scale(0); opacity: 1; }
    30% { transform: translate(-50%, -50%) scale(1.3); opacity: 1; }
    100% { transform: translate(-50%, -80%) scale(1); opacity: 0; }
  }

  @keyframes fadeInUp {
    from { opacity: 0; transform: translateY(15px); }
    to { opacity: 1; transform: translateY(0); }
  }

  .round-info {
    text-align: center;
    font-weight: 700;
    color: #aaa;
    margin-bottom: 5px;
  }

  /* Responsive */
  @media (max-width: 600px) {
    header h1 { font-size: 2em; }
    .quiz-flag { font-size: 5em; }
    .quiz-options { grid-template-columns: 1fr; }
    .match-grid { grid-template-columns: repeat(3, 1fr); }
    .game-area { padding: 20px; border-radius: 20px; }
    .mode-btn { padding: 10px 20px; font-size: 0.9em; }
  }
</style>
</head>
<body>
<div class="bg-shapes"><span></span><span></span><span></span><span></span></div>

<div class="container">
  <header>
    <a href="/logout" style="position:absolute;top:20px;right:20px;background:rgba(255,255,255,0.08);border:1px solid rgba(255,255,255,0.12);border-radius:12px;padding:8px 16px;color:#aaa;text-decoration:none;font-size:0.85em;font-weight:700;transition:all 0.2s;" onmouseover="this.style.color='#FF6B9D';this.style.borderColor='#FF6B9D'" onmouseout="this.style.color='#aaa';this.style.borderColor='rgba(255,255,255,0.12)'">&#128274; Logout</a>
    <h1>Flag Explorer</h1>
    <p>Learn the flags of the world!</p>
  </header>

  <div class="score-bar">
    <div class="score-item">
      <span class="icon stars-display">&#11088;</span>
      <span>Stars: <span id="stars">0</span></span>
    </div>
    <div class="score-item">
      <span class="icon streak-fire">&#128293;</span>
      <span>Streak: <span id="streak">0</span></span>
    </div>
    <div class="score-item">
      <span class="icon">&#127942;</span>
      <span>Best: <span id="best">0</span></span>
    </div>
  </div>

  <div class="mode-selector">
    <button class="mode-btn mode-btn-quiz active" onclick="switchMode('quiz')">&#127891; Quiz</button>
    <button class="mode-btn mode-btn-match" onclick="switchMode('match')">&#129513; Match</button>
    <button class="mode-btn mode-btn-explore" onclick="switchMode('explore')">&#127758; Explore</button>
  </div>

  <div class="game-area" id="gameArea"></div>
</div>

<div class="celebration" id="celebration">
  <h2 id="celebTitle">&#127881; Amazing! &#127881;</h2>
  <p class="sub" id="celebSub">You're a flag superstar!</p>
  <button class="play-again" onclick="playAgain()">Play Again!</button>
</div>

<script>
const COUNTRIES = {{ countries | safe }};
let state = {
  mode: 'quiz',
  stars: 0,
  streak: 0,
  best: 0,
  quizRound: 0,
  quizOrder: [],
  quizTotal: 10,
  quizCorrect: 0,
  matchCards: [],
  matchSelected: null,
  matchPairs: 0,
  locked: false
};

// Audio context for sound effects
const AudioCtx = window.AudioContext || window.webkitAudioContext;
let audioCtx;
function ensureAudio() {
  if (!audioCtx) audioCtx = new AudioCtx();
}

function playTone(freq, duration, type='sine') {
  ensureAudio();
  const o = audioCtx.createOscillator();
  const g = audioCtx.createGain();
  o.type = type;
  o.frequency.value = freq;
  g.gain.value = 0.1;
  g.gain.exponentialRampToValueAtTime(0.001, audioCtx.currentTime + duration);
  o.connect(g);
  g.connect(audioCtx.destination);
  o.start();
  o.stop(audioCtx.currentTime + duration);
}

function playCorrect() {
  playTone(523, 0.15);
  setTimeout(() => playTone(659, 0.15), 100);
  setTimeout(() => playTone(784, 0.3), 200);
}

function playWrong() {
  playTone(311, 0.3, 'square');
}

function playCelebration() {
  [523, 587, 659, 698, 784, 880, 988, 1047].forEach((f, i) => {
    setTimeout(() => playTone(f, 0.2), i * 80);
  });
}

// Shuffle helper
function shuffle(arr) {
  const a = [...arr];
  for (let i = a.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}

function switchMode(mode) {
  state.mode = mode;
  document.querySelectorAll('.mode-btn').forEach(b => b.classList.remove('active'));
  document.querySelector(`.mode-btn-${mode}`).classList.add('active');
  if (mode === 'quiz') startQuiz();
  else if (mode === 'match') startMatch();
  else if (mode === 'explore') showExplore();
}

function updateScores() {
  document.getElementById('stars').textContent = state.stars;
  document.getElementById('streak').textContent = state.streak;
  document.getElementById('best').textContent = state.best;
}

function showFeedback(text) {
  const el = document.createElement('div');
  el.className = 'feedback';
  el.textContent = text;
  document.body.appendChild(el);
  setTimeout(() => el.remove(), 1000);
}

function spawnConfetti() {
  const colors = ['#FF6B9D','#C44DFF','#4DA6FF','#4DDB7F','#FFD93D','#FF8C42'];
  for (let i = 0; i < 60; i++) {
    const c = document.createElement('div');
    c.className = 'confetti-piece';
    c.style.left = Math.random() * 100 + 'vw';
    c.style.background = colors[Math.floor(Math.random() * colors.length)];
    c.style.animationDelay = Math.random() * 1.5 + 's';
    c.style.animationDuration = (2 + Math.random() * 2) + 's';
    document.body.appendChild(c);
    setTimeout(() => c.remove(), 5000);
  }
}

// ==================== QUIZ MODE ====================
function startQuiz() {
  state.quizOrder = shuffle([...Array(COUNTRIES.length).keys()]).slice(0, state.quizTotal);
  state.quizRound = 0;
  state.quizCorrect = 0;
  showQuizRound();
}

function showQuizRound() {
  if (state.quizRound >= state.quizTotal) {
    endQuiz();
    return;
  }
  const idx = state.quizOrder[state.quizRound];
  const country = COUNTRIES[idx];
  // Pick 3 wrong answers
  let wrongIdxs = shuffle([...Array(COUNTRIES.length).keys()].filter(i => i !== idx)).slice(0, 3);
  let options = shuffle([idx, ...wrongIdxs]);

  const area = document.getElementById('gameArea');
  area.innerHTML = `
    <div class="round-info">Question ${state.quizRound + 1} of ${state.quizTotal}</div>
    <div class="quiz-flag" id="quizFlag">${country.emoji}</div>
    <div class="quiz-prompt">Which country is this flag from?</div>
    <div class="quiz-options" id="quizOptions">
      ${options.map(i => `
        <button class="quiz-option" data-idx="${i}" onclick="quizAnswer(this, ${i}, ${idx})">${COUNTRIES[i].name}</button>
      `).join('')}
    </div>
    <div id="funFact"></div>
    <div class="progress-wrap">
      <div class="progress-label">Progress</div>
      <div class="progress-bar"><div class="progress-fill" style="width: ${(state.quizRound / state.quizTotal) * 100}%"></div></div>
    </div>
  `;
}

function quizAnswer(btn, chosen, correct) {
  if (state.locked) return;
  state.locked = true;
  const isCorrect = chosen === correct;
  const country = COUNTRIES[correct];

  if (isCorrect) {
    btn.classList.add('correct');
    state.stars++;
    state.streak++;
    state.quizCorrect++;
    if (state.streak > state.best) state.best = state.streak;
    playCorrect();
    const feedbacks = ['Super!', 'Wow!', 'Yes!', 'Cool!', 'Nice!'];
    showFeedback(feedbacks[Math.floor(Math.random() * feedbacks.length)]);
  } else {
    btn.classList.add('wrong');
    state.streak = 0;
    playWrong();
    // Highlight correct
    document.querySelectorAll('.quiz-option').forEach(b => {
      if (parseInt(b.dataset.idx) === correct) b.classList.add('correct');
    });
    showFeedback('Oops!');
  }

  updateScores();
  document.getElementById('funFact').innerHTML = `<div class="fun-fact">&#128161; ${country.fun_fact}</div>`;

  setTimeout(() => {
    state.quizRound++;
    state.locked = false;
    showQuizRound();
  }, isCorrect ? 1500 : 2500);
}

function endQuiz() {
  spawnConfetti();
  playCelebration();
  const pct = Math.round((state.quizCorrect / state.quizTotal) * 100);
  let msg, sub;
  if (pct === 100) { msg = '&#127775; PERFECT! &#127775;'; sub = 'You got every single one right!'; }
  else if (pct >= 80) { msg = '&#127881; Amazing! &#127881;'; sub = `You got ${state.quizCorrect} out of ${state.quizTotal}!`; }
  else if (pct >= 50) { msg = '&#128079; Great Job! &#128079;'; sub = `You got ${state.quizCorrect} out of ${state.quizTotal}!`; }
  else { msg = '&#128170; Keep Going! &#128170;'; sub = `You got ${state.quizCorrect} out of ${state.quizTotal}! Try again!`; }

  document.getElementById('celebTitle').innerHTML = msg;
  document.getElementById('celebSub').textContent = sub;
  document.getElementById('celebration').classList.add('active');
}

// ==================== MATCH MODE ====================
function startMatch() {
  // Pick 6 countries for 12 cards (6 flag + 6 name)
  const chosen = shuffle([...Array(COUNTRIES.length).keys()]).slice(0, 6);
  let cards = [];
  chosen.forEach(i => {
    cards.push({ id: i, type: 'flag', display: COUNTRIES[i].emoji, matched: false });
    cards.push({ id: i, type: 'name', display: COUNTRIES[i].name, matched: false });
  });
  state.matchCards = shuffle(cards);
  state.matchSelected = null;
  state.matchPairs = 0;
  renderMatch();
}

function renderMatch() {
  const area = document.getElementById('gameArea');
  area.innerHTML = `
    <div class="round-info" style="margin-bottom:20px;">Match each flag to its country!</div>
    <div class="match-grid">
      ${state.matchCards.map((card, i) => `
        <div class="match-card ${card.matched ? 'matched' : ''} ${state.matchSelected === i ? 'selected' : ''}"
             onclick="matchClick(${i})" id="mc${i}">
          <span class="${card.type === 'flag' ? 'card-content' : 'card-text'}">${card.display}</span>
        </div>
      `).join('')}
    </div>
  `;
}

function matchClick(i) {
  if (state.locked) return;
  const card = state.matchCards[i];
  if (card.matched) return;
  if (state.matchSelected === i) {
    state.matchSelected = null;
    renderMatch();
    return;
  }

  if (state.matchSelected === null) {
    state.matchSelected = i;
    renderMatch();
    return;
  }

  const first = state.matchCards[state.matchSelected];
  const second = card;

  // Must be different types
  if (first.type === second.type) {
    state.matchSelected = i;
    renderMatch();
    return;
  }

  state.locked = true;
  // Highlight both
  document.getElementById('mc' + state.matchSelected).classList.add('selected');
  document.getElementById('mc' + i).classList.add('selected');

  if (first.id === second.id) {
    // Match!
    first.matched = true;
    second.matched = true;
    state.matchPairs++;
    state.stars++;
    state.streak++;
    if (state.streak > state.best) state.best = state.streak;
    updateScores();
    playCorrect();
    showFeedback('Match!');

    setTimeout(() => {
      state.matchSelected = null;
      state.locked = false;
      if (state.matchPairs === 6) {
        spawnConfetti();
        playCelebration();
        document.getElementById('celebTitle').innerHTML = '&#127881; You matched them all! &#127881;';
        document.getElementById('celebSub').textContent = 'Amazing memory!';
        document.getElementById('celebration').classList.add('active');
      } else {
        renderMatch();
      }
    }, 600);
  } else {
    // No match
    state.streak = 0;
    updateScores();
    playWrong();
    document.getElementById('mc' + state.matchSelected).classList.add('wrong-match');
    document.getElementById('mc' + i).classList.add('wrong-match');

    setTimeout(() => {
      state.matchSelected = null;
      state.locked = false;
      renderMatch();
    }, 800);
  }
}

// ==================== EXPLORE MODE ====================
function showExplore() {
  const area = document.getElementById('gameArea');
  area.innerHTML = `
    <div class="round-info" style="margin-bottom:20px;">Tap a flag to learn about it!</div>
    <div class="explore-grid" id="exploreGrid">
      ${COUNTRIES.map((c, i) => `
        <div class="explore-card" onclick="toggleExplore(this, ${i})" id="ec${i}">
          <div class="flag">${c.emoji}</div>
          <div class="name">${c.name}</div>
          <div class="fact">${c.fun_fact}</div>
        </div>
      `).join('')}
    </div>
  `;
}

function toggleExplore(el, i) {
  const wasExpanded = el.classList.contains('expanded');
  document.querySelectorAll('.explore-card').forEach(c => c.classList.remove('expanded'));
  if (!wasExpanded) {
    el.classList.add('expanded');
    el.scrollIntoView({ behavior: 'smooth', block: 'center' });
  }
}

function playAgain() {
  document.getElementById('celebration').classList.remove('active');
  switchMode(state.mode);
}

// Start!
startQuiz();
</script>
</body>
</html>
"""

if __name__ == "__main__":
    cert = Path(__file__).parent / "cert.pem"
    key = Path(__file__).parent / "key.pem"
    ssl_ctx = (cert, key) if cert.exists() and key.exists() else None
    app.run(
        debug=True,
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5050)),
        ssl_context=ssl_ctx,
    )

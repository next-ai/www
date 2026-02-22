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
RP_NAME = "musoyan.com"
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


# --- Global auth guard ---
AUTH_EXEMPT_PREFIXES = ("/auth", "/register", "/login", "/logout", "/robots.txt")


@app.before_request
def require_auth():
    if request.path.startswith(AUTH_EXEMPT_PREFIXES):
        return None
    if not session.get("authenticated"):
        return redirect(url_for("auth_page"))
    return None


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
<title>Login</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    background: #1a1a2e; color: white;
    min-height: 100vh; display: flex;
    align-items: center; justify-content: center;
  }
  .auth {
    text-align: center; position: relative; z-index: 1;
  }
  .auth-btn {
    font-family: inherit; font-weight: 600; font-size: 1em;
    padding: 14px 36px; border: 1px solid rgba(255,255,255,0.15);
    border-radius: 8px; cursor: pointer; color: white;
    background: rgba(255,255,255,0.06); transition: all 0.2s;
  }
  .auth-btn:hover { background: rgba(255,255,255,0.1); border-color: rgba(255,255,255,0.25); }
  .auth-btn:active { transform: scale(0.98); }
  .auth-btn:disabled { opacity: 0.4; cursor: not-allowed; transform: none; }
  .status { margin-top: 16px; font-size: 0.9em; color: #888; min-height: 1.4em; }
  .status.error { color: #e06; }
  .status.success { color: #4d8; }
  .denied { color: #888; font-size: 0.95em; }
</style>
</head>
<body>
<div class="auth">
  {% if registration_locked and not has_credentials %}
  <p class="denied">Access denied.</p>
  {% elif has_credentials %}
  <button class="auth-btn" id="loginBtn" onclick="doLogin()">Authenticate</button>
  {% else %}
  <button class="auth-btn" id="registerBtn" onclick="doRegister()">Set up passkey</button>
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
        user_id=b"musoyan-user",
        user_name="musoyan",
        user_display_name="Musoyan",
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


@app.route("/robots.txt")
def robots():
    return "User-agent: *\nDisallow: /\n", 200, {"Content-Type": "text/plain"}


from flags import flags_bp


LANDING_TEMPLATE = r"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Musoyan</title>
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
  .landing {
    text-align: center; position: relative; z-index: 1;
    max-width: 600px; width: 90%;
  }
  .landing h1 {
    font-family: 'Fredoka One', cursive; font-size: 3.5em;
    background: linear-gradient(135deg, var(--yellow), var(--orange), var(--pink));
    -webkit-background-clip: text; -webkit-text-fill-color: transparent;
    background-clip: text; margin-bottom: 40px;
  }
  .apps {
    display: grid; gap: 18px;
  }
  .app-card {
    display: flex; align-items: center; gap: 20px;
    background: var(--card); border: 2px solid rgba(255,255,255,0.05);
    border-radius: 20px; padding: 25px 30px;
    text-decoration: none; color: white;
    transition: all 0.3s;
  }
  .app-card:hover {
    transform: translateY(-4px);
    border-color: var(--purple);
    box-shadow: 0 8px 30px rgba(0,0,0,0.3);
  }
  .app-card .icon { font-size: 2.5em; }
  .app-card .info { text-align: left; }
  .app-card .info .name { font-weight: 800; font-size: 1.3em; }
  .app-card .info .desc { color: #aaa; font-size: 0.95em; margin-top: 2px; }
  .logout-btn {
    position: fixed; top: 20px; right: 20px;
    background: rgba(255,255,255,0.08); border: 1px solid rgba(255,255,255,0.12);
    border-radius: 12px; padding: 8px 16px;
    color: #aaa; text-decoration: none;
    font-size: 0.85em; font-weight: 700;
    transition: all 0.2s; z-index: 2;
  }
  .logout-btn:hover { color: var(--pink); border-color: var(--pink); }
</style>
</head>
<body>
<div class="bg-shapes"><span></span><span></span><span></span><span></span></div>
<a href="/logout" class="logout-btn">&#128274; Logout</a>
<div class="landing">
  <h1>Musoyan</h1>
  <div class="apps">
    <a href="/flags" class="app-card">
      <span class="icon">&#127988;</span>
      <div class="info">
        <div class="name">Flag Explorer</div>
        <div class="desc">Learn the flags of the world</div>
      </div>
    </a>
  </div>
</div>
</body>
</html>
"""


@app.route("/")
def landing():
    return render_template_string(LANDING_TEMPLATE)


app.register_blueprint(flags_bp)

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

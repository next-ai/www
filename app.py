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
    background: #f5f0eb; color: #2c2c2c;
    min-height: 100vh; display: flex;
    align-items: center; justify-content: center;
  }
  .auth { text-align: center; }
  .auth-btn {
    font-family: inherit; font-weight: 600; font-size: 1em;
    padding: 14px 36px;
    border: 1px solid #e8e2dc;
    border-radius: 10px; cursor: pointer;
    color: #2c2c2c; background: #fff;
    box-shadow: 0 1px 3px rgba(0,0,0,0.04);
    transition: all 0.2s;
  }
  .auth-btn:hover { border-color: #c9bfb4; box-shadow: 0 4px 16px rgba(0,0,0,0.07); }
  .auth-btn:active { transform: scale(0.98); }
  .auth-btn:disabled { opacity: 0.4; cursor: not-allowed; transform: none; }
  .status { margin-top: 16px; font-size: 0.9em; color: #9a8f85; min-height: 1.4em; }
  .status.error { color: #c45; }
  .status.success { color: #5a9a6a; }
  .denied { color: #9a8f85; font-size: 0.95em; }
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
from tictactoe import tictactoe_bp


LANDING_TEMPLATE = r"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Musoyan</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    background: #f5f0eb; color: #2c2c2c;
    min-height: 100vh; display: flex;
    align-items: center; justify-content: center;
  }
  .landing { max-width: 460px; width: 90%; text-align: center; }
  .landing h1 {
    font-size: 2.2em; font-weight: 600;
    color: #3a3a3a; margin-bottom: 12px;
  }
  .landing .subtitle {
    font-size: 0.95em; color: #9a8f85;
    margin-bottom: 44px;
  }
  .apps { display: grid; gap: 14px; }
  .app-card {
    display: flex; align-items: center; gap: 18px;
    padding: 20px 24px;
    text-decoration: none; color: #2c2c2c;
    background: #fff;
    border: 1px solid #e8e2dc;
    border-radius: 14px;
    transition: all 0.2s;
    text-align: left;
    box-shadow: 0 1px 3px rgba(0,0,0,0.04);
  }
  .app-card:hover {
    border-color: #c9bfb4;
    box-shadow: 0 4px 16px rgba(0,0,0,0.07);
    transform: translateY(-2px);
  }
  .app-card .icon {
    font-size: 2em;
    width: 52px; height: 52px;
    display: flex; align-items: center; justify-content: center;
    background: #f0ebe5; border-radius: 12px;
    flex-shrink: 0;
  }
  .app-card .info .name { font-weight: 600; font-size: 1.05em; color: #2c2c2c; }
  .app-card .info .desc { color: #9a8f85; font-size: 0.88em; margin-top: 3px; }
  .logout-btn {
    display: inline-block; margin-top: 44px;
    padding: 10px 30px;
    color: #9a8f85; text-decoration: none;
    font-size: 0.88em; font-weight: 500;
    background: #fff;
    border: 1px solid #e8e2dc;
    border-radius: 10px;
    transition: all 0.2s;
  }
  .logout-btn:hover { color: #6b5f53; border-color: #c9bfb4; }
</style>
</head>
<body>
<div class="landing">
  <h1>Musoyan</h1>
  <p class="subtitle">Welcome back</p>
  <div class="apps">
    <a href="/flags" class="app-card">
      <span class="icon">&#127988;</span>
      <div class="info">
        <div class="name">Flag Explorer</div>
        <div class="desc">Learn the flags of the world</div>
      </div>
    </a>
    <a href="/tictactoe" class="app-card">
      <span class="icon">&#10060;</span>
      <div class="info">
        <div class="name">Tic-Tac-Toe</div>
        <div class="desc">Play against an unbeatable AI</div>
      </div>
    </a>
  </div>
  <a href="/logout" class="logout-btn">Log out</a>
</div>
</body>
</html>
"""


@app.route("/")
def landing():
    return render_template_string(LANDING_TEMPLATE)


app.register_blueprint(flags_bp)
app.register_blueprint(tictactoe_bp)

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

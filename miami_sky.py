from flask import Blueprint, render_template_string

miami_sky_bp = Blueprint("miami_sky", __name__, url_prefix="/miami-sky")

MIAMI_SKY_TEMPLATE = r"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Miami Sky</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    background: #f5f0eb; color: #2c2c2c;
    min-height: 100vh; display: flex;
    align-items: center; justify-content: center;
  }
  .container { max-width: 460px; width: 90%; text-align: center; }
  h1 { font-size: 1.8em; font-weight: 600; color: #3a3a3a; margin-bottom: 6px; }
  .subtitle { font-size: 0.92em; color: #9a8f85; margin-bottom: 28px; }
  .card {
    background: #fff;
    border: 1px solid #e8e2dc;
    border-radius: 14px;
    padding: 28px 24px;
    margin-bottom: 14px;
    box-shadow: 0 1px 3px rgba(0,0,0,0.04);
    text-align: left;
  }
  .card-title {
    font-weight: 600; font-size: 1.05em; color: #3a3a3a;
    margin-bottom: 12px; display: flex; align-items: center; gap: 10px;
  }
  .card-title .icon { font-size: 1.4em; }
  .card-value {
    font-size: 1.6em; font-weight: 600; color: #2c2c2c;
    margin-bottom: 6px;
  }
  .card-detail { font-size: 0.88em; color: #9a8f85; }
  .back {
    display: inline-block; margin-top: 28px;
    padding: 10px 30px;
    color: #9a8f85; text-decoration: none;
    font-size: 0.88em; font-weight: 500;
    background: #fff;
    border: 1px solid #e8e2dc;
    border-radius: 10px;
    transition: all 0.2s;
  }
  .back:hover { color: #6b5f53; border-color: #c9bfb4; }
  .updated { font-size: 0.78em; color: #b8b0a6; margin-top: 18px; }
</style>
</head>
<body>
<div class="container">
  <h1>Miami Sky</h1>
  <p class="subtitle">25.76&#176;N, 80.19&#176;W</p>

  <div class="card">
    <div class="card-title"><span class="icon">&#9728;&#65039;</span> Sunset</div>
    <div class="card-value" id="sunsetValue">--</div>
    <div class="card-detail" id="sunsetDetail"></div>
  </div>

  <div class="card">
    <div class="card-title"><span class="icon">&#127761;</span> Moon</div>
    <div class="card-value" id="moonValue">--</div>
    <div class="card-detail" id="moonDetail"></div>
  </div>

  <div class="updated" id="updated"></div>
  <a href="/" class="back">Back to home</a>
</div>

<script>
// Miami coordinates
const LAT = 25.7617;
const LNG = -80.1918;

function toRad(d) { return d * Math.PI / 180; }
function toDeg(r) { return r * 180 / Math.PI; }

// Julian date from JS Date
function toJulian(date) {
  return date.getTime() / 86400000 + 2440587.5;
}

// Compute sunset time for a given date in Miami (returns a Date or null)
function computeSunset(date) {
  const jd = toJulian(date);
  const n = Math.floor(jd - 2451545.0 + 0.0008);
  const jStar = 2451545.0 + n - LNG / 360;
  const M = (357.5291 + 0.98560028 * (jStar - 2451545.0)) % 360;
  const mRad = toRad(M);
  const C = 1.9148 * Math.sin(mRad) + 0.02 * Math.sin(2 * mRad) + 0.0003 * Math.sin(3 * mRad);
  const lambdaSun = (M + C + 180 + 102.9372) % 360;
  const lambdaRad = toRad(lambdaSun);
  const jTransit = jStar + 0.0053 * Math.sin(mRad) - 0.0069 * Math.sin(2 * lambdaRad);
  const sinDec = Math.sin(lambdaRad) * Math.sin(toRad(23.4397));
  const cosDec = Math.cos(Math.asin(sinDec));
  const latRad = toRad(LAT);
  const cosH = (Math.sin(toRad(-0.833)) - Math.sin(latRad) * sinDec) / (Math.cos(latRad) * cosDec);
  if (cosH > 1 || cosH < -1) return null; // no sunset
  const H = toDeg(Math.acos(cosH));
  const jSet = jTransit + H / 360;
  return new Date((jSet - 2440587.5) * 86400000);
}

// Moon position (altitude above horizon)
function moonAltitude(date) {
  const jd = toJulian(date);
  const T = (jd - 2451545.0) / 36525;

  // Moon's mean elements
  const L0 = (218.3165 + 481267.8813 * T) % 360;
  const M = (134.9634 + 477198.8676 * T) % 360;  // moon mean anomaly
  const Ms = (357.5291 + 35999.0503 * T) % 360;   // sun mean anomaly
  const D = (297.8502 + 445267.1115 * T) % 360;    // mean elongation
  const F = (93.2720 + 483202.0175 * T) % 360;     // argument of latitude

  const mRad = toRad(M), msRad = toRad(Ms), dRad = toRad(D), fRad = toRad(F);

  // Ecliptic longitude
  let lon = L0
    + 6.289 * Math.sin(mRad)
    - 1.274 * Math.sin(2 * dRad - mRad)
    + 0.658 * Math.sin(2 * dRad)
    + 0.214 * Math.sin(2 * mRad)
    - 0.186 * Math.sin(msRad)
    - 0.114 * Math.sin(2 * fRad);

  // Ecliptic latitude
  let lat = 5.128 * Math.sin(fRad)
    + 0.281 * Math.sin(mRad + fRad)
    - 0.278 * Math.sin(fRad - mRad)
    - 0.173 * Math.sin(2 * dRad - fRad);

  const lonRad = toRad(lon), latRad = toRad(lat);
  const obliq = toRad(23.4397);

  // Equatorial coordinates
  const ra = Math.atan2(
    Math.sin(lonRad) * Math.cos(obliq) - Math.tan(latRad) * Math.sin(obliq),
    Math.cos(lonRad)
  );
  const dec = Math.asin(
    Math.sin(latRad) * Math.cos(obliq) + Math.cos(latRad) * Math.sin(obliq) * Math.sin(lonRad)
  );

  // Sidereal time at Greenwich
  const gmst = (280.46061837 + 360.98564736629 * (jd - 2451545.0)) % 360;
  const lst = toRad((gmst + LNG) % 360);
  const ha = lst - ra;
  const latR = toRad(LAT);

  const alt = Math.asin(Math.sin(latR) * Math.sin(dec) + Math.cos(latR) * Math.cos(dec) * Math.cos(ha));
  return toDeg(alt);
}

// Moon illumination percentage and phase name
function moonPhase(date) {
  const jd = toJulian(date);
  const T = (jd - 2451545.0) / 36525;
  const D = ((297.8502 + 445267.1115 * T) % 360 + 360) % 360;
  const M = ((357.5291 + 35999.0503 * T) % 360 + 360) % 360;
  const Mp = ((134.9634 + 477198.8676 * T) % 360 + 360) % 360;

  // Phase angle
  const i = 180 - D
    - 6.289 * Math.sin(toRad(Mp))
    + 2.1 * Math.sin(toRad(M))
    - 1.274 * Math.sin(toRad(2 * D - Mp))
    - 0.658 * Math.sin(toRad(2 * D))
    - 0.214 * Math.sin(toRad(2 * Mp))
    - 0.11 * Math.sin(toRad(D));

  const illumination = Math.round((1 + Math.cos(toRad(i))) / 2 * 100);

  // Phase name from elongation
  const phase = ((D % 360) + 360) % 360;
  let name;
  if (phase < 22.5)       name = "New Moon";
  else if (phase < 67.5)  name = "Waxing Crescent";
  else if (phase < 112.5) name = "First Quarter";
  else if (phase < 157.5) name = "Waxing Gibbous";
  else if (phase < 202.5) name = "Full Moon";
  else if (phase < 247.5) name = "Waning Gibbous";
  else if (phase < 292.5) name = "Last Quarter";
  else if (phase < 337.5) name = "Waning Crescent";
  else                     name = "New Moon";

  return { illumination, name };
}

function update() {
  const now = new Date();

  // --- Sunset ---
  const sunset = computeSunset(now);
  const sunEl = document.getElementById('sunsetValue');
  const sunDet = document.getElementById('sunsetDetail');

  if (!sunset) {
    sunEl.textContent = "No sunset today";
    sunDet.textContent = "";
  } else {
    const diff = sunset - now;
    if (diff > 0) {
      const h = Math.floor(diff / 3600000);
      const m = Math.floor((diff % 3600000) / 60000);
      sunEl.textContent = h + "h " + m + "m remaining";
      const timeStr = sunset.toLocaleTimeString('en-US', {
        hour: 'numeric', minute: '2-digit',
        timeZone: 'America/New_York'
      });
      sunDet.textContent = "Sunset at " + timeStr + " EST";
    } else {
      sunEl.textContent = "Past sunset";
      const timeStr = sunset.toLocaleTimeString('en-US', {
        hour: 'numeric', minute: '2-digit',
        timeZone: 'America/New_York'
      });
      sunDet.textContent = "Sunset was at " + timeStr + " EST";
    }
  }

  // --- Moon ---
  const alt = moonAltitude(now);
  const { illumination, name } = moonPhase(now);
  const moonEl = document.getElementById('moonValue');
  const moonDet = document.getElementById('moonDetail');

  if (alt > 0) {
    moonEl.textContent = "Above horizon";
    moonDet.textContent = name + " \u2022 " + illumination + "% illuminated \u2022 " + alt.toFixed(1) + "\u00B0 alt";
  } else {
    moonEl.textContent = "Below horizon";
    moonDet.textContent = name + " \u2022 " + illumination + "% illuminated";
  }

  // Timestamp
  document.getElementById('updated').textContent = "Updated " +
    now.toLocaleTimeString('en-US', { hour: 'numeric', minute: '2-digit', second: '2-digit', timeZone: 'America/New_York' }) + " EST";
}

update();
setInterval(update, 60000);
</script>
</body>
</html>
"""


@miami_sky_bp.route("/")
def miami_sky():
    return render_template_string(MIAMI_SKY_TEMPLATE)

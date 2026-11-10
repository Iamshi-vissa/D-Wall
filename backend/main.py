"""
D-WALL — Scam QR Code & Payment Link Analyzer
Backend: FastAPI + OpenCV + pyzbar + a trained phishing-URL model (scikit-learn)

Scoring
-------
Every link gets two independent scores (0-100):
  * ml_score   - the trained model's phishing probability x 100 (see ml/D-WALL_Model_Training.ipynb)
  * rule_score - D-WALL's expert rules (look-alike brands, redirects, credential forms, ...)
The final score is the HIGHER of the two: either detector can raise the alarm.
"""

from __future__ import annotations

import base64
import logging
import os
import re
import urllib.parse
from typing import Optional

import cv2
import numpy as np
import requests
from fastapi import FastAPI, File, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

try:
    from pyzbar import pyzbar
    HAS_PYZBAR = True
except Exception:  # ImportError, or missing zbar DLL on Windows
    HAS_PYZBAR = False

# Playwright is optional — will gracefully degrade if not available
try:
    from playwright.async_api import async_playwright, TimeoutError as PlaywrightTimeout
    HAS_PLAYWRIGHT = True
except Exception:
    HAS_PLAYWRIGHT = False

from ml.predictor import DEFAULT_MODEL_PATH, PhishingModel

log = logging.getLogger("dwall")

app = FastAPI(title="D-WALL API", version="2.0.0")

_origins = os.getenv("DWALL_CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in _origins.split(",") if o.strip()],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PAYMENT_BRANDS = [
    "npci", "paytm", "phonepe", "googlepay", "gpay", "bhim",
    "amazonpay", "mobikwik", "freecharge", "airtel",
]

SUSPICIOUS_KEYWORDS = [
    "refund", "verify", "claim", "urgent", "kyc", "reward",
    "winner", "prize", "cashback", "free", "lucky", "offer",
    "update", "suspended", "blocked", "expire", "alert",
]

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "short.link", "rb.gy", "buff.ly", "is.gd", "tiny.cc",
    "cutt.ly", "shorturl.at", "tiny.one", "snip.ly",
    "v.gd", "qr.ae", "shorte.st", "bit.do", "rebrand.ly", "t.ly",
}

MAX_REDIRECT_HOPS = 5
REQUEST_TIMEOUT = 5  # seconds
MAX_INPUT_LEN = 2048
MAX_BATCH = 1000
MAX_QR_BYTES = 5 * 1024 * 1024

SANDBOX_TIMEOUT = 8000  # milliseconds
SANDBOX_VIEWPORT = {"width": 1280, "height": 720}

CREDENTIAL_SELECTORS = [
    'input[type="password"]',
    'input[name*="pin" i]',
    'input[id*="pin" i]',
    'input[name*="password" i]',
    'input[id*="password" i]',
    'input[autocomplete="current-password"]',
    'input[autocomplete="new-password"]',
    'input[type="text"][name*="upi" i]',
    'input[type="text"][id*="upi" i]',
    'input[name*="otp" i]',
    'input[id*="otp" i]',
    'input[name*="mpin" i]',
    'input[id*="mpin" i]',
]

GSB_API_KEY = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "").strip()

# ---------------------------------------------------------------------------
# ML model (loaded once at start-up)
# ---------------------------------------------------------------------------

MODEL: Optional[PhishingModel] = None
MODEL_ERROR: Optional[str] = None
try:
    MODEL = PhishingModel.load(os.getenv("DWALL_MODEL_PATH", DEFAULT_MODEL_PATH))
except Exception as exc:  # missing file, version mismatch, ...
    MODEL_ERROR = f"{type(exc).__name__}: {exc}"
    log.warning("ML model not loaded (%s). Falling back to rules only.", MODEL_ERROR)


# ---------------------------------------------------------------------------
# Request models (input validation)
# ---------------------------------------------------------------------------

class LinkRequest(BaseModel):
    input: str = Field(..., min_length=1, max_length=MAX_INPUT_LEN, description="URL or UPI string")


class BatchRequest(BaseModel):
    urls: list[str] = Field(..., min_length=1, max_length=MAX_BATCH)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def levenshtein(a: str, b: str) -> int:
    """Standard Levenshtein edit distance."""
    if len(a) < len(b):
        a, b = b, a
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        curr = [i]
        for j, cb in enumerate(b, 1):
            curr.append(min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = curr
    return prev[-1]


def extract_domain(url: str) -> str:
    """Return just the hostname (lowercase, no www.)."""
    try:
        host = urllib.parse.urlparse(url).hostname or ""
        return host.lower().removeprefix("www.")
    except Exception:
        return ""


def ensure_scheme(raw: str) -> Optional[str]:
    """Add https:// to bare domains. Returns None if it doesn't look like a link."""
    if raw.lower().startswith(("http://", "https://")):
        return raw
    if re.match(r"^[\w.-]+\.[a-zA-Z]{2,}(?::\d+)?(?:[/?#].*)?$", raw) or re.match(r"^\d{1,3}(\.\d{1,3}){3}", raw):
        return "https://" + raw
    return None


def follow_redirects(url: str) -> list[str]:
    """Follow up to MAX_REDIRECT_HOPS redirects and return the chain of URLs."""
    chain = [url]
    session = requests.Session()
    session.max_redirects = MAX_REDIRECT_HOPS
    try:
        resp = session.head(
            url,
            allow_redirects=True,
            timeout=REQUEST_TIMEOUT,
            headers={"User-Agent": "Mozilla/5.0 (D-WALL/2.0 security scanner)"},
        )
        for r in resp.history:
            if r.url not in chain:
                chain.append(r.url)
        if resp.url not in chain:
            chain.append(resp.url)
    except requests.TooManyRedirects:
        chain.append("<too-many-redirects>")
    except Exception as exc:
        chain.append(f"<unreachable: {type(exc).__name__}>")
    return chain


def is_shortened_url(url: str) -> bool:
    return extract_domain(url) in SHORTENERS


def parse_upi(raw: str) -> Optional[dict]:
    """Parse a UPI deep-link (upi://pay?...) and return its parameters."""
    if not raw.lower().startswith("upi://"):
        return None
    parsed = urllib.parse.urlparse(raw)
    return dict(urllib.parse.parse_qsl(parsed.query))


def check_threat_feed(url: str) -> Optional[bool]:
    """Google Safe Browsing lookup. Returns None when no API key is configured or the call fails."""
    if not GSB_API_KEY:
        return None
    body = {
        "client": {"clientId": "d-wall", "clientVersion": app.version},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    try:
        r = requests.post(
            "https://safebrowsing.googleapis.com/v4/threatMatches:find",
            params={"key": GSB_API_KEY}, json=body, timeout=REQUEST_TIMEOUT,
        )
        r.raise_for_status()
        return bool(r.json().get("matches"))
    except Exception as exc:
        log.warning("Safe Browsing lookup failed: %s", exc)
        return None


async def run_landing_page_check(url: str) -> dict:
    """Use headless Playwright to look for password / PIN / OTP fields on the page."""
    if not HAS_PLAYWRIGHT or not url.startswith(("http://", "https://")):
        return {"has_creds": False, "screenshot_b64": None, "error": "Playwright not installed"}

    result = {"has_creds": False, "screenshot_b64": None, "error": None}
    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context(viewport=SANDBOX_VIEWPORT)
            page = await context.new_page()
            try:
                await page.goto(url, timeout=SANDBOX_TIMEOUT)
            except PlaywrightTimeout:
                result["error"] = "Timeout"
                await browser.close()
                return result
            for selector in CREDENTIAL_SELECTORS:
                if await page.query_selector(selector):
                    result["has_creds"] = True
                    break
            screenshot_bytes = await page.screenshot(type="png", full_page=False)
            result["screenshot_b64"] = base64.b64encode(screenshot_bytes).decode("utf-8")
            await browser.close()
    except Exception as e:
        result["error"] = str(e)
    return result


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

def rule_checks(url: str) -> tuple[int, list[str]]:
    """Offline expert rules on one URL (no network). Returns (points, reasons)."""
    score, reasons = 0, []
    domain = extract_domain(url)
    parsed = urllib.parse.urlparse(url)
    full_path = (parsed.path + "?" + parsed.query).lower()

    # Look-alike payment brand
    domain_base = domain.split(".")[0] if domain else ""
    if domain not in SHORTENERS:
        for brand in PAYMENT_BRANDS:
            dist = levenshtein(domain_base, brand)
            if 0 < dist <= 2 and abs(len(domain_base) - len(brand)) <= 2 and len(domain_base) >= 4:
                score += 30
                reasons.append(
                    f"Domain '{domain}' closely resembles payment brand '{brand}' "
                    f"(edit distance {dist}) — possible fake site."
                )
                break
            if brand in domain_base and domain_base != brand:
                score += 20
                reasons.append(f"Domain '{domain}' contains the payment brand name '{brand}' — common in scam links.")
                break

    found = [kw for kw in SUSPICIOUS_KEYWORDS if kw in full_path]
    if found:
        score += min(10 * len(found), 25)
        reasons.append(f"Scam keyword(s) in the link: {', '.join(found)}.")

    if url.startswith("http://"):
        score += 10
        reasons.append("Link uses unencrypted HTTP — your data is not protected.")

    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain):
        score += 20
        reasons.append("Link goes directly to an IP address — real payment sites don't do this.")

    if len(domain.split(".")) > 4:
        score += 10
        reasons.append(f"Unusually many subdomains in '{domain}' — a common disguise trick.")

    return score, reasons


def ml_check(url: str) -> dict:
    """Run the trained model on one URL."""
    if MODEL is None:
        return {"available": False, "error": MODEL_ERROR}
    prob = float(MODEL.predict_proba([url])[0])
    return {
        "available": True,
        "probability": round(prob, 4),
        "score": round(prob * 100),
        "reasons": MODEL.explain(url) if prob >= 0.31 else [],
        "model_version": MODEL.version,
    }


def verdict_for(score: int) -> tuple[str, str]:
    if score <= 30:
        return "Safe", "This link looks legitimate based on our checks."
    if score <= 70:
        return "Suspicious", "Proceed with caution — some red flags were detected."
    return "Dangerous", "Do NOT proceed — high probability of phishing or scam."


async def analyze(raw: str) -> dict:
    """Core analysis: accepts a URL, a UPI string, or any text decoded from a QR code."""
    reasons: list[str] = []
    rule_score = 0
    notes: list[str] = []
    redirect_chain: list[str] = [raw]
    landing_check = {"has_creds": False, "screenshot_b64": None, "error": None}
    ml = {"available": False}

    # ── UPI path ─────────────────────────────────────────────────────────────
    upi_params = parse_upi(raw)
    if upi_params is not None:
        vpa = upi_params.get("pa", "")
        amount_str = upi_params.get("am", "")
        if not vpa:
            rule_score += 25
            reasons.append("UPI link has no payee address (pa=…) — not a valid payment request.")
        elif not re.match(r"^[\w.\-]+@[\w]+$", vpa):
            rule_score += 25
            reasons.append(f"UPI ID '{vpa}' has an unusual format — may be fake.")
        try:
            amount = float(amount_str)
            if amount > 10_000:
                rule_score += 20
                reasons.append(f"UPI request is for ₹{amount:,.0f} — unusually high amount.")
            elif amount > 0:
                reasons.append(f"UPI amount requested: ₹{amount:,.0f}. Scanning a QR to *receive* money is a common scam — you never need to pay or enter a PIN to receive.")
        except (ValueError, TypeError):
            pass
        for kw in SUSPICIOUS_KEYWORDS:
            if kw in vpa.lower() or kw in upi_params.get("pn", "").lower():
                rule_score += 15
                reasons.append(f"UPI payee contains the scam keyword '{kw}'.")
                break
        notes.append("The ML model checks web links; UPI requests are checked with rules only.")
        upi = {"payee": vpa, "name": upi_params.get("pn"), "amount": amount_str or None,
               "currency": upi_params.get("cu", "INR"), "note": upi_params.get("tn")}
        return _build_result(rule_score, rule_score, ml, reasons, redirect_chain, raw, landing_check, notes, upi)

    # ── URL path ─────────────────────────────────────────────────────────────
    url = ensure_scheme(raw)
    if url is None:
        reasons.append("Input doesn't look like a web link or UPI string.")
        return _build_result(10, 10, ml, reasons, redirect_chain, raw, landing_check, notes)

    final_url = url
    if is_shortened_url(url):
        redirect_chain = follow_redirects(url)
        last_hop = redirect_chain[-1]
        if last_hop.startswith("<"):
            final_url = redirect_chain[-2] if len(redirect_chain) > 1 else url
            rule_score += 15
            reasons.append(f"Short link could not be opened ({last_hop.strip('<>')}), so its real destination is hidden.")
        else:
            final_url = last_hop
            reasons.append(f"Short link detected — it leads to {final_url} after {len(redirect_chain) - 1} hop(s).")
        hops = len(redirect_chain) - 1
        if hops >= 3:
            rule_score += 20
            reasons.append(f"Long redirect chain ({hops} hops) — often used to hide the destination.")
        elif hops == 2:
            rule_score += 10
            reasons.append("Two redirect hops found.")

    # Trained ML model on the final destination
    ml = ml_check(final_url)
    if ml.get("available"):
        reasons.extend(ml["reasons"])

    # Expert rules
    pts, why = rule_checks(final_url)
    rule_score += pts
    reasons.extend(why)

    # Optional: page check with a headless browser
    landing_check = await run_landing_page_check(final_url)
    if landing_check["has_creds"]:
        rule_score += 40
        reasons.append("The page asks for a UPI PIN, OTP or password — high risk of stealing your details.")
    elif landing_check["error"]:
        first_line = str(landing_check["error"]).splitlines()[0][:160]
        notes.append(f"Page check skipped: {first_line}.")

    # Optional: threat feed
    on_feed = check_threat_feed(final_url)
    if on_feed:
        rule_score += 60
        reasons.append("Google Safe Browsing lists this link as dangerous.")
    elif on_feed is None:
        notes.append("Threat-feed lookup is off (set GOOGLE_SAFE_BROWSING_API_KEY to enable it).")

    ml_score = ml.get("score", 0) if ml.get("available") else 0
    final = max(ml_score, rule_score)
    if not reasons:
        reasons.append("No red flags found by the model or the rules.")
    return _build_result(final, rule_score, ml, reasons, redirect_chain, final_url, landing_check, notes)


def _build_result(score, rule_score, ml, reasons, chain, final_url, landing_check, notes, upi=None) -> dict:
    score = int(max(0, min(100, score)))
    verdict, detail = verdict_for(score)
    if not ml.get("available") and ml.get("error"):
        notes.append("ML model not loaded — using rules only.")
    return {
        "score": score,
        "verdict": verdict,
        "verdict_detail": detail,
        "ml": ml,
        "rule_score": int(max(0, min(100, rule_score))),
        "reasons": reasons,
        "redirect_chain": chain,
        "final_url": final_url,
        "target": final_url,
        "upi": upi,
        "landing_page_check": landing_check,
        "notes": notes,
    }


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/health")
def health():
    return {"status": "ok", "model_loaded": MODEL is not None, "playwright": HAS_PLAYWRIGHT, "pyzbar": HAS_PYZBAR}


@app.get("/model/info")
def model_info():
    """Validation metrics of the loaded model (from the training notebook)."""
    if MODEL is None:
        raise HTTPException(status_code=503, detail=f"Model not loaded: {MODEL_ERROR}")
    return {"version": MODEL.version, "metrics": MODEL.metrics,
            "best_params": MODEL.bundle.get("best_params"), "trained_with_sklearn": MODEL.bundle.get("sklearn_version")}


@app.post("/analyze/link")
async def analyze_link(request: Request):
    """Analyze a URL or UPI string. Body: JSON {"input": "..."} (form field 'input'/'url' also accepted)."""
    if request.headers.get("content-type", "").startswith("application/json"):
        try:
            body = await request.json()
        except Exception:
            raise HTTPException(status_code=400, detail="Body is not valid JSON.")
        if not isinstance(body, dict):
            raise HTTPException(status_code=400, detail='Send a JSON object like {"input": "<link>"}.')
    else:
        body = dict(await request.form())
    raw = str(body.get("input") or body.get("link") or body.get("url") or "").strip()
    if not raw:
        raise HTTPException(status_code=400, detail="No input provided.")
    if len(raw) > MAX_INPUT_LEN:
        raise HTTPException(status_code=413, detail=f"Input is longer than {MAX_INPUT_LEN} characters.")
    return await analyze(LinkRequest(input=raw).input)


@app.post("/analyze/batch")
def analyze_batch(payload: BatchRequest):
    """Fast offline check of up to 1000 links at once (ML model + rules, no network calls)."""
    urls = [u.strip() for u in payload.urls]
    if any(len(u) > MAX_INPUT_LEN for u in urls):
        raise HTTPException(status_code=413, detail=f"Each URL must be at most {MAX_INPUT_LEN} characters.")
    probs = MODEL.predict_proba(urls) if MODEL is not None else np.zeros(len(urls))
    out = []
    for u, p in zip(urls, probs):
        full = ensure_scheme(u) or u
        rule_score, _ = rule_checks(full)
        ml_score = round(float(p) * 100) if MODEL is not None else 0
        score = int(min(100, max(ml_score, rule_score)))
        out.append({"url": u, "score": score, "verdict": verdict_for(score)[0],
                    "ml_probability": round(float(p), 4) if MODEL is not None else None, "rule_score": min(rule_score, 100)})
    return {"count": len(out), "model_loaded": MODEL is not None, "results": out}


@app.post("/analyze/qr")
async def analyze_qr(file: UploadFile = File(...)):
    """Decode an uploaded QR code image, then run the same analysis."""
    if not (file.content_type or "").startswith("image/"):
        raise HTTPException(status_code=400, detail="File must be an image.")
    contents = await file.read()
    if len(contents) > MAX_QR_BYTES:
        raise HTTPException(status_code=413, detail="Image is larger than 5 MB.")

    img = cv2.imdecode(np.frombuffer(contents, np.uint8), cv2.IMREAD_COLOR)
    if img is None:
        raise HTTPException(status_code=400, detail="Could not read the image — is it a valid image file?")

    raw = None
    if HAS_PYZBAR:
        decoded = pyzbar.decode(img)
        if decoded:
            raw = decoded[0].data.decode("utf-8", errors="replace").strip()
    if not raw:
        data, _, _ = cv2.QRCodeDetector().detectAndDecode(img)
        raw = (data or "").strip()
    if not raw:
        raise HTTPException(status_code=422, detail="No QR code found in the image. Make sure it is clear and well-lit.")

    result = await analyze(raw[:MAX_INPUT_LEN])
    result["decoded_text"] = raw
    return result

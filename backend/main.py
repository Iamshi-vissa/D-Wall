"""
X-Wall — Scam QR Code & Payment Link Analyzer
Backend: FastAPI + OpenCV + pyzbar
"""

import asyncio
import base64
import re
import urllib.parse
from typing import Optional

import cv2
import numpy as np
import requests
from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware

try:
    from pyzbar import pyzbar
    HAS_PYZBAR = True
except ImportError:
    HAS_PYZBAR = False
except Exception:
    # On Windows, pyzbar often crashes during import due to missing DLLs
    HAS_PYZBAR = False

# Playwright is optional — will gracefully degrade if not available
try:
    from playwright.async_api import async_playwright, TimeoutError as PlaywrightTimeout
    HAS_PLAYWRIGHT = True
except ImportError:
    HAS_PLAYWRIGHT = False
except Exception:
    HAS_PLAYWRIGHT = False

app = FastAPI(title="X-Wall API", version="0.1.0")

# Allow the Vite dev server to talk to us
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
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

MAX_REDIRECT_HOPS = 5
REQUEST_TIMEOUT = 5  # seconds

# Landing page sandbox settings
SANDBOX_TIMEOUT = 8000  # milliseconds (8s)
SANDBOX_VIEWPORT = {"width": 1280, "height": 720}

# Selectors for credential harvesting indicators
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
    'input[name*="m pin" i]',
    'input[id*="m pin" i]',
    'input[name*="mpin" i]',
    'input[id*="mpin" i]',
]


# ---------------------------------------------------------------------------
# STUB: Domain-age lookup
# In production, replace with WHOIS / DomainTools / SecurityTrails API call.
# ---------------------------------------------------------------------------

def stub_domain_age_days(domain: str) -> int:
    """
    STUB — returns a fake but plausible domain age.
    Real implementation: query WHOIS / SecurityTrails and parse creation date.
    """
    # Deterministic fake age based on domain length so results are consistent
    seed = sum(ord(c) for c in domain) % 365
    return seed + 1  # 1..365 days


# ---------------------------------------------------------------------------
# STUB: Threat-feed lookup
# In production, replace with VirusTotal / Google Safe Browsing / PhishTank.
# ---------------------------------------------------------------------------

def stub_threat_feed(url: str) -> bool:
    """
    STUB — always returns False (not on threat feed).
    Real implementation: hit VirusTotal /urls or Google Safe Browsing API.
    """
    return False


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
        host = urllib.parse.urlparse(url).netloc
        return host.lower().lstrip("www.").split(":")[0]
    except Exception:
        return ""


def follow_redirects(url: str) -> list[str]:
    """
    Follow up to MAX_REDIRECT_HOPS redirects and return the chain of URLs.
    Does NOT raise on HTTP errors — captures them for scoring.
    """
    chain = [url]
    session = requests.Session()
    session.max_redirects = MAX_REDIRECT_HOPS
    try:
        resp = session.head(
            url,
            allow_redirects=True,
            timeout=REQUEST_TIMEOUT,
            headers={"User-Agent": "Mozilla/5.0 (X-Wall/0.1 security scanner)"},
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
    """Check if domain is a known URL shortener."""
    shorteners = {
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
        "short.link", "rb.gy", "buff.ly", "is.gd", "tiny.cc",
        "cutt.ly", "shorturl.at", "tiny.one", "snip.ly",
        "v.gd", "qr.ae", "shorte.st", "is.gd", "bit.do",
    }
    domain = extract_domain(url)
    if domain in shorteners:
        return True
    return False


def parse_upi(raw: str) -> Optional[dict]:
    """
    Parse a UPI deep-link (upi://pay?...) and return its parameters.
    Returns None if the input isn't a UPI string.
    """
    if not raw.lower().startswith("upi://"):
        return None
    parsed = urllib.parse.urlparse(raw)
    params = dict(urllib.parse.parse_qsl(parsed.query))
    return params


async def run_landing_page_check(url: str) -> dict:
    """
    Use Headless Playwright to check for credential harvesting inputs.
    Returns: { "has_creds": bool, "screenshot_b64": str, "error": str }
    """
    if not HAS_PLAYWRIGHT or not url.startswith(("http://", "https://")):
        return {"has_creds": False, "screenshot_b64": None, "error": "Playwright unavailable or not a web URL"}

    result = {"has_creds": False, "screenshot_b64": None, "error": None}
    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context(viewport=SANDBOX_VIEWPORT)
            page = await context.new_page()

            # Navigate with timeout
            try:
                await page.goto(url, timeout=SANDBOX_TIMEOUT)
            except PlaywrightTimeout:
                result["error"] = "Timeout"
                await browser.close()
                return result

            # Check for credential fields
            for selector in CREDENTIAL_SELECTORS:
                if await page.query_selector(selector):
                    result["has_creds"] = True
                    break

            # Take screenshot
            screenshot_bytes = await page.screenshot(type="png", full_page=False)
            result["screenshot_b64"] = base64.b64encode(screenshot_bytes).decode("utf-8")

            await browser.close()
    except Exception as e:
        result["error"] = str(e)
    return result

# ---------------------------------------------------------------------------
# Scoring engine
# ---------------------------------------------------------------------------

async def analyze(raw: str) -> dict:
    """
    Core analysis function.  Accepts a raw URL, UPI string, or any text
    decoded from a QR code.  Returns a structured result dict.
    """
    reasons: list[str] = []
    score = 0
    redirect_chain: list[str] = [raw]
    final_url = raw
    landing_check = {"has_creds": False, "screenshot_b64": None, "error": None}

    # ── UPI path ─────────────────────────────────────────────────────────────
    upi_params = parse_upi(raw)
    if upi_params:
        vpa: str = upi_params.get("pa", "")
        amount_str: str = upi_params.get("am", "")

        # VPA format check: should be something@bankhandle
        if vpa and not re.match(r"^[\w.\-]+@[\w]+$", vpa):
            score += 25
            reasons.append(f"UPI VPA '{vpa}' has an unusual format — may be fake.")

        # Suspicious amount
        try:
            amount = float(amount_str)
            if amount > 10_000:
                score += 20
                reasons.append(f"UPI request is for ₹{amount:,.0f} — unusually high amount.")
            elif amount > 0:
                reasons.append(f"UPI amount requested: ₹{amount:,.0f}.")
        except (ValueError, TypeError):
            pass

        # Keyword scan on VPA
        for kw in SUSPICIOUS_KEYWORDS:
            if kw in vpa.lower():
                score += 15
                reasons.append(f"UPI VPA contains suspicious keyword '{kw}'.")
                break

        return _build_result(score, reasons, redirect_chain, final_url, landing_check)

    # ── URL path ─────────────────────────────────────────────────────────────
    # Ensure it looks like a URL; prepend https:// if missing so urlparse works
    if not raw.lower().startswith(("http://", "https://")):
        if "." in raw:
            raw = "https://" + raw
        else:
            reasons.append("Input doesn't look like a URL or UPI string.")
            return _build_result(min(score + 10, 100), reasons, redirect_chain, raw, landing_check)

    final_url = raw

    # Follow redirects if shortened
    if is_shortened_url(raw):
        redirect_chain = follow_redirects(raw)
        last_hop = redirect_chain[-1]
        if last_hop.startswith("<"):
            # An error occurred during redirection
            final_url = redirect_chain[-2] if len(redirect_chain) > 1 else raw
            reasons.append(f"Shortened URL failed to resolve: {last_hop.strip('<>')}")
        else:
            final_url = last_hop
            reasons.append(f"Shortened URL detected — resolves via {len(redirect_chain) - 1} hop(s).")

    # Landing page check (async)
    landing_check = await run_landing_page_check(final_url)
    if landing_check["has_creds"]:
        score += 40
        reasons.append("Asks for a UPI PIN or password on the page — high credential harvesting risk.")
    elif landing_check["error"]:
        reasons.append(f"Landing page check unavailable: {landing_check['error']}.")

    # Redirect chain length penalty
    hops = len(redirect_chain) - 1
    if hops >= 3:
        score += 20
        reasons.append(f"Long redirect chain ({hops} hops) — often used to obscure destination.")
    elif hops == 2:
        score += 10
        reasons.append(f"Two redirect hops found.")

    # Work with the final destination URL from here on
    url_lower = final_url.lower()
    domain = extract_domain(final_url)
    parsed = urllib.parse.urlparse(final_url)
    full_path = (parsed.path + "?" + parsed.query).lower()

    # ── Domain age check (STUB) ───────────────────────────────────────────────
    age_days = stub_domain_age_days(domain)   # STUB
    if age_days < 7:
        score += 35
        reasons.append(f"[STUB] Domain '{domain}' appears to be only {age_days} day(s) old — very new domains are a red flag.")
    elif age_days < 30:
        score += 20
        reasons.append(f"[STUB] Domain '{domain}' registered ~{age_days} days ago — recently registered domains are suspicious.")
    elif age_days < 90:
        score += 10
        reasons.append(f"[STUB] Domain '{domain}' is ~{age_days} days old — moderately new.")

    # ── Look-alike domain check ───────────────────────────────────────────────
    domain_base = re.split(r"\.", domain)[0]
    # Exclude known shortener domains from lookalike detection
    _shortener_domains = {
        "bit", "tinyurl", "goo", "ow", "rb", "buff", "is",
        "tiny", "cutt", "shorturl", "snip", "qr", "shorte",
    }
    _skip_lookalike = domain_base in _shortener_domains
    for brand in PAYMENT_BRANDS:
        dist = levenshtein(domain_base, brand)
        # Same length ±2 and distance ≤2 but not identical = look-alike
        if 0 < dist <= 2 and abs(len(domain_base) - len(brand)) <= 2 and not _skip_lookalike:
            score += 30
            reasons.append(
                f"Domain '{domain}' closely resembles known payment brand '{brand}' "
                f"(edit distance {dist}) — possible phishing domain."
            )
            break
        # Brand name appears as a substring of a longer domain (e.g. paytm-refund.com)
        if brand in domain_base and domain_base != brand:
            score += 20
            reasons.append(
                f"Domain '{domain}' contains payment brand name '{brand}' — "
                "commonly used in phishing links."
            )
            break

    # ── Suspicious keyword scan ───────────────────────────────────────────────
    found_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in full_path]
    if found_keywords:
        score += min(10 * len(found_keywords), 25)
        reasons.append(
            f"Suspicious keyword(s) in URL: {', '.join(found_keywords)}."
        )

    # ── HTTP vs HTTPS ─────────────────────────────────────────────────────────
    if final_url.startswith("http://"):
        score += 10
        reasons.append("Link uses unencrypted HTTP — your data is not protected.")

    # ── Threat feed check (STUB) ──────────────────────────────────────────────
    on_feed = stub_threat_feed(final_url)   # STUB
    if on_feed:
        score += 40
        reasons.append("[STUB] URL found on threat feed (VirusTotal / PhishTank).")

    # ── IP address instead of domain ─────────────────────────────────────────
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain):
        score += 20
        reasons.append("Link goes directly to an IP address — legitimate payment sites don't do this.")

    # ── Excessive subdomains ──────────────────────────────────────────────────
    parts = domain.split(".")
    if len(parts) > 4:
        score += 10
        reasons.append(f"Unusually many subdomains in '{domain}' — a common obfuscation trick.")

    if not reasons:
        reasons.append("No obvious red flags detected.")

    return _build_result(score, reasons, redirect_chain, final_url, landing_check)


def _build_result(score: int, reasons: list[str], chain: list[str], final_url: str, landing_check: dict) -> dict:
    score = max(0, min(100, score))
    if score <= 30:
        verdict = "Safe"
        verdict_detail = "This link looks legitimate based on our checks."
    elif score <= 70:
        verdict = "Suspicious"
        verdict_detail = "Proceed with caution — some red flags were detected."
    else:
        verdict = "Dangerous"
        verdict_detail = "Do NOT proceed — high probability of phishing or scam."

    return {
        "score": score,
        "verdict": verdict,
        "verdict_detail": verdict_detail,
        "reasons": reasons,
        "redirect_chain": chain,
        "final_url": final_url,
        "landing_page_check": landing_check,
        "stubs_active": [
            "domain_age (replace with WHOIS/SecurityTrails API)",
            "threat_feed (replace with VirusTotal/Google Safe Browsing API)",
        ],
    }



# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/analyze/link")
async def analyze_link(payload: dict):
    """Analyze a URL or UPI string submitted as JSON."""
    raw = payload.get("input") or payload.get("link") or ""
    raw = raw.strip()
    if not raw:
        raise HTTPException(status_code=400, detail="No input provided.")
    result = await analyze(raw)
    return result


@app.post("/analyze/qr")
async def analyze_qr(file: UploadFile = File(...)):
    """
    Accept an uploaded QR code image, decode it with OpenCV + pyzbar,
    then run the same analysis pipeline.
    """
    if not file.content_type.startswith("image/"):
        raise HTTPException(status_code=400, detail="File must be an image.")

    contents = await file.read()
    nparr = np.frombuffer(contents, np.uint8)
    img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)

    if img is None:
        raise HTTPException(status_code=400, detail="Could not decode image — is it a valid image file?")

    # Try pyzbar first (faster, more reliable for clean QR codes)
    decoded = None
    if HAS_PYZBAR:
        decoded = pyzbar.decode(img)

    # If pyzbar fails, try OpenCV's built-in QR detector as fallback
    if not decoded:
        detector = cv2.QRCodeDetector()
        data, _, _ = detector.detectAndDecode(img)
        if data:
            raw = data.strip()
        else:
            raise HTTPException(
                status_code=422,
                detail="No QR code found in the image. Make sure the image is clear and well-lit.",
            )
    else:
        raw = decoded[0].data.decode("utf-8", errors="replace").strip()

    result = await analyze(raw)
    result["decoded_text"] = raw  # Surface what was inside the QR
    return result

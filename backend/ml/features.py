"""
URL feature extraction for the D-WALL phishing model.

Every feature is computed from the URL text only, so nothing is downloaded.
That makes it fast (tens of thousands of URLs per second) and safe to run
on links you don't trust.

The SAME function is used for training (in the notebook) and in the API,
so the model always sees features built the same way.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from urllib.parse import urlsplit

import numpy as np
import pandas as pd

SUSPICIOUS_WORDS = [
    "login", "signin", "verify", "secure", "account", "update", "bank",
    "confirm", "password", "webscr", "ebayisapi", "wallet", "billing",
    "support", "suspend", "unlock", "kyc", "refund", "reward", "claim",
    "free", "bonus", "gift", "admin", "auth", "session",
]

BRANDS = [
    "paypal", "apple", "icloud", "microsoft", "office", "outlook", "google",
    "facebook", "instagram", "whatsapp", "amazon", "netflix", "dropbox",
    "chase", "wellsfargo", "bankofamerica", "dhl", "fedex", "ebay", "yahoo",
    "paytm", "phonepe", "gpay", "bhim", "npci", "sbi", "hdfc", "icici",
    "axis", "kotak", "airtel", "jio", "flipkart",
]

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "rb.gy", "buff.ly",
    "is.gd", "tiny.cc", "cutt.ly", "shorturl.at", "tiny.one", "snip.ly",
    "v.gd", "qr.ae", "shorte.st", "bit.do", "rebrand.ly", "t.ly",
}

# TLDs that are cheap/free and heavily abused in phishing reports
RISKY_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "club", "online", "site",
    "info", "buzz", "live", "icu", "work", "click", "link", "rest", "fit",
    "ru", "cn", "su", "pw", "cc", "ws", "shop", "store", "vip",
}

FREE_HOSTS = [
    "000webhostapp", "weebly", "wix", "blogspot", "firebaseapp", "web.app",
    "github.io", "netlify", "vercel.app", "herokuapp", "glitch.me",
    "sites.google", "duckdns", "ngrok", "repl.co", "pages.dev", "workers.dev",
]

_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_HEX_RE = re.compile(r"[0-9a-f]{16,}")

FEATURE_NAMES = [
    "url_len", "host_len", "path_len", "query_len",
    "n_dots", "n_hyphens", "n_underscores", "n_slashes", "n_at", "n_qmark",
    "n_equals", "n_amp", "n_percent", "n_tilde", "n_digits_url",
    "digit_ratio_url", "digit_ratio_host", "upper_ratio_path",
    "n_subdomains", "host_has_hyphen", "host_is_ip", "has_port",
    "host_entropy", "path_entropy", "tld_len", "tld_risky",
    "path_depth", "longest_token", "n_tokens_host", "max_host_token_len",
    "has_double_slash_in_path", "has_hex_string", "file_php", "file_html",
    "file_exe_zip", "n_sus_words", "brand_in_host_not_domain",
    "brand_in_path", "is_shortener", "free_host", "has_email_in_url",
    "vowel_ratio_host", "max_consonant_run_host", "n_params",
]


def normalize_url(url: str) -> str:
    """Lower-case scheme/host, drop the scheme and a leading 'www.'.

    The training data mostly has no scheme, so we remove it everywhere.
    That stops the model from learning "has https" as a shortcut that would
    not hold in the real world.
    """
    url = str(url).strip()
    url = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", url)
    if url.lower().startswith("www."):
        url = url[4:]
    return url


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def _split(url: str) -> tuple[str, str, str, int | None]:
    """Return host, path, query, port from a scheme-less URL."""
    try:
        parts = urlsplit("http://" + url)
        host = (parts.hostname or "").lower()
        try:
            port = parts.port
        except ValueError:
            port = -1
        return host, parts.path or "", parts.query or "", port
    except ValueError:
        # Badly formed URL: treat everything before the first "/" as host
        host, _, rest = url.partition("/")
        return host.lower(), "/" + rest, "", None


def _max_consonant_run(s: str) -> int:
    best = run = 0
    for ch in s:
        if ch.isalpha() and ch not in "aeiou":
            run += 1
            best = max(best, run)
        else:
            run = 0
    return best


def extract_features(url: str) -> list[float]:
    """Turn one URL into a fixed-length list of numbers (see FEATURE_NAMES)."""
    u = normalize_url(url)
    host, path, query, port = _split(u)
    lower = u.lower()
    host_parts = [p for p in host.split(".") if p]
    tld = host_parts[-1] if host_parts else ""
    registered = ".".join(host_parts[-2:]) if len(host_parts) >= 2 else host
    sub = ".".join(host_parts[:-2])
    tokens = [t for t in re.split(r"[/\.\-_?=&]", lower) if t]
    host_alpha = [c for c in host if c.isalpha()]
    path_letters = [c for c in path if c.isalpha()]
    n = max(len(u), 1)

    brand_in_host_not_domain = int(
        any(b in sub or (b in registered and registered.split(".")[0] != b) for b in BRANDS)
    )
    brand_in_path = int(any(b in (path + query).lower() for b in BRANDS))

    return [
        len(u),
        len(host),
        len(path),
        len(query),
        u.count("."),
        u.count("-"),
        u.count("_"),
        u.count("/"),
        u.count("@"),
        u.count("?"),
        u.count("="),
        u.count("&"),
        u.count("%"),
        u.count("~"),
        sum(c.isdigit() for c in u),
        sum(c.isdigit() for c in u) / n,
        sum(c.isdigit() for c in host) / max(len(host), 1),
        sum(c.isupper() for c in path_letters) / max(len(path_letters), 1),
        max(len(host_parts) - 2, 0),
        int("-" in host),
        int(bool(_IP_RE.match(host))),
        int(port not in (None, 80, 443)),
        _entropy(host),
        _entropy(path),
        len(tld),
        int(tld in RISKY_TLDS),
        len([p for p in path.split("/") if p]),
        max((len(t) for t in tokens), default=0),
        len(host_parts),
        max((len(p) for p in host_parts), default=0),
        int("//" in path),
        int(bool(_HEX_RE.search(lower))),
        int(".php" in path.lower()),
        int(bool(re.search(r"\.html?$", path.lower()))),
        int(bool(re.search(r"\.(exe|zip|rar|apk|scr|js)$", path.lower()))),
        sum(w in lower for w in SUSPICIOUS_WORDS),
        brand_in_host_not_domain,
        brand_in_path,
        int(host in SHORTENERS),
        int(any(f in host for f in FREE_HOSTS)),
        int(bool(re.search(r"[\w.]+@[\w-]+\.[a-z]{2,}", lower))),
        sum(c in "aeiou" for c in host_alpha) / max(len(host_alpha), 1),
        _max_consonant_run(host.split(".")[0] if host else ""),
        len([p for p in query.split("&") if p]),
    ]


def featurize(urls) -> pd.DataFrame:
    """Build the feature table for many URLs at once."""
    rows = [extract_features(u) for u in urls]
    return pd.DataFrame(np.asarray(rows, dtype=np.float32), columns=FEATURE_NAMES)

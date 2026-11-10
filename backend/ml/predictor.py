"""
Loads the trained D-WALL phishing model and scores URLs.

The model is a two-level (stacked) ensemble:
  1. Text model: TF-IDF on character 3-5 grams + Logistic Regression.
     It learns which spelling patterns appear in phishing links.
  2. Final model: Histogram Gradient Boosting on 44 hand-made URL features
     plus the text model's score.

Usage:
    from ml.predictor import PhishingModel
    model = PhishingModel.load()
    model.predict_proba(["paytm-kyc-refund.xyz/claim.php"])  # -> array([0.98])
    model.explain("paytm-kyc-refund.xyz/claim.php")          # -> list of reasons
"""

from __future__ import annotations

from pathlib import Path

import joblib
import numpy as np

from .features import FEATURE_NAMES, featurize, normalize_url

DEFAULT_MODEL_PATH = Path(__file__).with_name("dwall_model.joblib")

# Plain-English text for the features we can explain to a user.
# "flag" features: any value above 0 is a warning sign.
# "high" features: only a warning when the value is higher than 99% of safe URLs.
_FLAG_TEXT = {
    "host_is_ip": "The link uses a raw IP address instead of a domain name.",
    "tld_risky": "The domain ending (TLD) is one that is cheap and often abused by scammers.",
    "free_host": "The site is on a free hosting service, which scammers use to set up pages quickly.",
    "brand_in_host_not_domain": "A brand name appears in the address, but the site is not that brand's real domain.",
    "has_email_in_url": "The link contains an email address, a common trick in phishing links.",
    "has_double_slash_in_path": "The path has a hidden '//' redirect pattern.",
    "file_exe_zip": "The link points to a downloadable file (.exe, .zip, .apk, ...).",
    "is_shortener": "This is a short link, so the real destination is hidden.",
    "has_port": "The link uses an unusual network port.",
}
_HIGH_TEXT = {
    "url_len": "The link is unusually long ({v:.0f} characters).",
    "n_subdomains": "The address has an unusual number of subdomains ({v:.0f}).",
    "host_entropy": "The domain name is unusually long or random-looking.",
    "n_hyphens": "The link has many hyphens ({v:.0f}).",
    "path_depth": "The link goes unusually deep into folders ({v:.0f} levels).",
    "n_sus_words": "The link uses {v:.0f} words that are common in scams (login, verify, kyc, refund, ...).",
    "digit_ratio_host": "The domain name is full of numbers.",
    "max_consonant_run_host": "The domain name has long runs of random letters.",
}


class PhishingModel:
    def __init__(self, bundle: dict):
        self.bundle = bundle
        self.tfidf = bundle["tfidf"]
        self.text_model = bundle["text_model"]
        self.final_model = bundle["final_model"]
        self.benign_p99 = bundle["benign_p99"]
        self.metrics = bundle.get("metrics", {})
        self.version = bundle.get("version", "unknown")
        if list(bundle["feature_names"]) != FEATURE_NAMES:
            raise ValueError(
                "The saved model was trained with a different feature list. "
                "Re-run the training notebook."
            )

    @classmethod
    def load(cls, path: str | Path = DEFAULT_MODEL_PATH) -> "PhishingModel":
        return cls(joblib.load(path))

    def _features(self, urls):
        norm = [normalize_url(u) for u in urls]
        X = featurize(norm)
        text_score = self.text_model.predict_proba(self.tfidf.transform(norm))[:, 1]
        X["text_score"] = text_score.astype(np.float32)
        return X

    def predict_proba(self, urls) -> np.ndarray:
        """Probability (0-1) that each URL is phishing."""
        if isinstance(urls, str):
            urls = [urls]
        if len(urls) == 0:
            return np.array([])
        return self.final_model.predict_proba(self._features(urls))[:, 1]

    def explain(self, url: str, max_reasons: int = 4) -> list[str]:
        """Short, human-readable reasons behind the score for one URL."""
        X = self._features([url])
        row = X.iloc[0]
        reasons = []
        for name, text in _FLAG_TEXT.items():
            if row[name] > 0:
                reasons.append(text)
        for name, text in _HIGH_TEXT.items():
            if row[name] > self.benign_p99.get(name, np.inf):
                reasons.append(text.format(v=row[name]))
        if row["text_score"] >= 0.7:
            reasons.append(
                f"Its spelling patterns closely match known phishing links "
                f"(text model: {row['text_score']:.0%})."
            )
        return reasons[:max_reasons]

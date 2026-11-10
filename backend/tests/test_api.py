import pytest
from fastapi.testclient import TestClient

import main

client = TestClient(main.app)
needs_model = pytest.mark.skipif(main.MODEL is None, reason="model file not present")


def test_health():
    r = client.get("/health")
    assert r.status_code == 200 and r.json()["status"] == "ok"


def test_empty_and_too_long_input_rejected():
    assert client.post("/analyze/link", json={"input": "  "}).status_code == 400
    assert client.post("/analyze/link", json={"input": "a.com/" + "x" * 3000}).status_code == 413
    assert client.post("/analyze/link", json=["not", "an", "object"]).status_code == 400


def test_form_body_still_accepted():
    r = client.post("/analyze/link", data={"url": "example.com"})
    assert r.status_code == 200


@needs_model
def test_safe_and_phishing_links():
    safe = client.post("/analyze/link", json={"input": "https://www.google.com"}).json()
    bad = client.post("/analyze/link", json={"input": "http://paytrn-kyc-refund.xyz/claim.php"}).json()
    assert safe["verdict"] == "Safe" and safe["ml"]["available"]
    assert bad["verdict"] == "Dangerous" and bad["score"] > safe["score"]
    assert bad["target"].endswith("claim.php")


def test_upi_request():
    r = client.post("/analyze/link", json={"input": "upi://pay?pa=refund.kyc@okaxis&pn=Refund&am=25000"}).json()
    assert r["upi"]["payee"] == "refund.kyc@okaxis"
    assert r["verdict"] in {"Suspicious", "Dangerous"}


@needs_model
def test_batch():
    urls = ["google.com", "http://192.168.1.4/hdfc/login.php", "github.com/Iamshi-vissa/D-Wall"]
    r = client.post("/analyze/batch", json={"urls": urls})
    assert r.status_code == 200
    out = {x["url"]: x for x in r.json()["results"]}
    assert out["google.com"]["verdict"] == "Safe"
    assert out["http://192.168.1.4/hdfc/login.php"]["score"] > 70


def test_batch_limits():
    assert client.post("/analyze/batch", json={"urls": []}).status_code == 422
    assert client.post("/analyze/batch", json={"urls": ["a.com"] * 1001}).status_code == 422


@needs_model
def test_model_info():
    m = client.get("/model/info").json()["metrics"]
    assert m["test_f1"] > 0.85

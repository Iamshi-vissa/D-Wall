from ml.features import FEATURE_NAMES, extract_features, featurize, normalize_url


def test_normalize_strips_scheme_and_www():
    assert normalize_url("HTTPS://www.Example.com/a") == "Example.com/a"
    assert normalize_url("http://paytm.com") == "paytm.com"


def test_feature_vector_length_matches_names():
    assert len(extract_features("paytm-kyc.xyz/login.php?id=1")) == len(FEATURE_NAMES)


def test_obvious_signals():
    f = dict(zip(FEATURE_NAMES, extract_features("http://192.168.0.7/sbi/login.php")))
    assert f["host_is_ip"] == 1 and f["file_php"] == 1 and f["n_sus_words"] >= 1
    f = dict(zip(FEATURE_NAMES, extract_features("paytm.verify-account.tk/claim")))
    assert f["tld_risky"] == 1 and f["brand_in_host_not_domain"] == 1


def test_malformed_urls_do_not_crash():
    df = featurize(["", "http://[::1", "a" * 3000, "upi://pay?pa=x@y", "ftp://user:pass@host:99999/x"])
    assert df.shape == (5, len(FEATURE_NAMES))

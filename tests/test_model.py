"""Tests that need the trained model files (skipped if models/ is empty)."""
from pathlib import Path

import pytest

MODELS = Path(__file__).resolve().parent.parent / "models"
pytestmark = pytest.mark.skipif(
    not all((MODELS / f).exists() for f in ("tfidf.pkl", "classifier.pkl", "label_encoder.pkl")),
    reason="trained model files not found in models/")


@pytest.fixture(scope="module")
def clf():
    from src.classifier import PromptClassifier
    return PromptClassifier()


@pytest.fixture(scope="module")
def gateway():
    from src.gateway import DataLeakGateway
    return DataLeakGateway()


def test_prediction_has_expected_shape(clf):
    out = clf.predict("Explain how machine learning works.")
    assert {"label", "confidence", "probabilities"} <= set(out)
    assert abs(sum(out["probabilities"].values()) - 1.0) < 1e-6
    assert 0.0 <= out["confidence"] <= 1.0


def test_plain_question_is_safe(clf):
    assert clf.predict("Explain how machine learning works.")["label"] == "safe"


def test_all_six_classes_are_known(clf):
    assert set(clf.le.classes_) == {"safe", "pii", "financial", "credential", "source_code", "confidential"}


# ----------------------------------------------------- full pipeline demos
def test_demo_safe_is_allowed(gateway):
    assert gateway.analyze("Explain how machine learning works.")["action"] == "ALLOW"


def test_demo_pii_is_redacted(gateway):
    r = gateway.analyze("Analyze Ahmed Khan's CNIC 35202-1234567-1 and phone 0300-1234567.")
    assert r["action"] == "REDACT"
    assert "35202-1234567-1" not in r["forward_prompt"]
    assert "0300-1234567" not in r["forward_prompt"]


def test_demo_api_key_is_blocked(gateway):
    r = gateway.analyze("Debug my application using this API key AKIAIOSFODNN7EXAMPLE")
    assert r["action"] == "BLOCK" and r["forward_prompt"] is None


def test_demo_source_code_is_blocked(gateway):
    r = gateway.analyze("Analyze our confidential authentication source code and find vulnerabilities.")
    assert r["action"] == "BLOCK"


def test_lone_email_is_warned_or_stricter(gateway):
    assert gateway.analyze("Please email me at test@gmail.com")["action"] in ("WARN", "REDACT")


def test_blocked_request_never_forwards_original_text(gateway):
    r = gateway.analyze("password: Adm1n@2026 and the server 10.1.2.3")
    assert r["action"] == "BLOCK"
    assert r["forward_prompt"] is None

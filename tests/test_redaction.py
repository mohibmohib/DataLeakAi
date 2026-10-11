"""Tests for the redaction engine."""
from src.secret_detector import detect_secrets
from src.pii_detector import detect_pii
from src.redactor import redact, merge_entities


def run(text):
    return redact(text, merge_entities(detect_secrets(text) + detect_pii(text)))


def test_cnic_and_phone_are_replaced():
    out = run("Analyze Ahmed Khan's CNIC 35202-1234567-1 and phone 0300-1234567.")
    assert "[CNIC_REDACTED]" in out and "[PHONE_REDACTED]" in out
    assert "35202-1234567-1" not in out and "0300-1234567" not in out


def test_surrounding_text_is_preserved():
    out = run("Please email me at test@gmail.com tomorrow")
    assert out == "Please email me at [EMAIL_REDACTED] tomorrow"


def test_card_redaction_keeps_following_space():
    assert run("card 4111 1111 1111 1111 exp 09/28") == "card [CARD_REDACTED] exp 09/28"


def test_password_value_is_hidden_but_key_name_stays():
    out = run("DB_PASSWORD=Pr0dS3cret!2026 in my .env")
    assert out.startswith("DB_PASSWORD=")
    assert "Pr0dS3cret" not in out
    assert "[CREDENTIAL_REDACTED]" in out


def test_aws_key_is_removed():
    assert "AKIAIOSFODNN7EXAMPLE" not in run("use AKIAIOSFODNN7EXAMPLE now")


def test_confidential_marking_word_is_kept():
    out = run("Summarize this confidential report")
    assert "confidential" in out


def test_multiple_items_in_one_prompt():
    out = run("Send to a@b.com or call 0300-1234567 or 0321-7654321")
    assert out.count("[PHONE_REDACTED]") == 2
    assert "[EMAIL_REDACTED]" in out


def test_text_without_sensitive_data_is_unchanged():
    text = "Explain how machine learning works."
    assert run(text) == text


def test_merge_keeps_highest_severity_on_overlap():
    a = {"type": "A", "category": "x", "start": 0, "end": 10, "severity": 30}
    b = {"type": "B", "category": "x", "start": 5, "end": 15, "severity": 80}
    c = {"type": "C", "category": "x", "start": 20, "end": 25, "severity": 10}
    merged = merge_entities([a, b, c])
    assert [e["type"] for e in merged] == ["B", "C"]

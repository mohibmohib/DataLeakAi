"""Tests for the deterministic detectors (secrets and PII)."""
import pytest

from src.secret_detector import detect_secrets
from src.pii_detector import detect_pii, luhn_ok


def types(entities):
    return [e["type"] for e in entities]


# ---------------------------------------------------------------- secrets
@pytest.mark.parametrize("text, expected", [
    ("key AKIAIOSFODNN7EXAMPLE here", "AWS_ACCESS_KEY"),
    ("-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----", "PRIVATE_KEY"),
    ("token eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", "JWT"),
    ("curl -H 'Authorization: Bearer abcdefghijklmnopqrstuvwxyz123456'", "BEARER_TOKEN"),
    ("mongodb://admin:Sup3rS3cret@10.0.0.5:27017/prod", "DB_CONNECTION"),
    ("DB_PASSWORD=Pr0dS3cret!2026 in my .env", "PASSWORD_ASSIGNMENT"),
    ("password: Adm1n@2026", "PASSWORD_ASSIGNMENT"),
    ("api_key = 'sk_live_51HxYz9AbCdEfGhIjKlMn'", "SECRET_ASSIGNMENT"),
    ("ghp_" + "a" * 36, "GITHUB_TOKEN"),
])
def test_secret_is_detected(text, expected):
    assert expected in types(detect_secrets(text))


@pytest.mark.parametrize("text", [
    "Explain how machine learning works.",
    "How do I reset a forgotten password?",
    "What is an API key and why should I keep it secret?",
    "Write a Python function that checks whether a number is prime.",
])
def test_no_secret_in_normal_text(text):
    assert detect_secrets(text) == []


def test_secret_entities_have_required_fields():
    e = detect_secrets("AKIAIOSFODNN7EXAMPLE")[0]
    assert {"type", "category", "start", "end", "severity"} <= set(e)
    assert e["category"] == "credential"


# -------------------------------------------------------------------- pii
@pytest.mark.parametrize("text, expected", [
    ("CNIC 35202-1234567-1", "CNIC"),
    ("call 0300-1234567", "PHONE"),
    ("call +92 300 1234567", "PHONE"),
    ("mail sara.ahmed@gmail.com", "EMAIL"),
    ("account PK36SCBL0000001123456702", "IBAN"),
    ("server 192.168.1.20", "INTERNAL_IP"),
    ("DOB 14/03/1998", "DOB"),
    ("lives at House 12, Street 4", "ADDRESS"),
    ("this is confidential", "DOCUMENT_MARKING"),
])
def test_pii_is_detected(text, expected):
    assert expected in types(detect_pii(text))


def test_valid_card_is_detected():
    assert "CREDIT_CARD" in types(detect_pii("card 4111 1111 1111 1111"))


def test_invalid_card_is_ignored():
    assert "CREDIT_CARD" not in types(detect_pii("card 4111 1111 1111 1112"))


def test_luhn_helper():
    assert luhn_ok("4111 1111 1111 1111")
    assert not luhn_ok("4111 1111 1111 1112")


def test_cnic_is_not_mistaken_for_card_or_phone():
    assert types(detect_pii("35202-1234567-1")) == ["CNIC"]


def test_public_ip_is_not_internal():
    assert "INTERNAL_IP" not in types(detect_pii("DNS server 8.8.8.8"))


def test_plain_text_has_no_pii():
    assert detect_pii("What is the difference between a CNIC and a passport?") == []


def test_name_after_cue_word():
    found = detect_pii("Customer Sana Tariq called about a refund.", use_names=True)
    assert "PERSON" in types(found)


def test_names_off_by_default():
    assert "PERSON" not in types(detect_pii("Customer Sana Tariq called."))

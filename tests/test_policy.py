"""Tests for the risk engine and policy engine (no ML model needed)."""
import pytest

from src.policy_engine import decide, DEFAULT_POLICY
from src.risk_engine import compute_risk, level_for, ML_ONLY_CAP


def ent(type_, category, severity):
    return {"type": type_, "category": category, "start": 0, "end": 1, "severity": severity}


def ml(label, conf=0.9, p_safe=None):
    p_safe = (1 - conf) if p_safe is None else p_safe
    return {"label": label, "confidence": conf, "probabilities": {"safe": p_safe}}


def risk(score, ml_label="safe", ml_score=0.0):
    return {"score": score, "ml_label": ml_label, "ml_score": ml_score}


# ----------------------------------------------------------- thresholds
@pytest.mark.parametrize("score, action", [(0, "ALLOW"), (29, "ALLOW"), (30, "WARN"), (49, "WARN"),
                                           (50, "REDACT"), (69, "REDACT")])
def test_default_thresholds(score, action):
    entities = [ent("EMAIL", "pii", 35)]
    assert decide(risk(score), entities)["action"] == action


def test_high_score_with_credential_is_blocked():
    assert decide(risk(98), [ent("AWS_ACCESS_KEY", "credential", 98)])["action"] == "BLOCK"


def test_high_score_with_only_pii_is_redacted_not_blocked():
    assert decide(risk(81), [ent("CNIC", "pii", 75), ent("PHONE", "pii", 50)])["action"] == "REDACT"


def test_high_score_without_entities_is_blocked():
    assert decide(risk(75, "confidential", 75), [])["action"] == "BLOCK"


def test_unredactable_ml_label_forces_block_even_with_pii():
    r = risk(85, ml_label="source_code", ml_score=80)
    assert decide(r, [ent("EMAIL", "pii", 35)])["action"] == "BLOCK"


def test_marking_alone_is_never_treated_as_redactable():
    assert decide(risk(75, "confidential", 75), [ent("DOCUMENT_MARKING", "confidential", 25)])["action"] == "BLOCK"


def test_custom_thresholds_are_respected():
    strict = dict(DEFAULT_POLICY, allow_max=10, warn_max=20, redact_max=30)
    assert decide(risk(15), [ent("EMAIL", "pii", 35)], strict)["action"] == "WARN"


# ------------------------------------------------------------ risk score
def test_confident_safe_prompt_scores_low():
    r = compute_risk([], ml("safe", 0.95))
    assert r["score"] < 30 and r["level"] == "LOW"


def test_credential_entity_scores_critical():
    r = compute_risk([ent("AWS_ACCESS_KEY", "credential", 98)], ml("credential", 0.9, 0.05))
    assert r["score"] >= 90 and r["level"] == "CRITICAL"


def test_ml_alone_cannot_score_a_gated_label_above_cap():
    r = compute_risk([], ml("credential", 0.9, 0.05))
    assert r["score"] <= ML_ONLY_CAP


def test_source_code_is_scored_by_ml_alone():
    r = compute_risk([], ml("source_code", 0.9, 0.05))
    assert r["score"] > 60


def test_marking_with_flagged_prompt_is_boosted():
    r = compute_risk([ent("DOCUMENT_MARKING", "confidential", 25)], ml("confidential", 0.6, 0.3))
    assert r["score"] >= 75


def test_marking_with_safe_prompt_is_not_boosted():
    r = compute_risk([ent("DOCUMENT_MARKING", "confidential", 25)], ml("safe", 0.95))
    assert r["score"] < 50


def test_several_data_types_add_a_bonus():
    one = compute_risk([ent("CNIC", "pii", 75)], ml("pii", 0.9, 0.05))
    two = compute_risk([ent("CNIC", "pii", 75), ent("PHONE", "pii", 50)], ml("pii", 0.9, 0.05))
    assert two["score"] >= one["score"]


def test_risk_result_has_explanation_fields():
    r = compute_risk([ent("CNIC", "pii", 75)], ml("pii"))
    assert r["factors"] and r["entity_types"] == ["CNIC"]


@pytest.mark.parametrize("score, level", [(0, "LOW"), (29, "LOW"), (30, "MEDIUM"), (59, "MEDIUM"),
                                          (60, "HIGH"), (84, "HIGH"), (85, "CRITICAL"), (100, "CRITICAL")])
def test_level_boundaries(score, level):
    assert level_for(score) == level

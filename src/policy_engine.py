DEFAULT_POLICY = {
    "allow_max": 29,     # 0-29   ALLOW
    "warn_max": 49,      # 30-49  WARN
    "redact_max": 69,    # 50-69  REDACT, 70+ BLOCK
    "redactable_categories": ["pii", "financial"],
    "unredactable_ml_labels": ["source_code", "confidential", "credential"],
}

def decide(risk: dict, entities: list, policy: dict = DEFAULT_POLICY) -> dict:
    s = risk["score"]
    if   s <= policy["allow_max"]:  action, reason = "ALLOW",  "Low risk"
    elif s <= policy["warn_max"]:   action, reason = "WARN",   "Moderate risk: sensitive content may be present"
    elif s <= policy["redact_max"]: action, reason = "REDACT", "High risk: sensitive data will be removed"
    else:                           action, reason = "BLOCK",  "Critical risk"

    # confidentiality markings can't be redacted, so they never count as redactable evidence
    real = [e for e in entities if e["type"] != "DOCUMENT_MARKING"]
    ml_unredactable = (risk["ml_label"] in policy["unredactable_ml_labels"]
                       and risk["ml_score"] >= policy["warn_max"] + 1)
    all_redactable = bool(real) and all(e["category"] in policy["redactable_categories"] for e in real)

    if action == "BLOCK" and all_redactable and not ml_unredactable:
        action, reason = "REDACT", "Critical score, but all findings can be safely redacted"
    if action == "REDACT" and not real:
        action, reason = "BLOCK", "Sensitive content detected that cannot be redacted"
    return {"action": action, "reason": reason}

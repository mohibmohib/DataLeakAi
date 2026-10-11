# Combines detector evidence + ML prediction into a 0-100 score.
ML_BASE = {"safe": 0, "pii": 75, "financial": 85, "credential": 90, "source_code": 85, "confidential": 80}
SEV_OVERRIDE = {"PERSON": 20}                 # a bare name alone is weak evidence
GATED = {"pii", "financial", "credential"}    # ML label needs detector evidence for these
MARKING_BOOST = 75                            # marking word + non-safe ML label
ML_ONLY_CAP = 35                              # max score from ML alone for gated labels

def level_for(score: int) -> str:
    if score < 30: return "LOW"
    if score < 60: return "MEDIUM"
    if score < 85: return "HIGH"
    return "CRITICAL"

def compute_risk(entities: list, ml: dict, ml_only_cap: int = ML_ONLY_CAP) -> dict:
    factors, types = [], {}
    det_score = 0
    for e in entities:
        sev = SEV_OVERRIDE.get(e["type"], e["severity"])
        det_score = max(det_score, sev)
        types.setdefault(e["type"], e["category"])
    for t, c in types.items():
        factors.append(f"Detected {t} ({c})")

    label, conf = ml["label"], ml["confidence"]
    p_safe = ml.get("probabilities", {}).get("safe", 1 - conf)
    ml_score = ML_BASE.get(label, 0) * (1 - p_safe)
    if label in GATED and not any(e["category"] == label for e in entities) and ml_score > ml_only_cap:
        factors.append(f"ML predicted '{label}' but no matching pattern was found, so ML score was capped")
        ml_score = ml_only_cap
    elif label != "safe":
        factors.append(f"ML classifier predicted '{label}' ({conf:.0%} confidence)")

    bonus = min(9, 3 * (len(types) - 1)) if len(types) > 1 else 0
    if bonus: factors.append(f"Multiple sensitive data types found (+{bonus})")

    if not entities and label == "safe":
        score = round((1 - conf) * 30)
    else:
        score = round(min(100, max(det_score, ml_score) + bonus))

    if "DOCUMENT_MARKING" in types and label != "safe":
        factors.append("Confidentiality marking found and the ML classifier flags this prompt")
        score = max(score, MARKING_BOOST)

    if entities:
        category = max(entities, key=lambda e: SEV_OVERRIDE.get(e["type"], e["severity"]))["category"]
    else:
        category = label
    return {"score": int(score), "level": level_for(score), "category": category,
            "det_score": det_score, "ml_score": round(ml_score, 1),
            "ml_label": label, "ml_confidence": conf, "factors": factors,
            "entity_types": sorted(types)}

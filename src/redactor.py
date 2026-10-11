import re

TOKENS = {
    "CNIC": "[CNIC_REDACTED]", "PHONE": "[PHONE_REDACTED]", "EMAIL": "[EMAIL_REDACTED]",
    "CREDIT_CARD": "[CARD_REDACTED]", "IBAN": "[IBAN_REDACTED]", "PERSON": "[PERSON]",
    "DOB": "[DOB_REDACTED]", "ADDRESS": "[ADDRESS_REDACTED]", "INTERNAL_IP": "[IP_REDACTED]",
}

def merge_entities(entities: list) -> list:
    """Drop overlapping detections, keeping the highest severity."""
    kept = []
    for e in sorted(entities, key=lambda e: (-e["severity"], e["start"])):
        if not any(e["start"] < k["end"] and k["start"] < e["end"] for k in kept):
            kept.append(e)
    return sorted(kept, key=lambda e: e["start"])

def redact(text: str, entities: list) -> str:
    out = text
    entities = [e for e in entities if e["type"] != "DOCUMENT_MARKING"]   # never replace the marking word
    for e in sorted(entities, key=lambda e: e["start"], reverse=True):
        s, t = e["start"], e["end"]
        if e["type"].endswith("ASSIGNMENT"):          # keep the key name, hide the value
            m = re.search(r"[:=]\s*['\"]?", out[s:t])
            if m: s += m.end()
        out = out[:s] + TOKENS.get(e["type"], "[CREDENTIAL_REDACTED]") + out[t:]
    return out

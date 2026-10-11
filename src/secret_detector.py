import re, math

SECRET_RULES = [
    ("PRIVATE_KEY",        r"-----BEGIN [A-Z ]*PRIVATE KEY-----", 100),
    ("AWS_SECRET_KEY",     r"(?i)aws_secret_access_key['\"]?\s*[=:]\s*['\"]?[A-Za-z0-9/+=]{40}", 98),
    ("AWS_ACCESS_KEY",     r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b", 98),
    ("DB_CONNECTION",      r"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://[^\s:@/]+:[^\s@/]+@\S+", 96),
    ("GITHUB_TOKEN",       r"\bgh[pousr]_[A-Za-z0-9]{36,}\b", 97),
    ("SLACK_TOKEN",        r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b", 95),
    ("GOOGLE_API_KEY",     r"\bAIza[0-9A-Za-z_-]{35}\b", 95),
    ("JWT",                r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}", 90),
    ("BEARER_TOKEN",       r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{20,}", 90),
    ("SECRET_ASSIGNMENT",  r"(?i)\b(?:api[_-]?key|secret[_-]?key|client[_-]?secret|access[_-]?token|auth[_-]?token|secret|token)\b['\"]?\s*[:=]\s*['\"]?[^\s'\",;]{8,}", 90),
    ("PASSWORD_ASSIGNMENT",r"(?i)\b(?:password|passwd|pwd|db_password)\b['\"]?\s*[:=]\s*['\"]?[^\s'\",;]{4,}", 85),
    ("PASSWORD_STATEMENT", r"(?i)\bpassword\s+is\s+['\"]?(?=\S*\d)[^\s'\",;]{6,}", 80),
]
_COMPILED = [(n, re.compile(p), s) for n, p, s in SECRET_RULES]

def _entropy(s: str) -> float:
    if not s: return 0.0
    return -sum((s.count(c)/len(s)) * math.log2(s.count(c)/len(s)) for c in set(s))

def _overlaps(a, b): return a[0] < b[1] and b[0] < a[1]

def detect_secrets(text: str):
    found, spans = [], []
    for name, rx, sev in _COMPILED:
        for m in rx.finditer(text):
            span = (m.start(), m.end())
            if any(_overlaps(span, s) for s in spans): continue
            spans.append(span)
            found.append({"type": name, "category": "credential", "start": span[0], "end": span[1], "severity": sev})
    # fallback: long random-looking strings
    for m in re.finditer(r"[A-Za-z0-9+/=_-]{24,}", text):
        span = (m.start(), m.end())
        if any(_overlaps(span, s) for s in spans): continue
        if "/" in m.group() and m.group().count("/") > 2: continue   # looks like a path
        if _entropy(m.group()) >= 4.0:
            spans.append(span)
            found.append({"type": "HIGH_ENTROPY_STRING", "category": "credential",
                          "start": span[0], "end": span[1], "severity": 75})
    return sorted(found, key=lambda e: e["start"])

import re

PATTERNS = [
    (r"-----BEGIN [A-Z ]*PRIVATE KEY-----", " privatekeytoken "),
    (r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", " jwttoken "),
    (r"\bAKIA[0-9A-Z]{16}\b", " awskeytoken "),
    (r"\b\d{5}-\d{7}-\d\b", " cnictoken "),
    (r"\b03\d{2}-?\d{7}\b", " phonetoken "),
    (r"\b(?:\d[ -]?){13,16}\b", " cardtoken "),
    (r"\bPK\d{2}[A-Z]{4}\d{10,16}\b", " ibantoken "),
    (r"[\w.+-]+@[\w-]+\.[\w.]+", " emailtoken "),
    (r"\b(?:10|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}(?:\.\d{1,3})?\b", " internaliptoken "),
]

def clean_text(text: str) -> str:
    text = str(text)
    for pat, tok in PATTERNS:          # replace sensitive patterns with tokens first
        text = re.sub(pat, tok, text)
    text = text.lower()
    text = re.sub(r"[^a-z0-9_\s]", " ", text)
    text = re.sub(r"\b[a-z0-9]{25,}\b", " longsecrettoken ", text)  # long random strings
    return re.sub(r"\s+", " ", text).strip()

import re

def luhn_ok(num: str) -> bool:
    d = [int(c) for c in re.sub(r"\D", "", num)]
    if not 13 <= len(d) <= 19: return False
    s = 0
    for i, x in enumerate(reversed(d)):
        if i % 2 == 1:
            x *= 2
            if x > 9: x -= 9
        s += x
    return s % 10 == 0

RULES = [  # (type, category, regex, severity), order = priority
    ("CNIC",        "pii",       r"(?<!\d)\d{5}-\d{7}-\d(?!\d)", 75),
    ("IBAN",        "financial", r"\bPK\d{2}[A-Z]{4}\d{12,20}\b", 80),
    ("PHONE",       "pii",       r"(?<!\d)(?:\+92[- ]?|0)3\d{2}[- ]?\d{7}(?!\d)", 50),
    ("EMAIL",       "pii",       r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+", 35),
    ("INTERNAL_IP", "confidential", r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b", 45),
    ("DOB",         "pii",       r"(?i)\b(?:dob|date of birth|born(?: on)?)\b[:\s-]*\d{1,2}[/-]\d{1,2}[/-]\d{2,4}", 60),
    ("DOCUMENT_MARKING", "confidential", r"(?i)\b(?:confidential|internal[- ]only|nda|proprietary|trade secret|do not (?:share|distribute)|not for (?:external|public) (?:sharing|distribution)|private repo(?:sitory)?)\b", 25),
    ("ADDRESS",     "pii",       r"(?i)\bhouse\s*(?:no\.?\s*)?#?\d+[^\n.]{0,50}", 55),
]
_COMPILED = [(t, c, re.compile(p), s) for t, c, p, s in RULES]
_CARD = re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)")
_CNIC_PLAIN = re.compile(r"(?i)\b(?:cnic|nic|id card)\b[^\d]{0,15}(\d{13})(?!\d)")

# ---- name detection (best effort) ----
_NAME_CUE = re.compile(
    r"(?i:\b(?:customer|employee|client|patient|staff|applicant|mr|mrs|ms|dr)\b\.?(?:\s+details)?)"
    r"\s*[:,-]?\s+([A-Z][a-z]{2,}(?:\s+[A-Z][a-z]{2,}){0,2})")
_NOT_NAMES = {"Support","Service","Services","Details","Data","Information","Database","Name","Team","Care"}
_VERBS = {"analyze","analyse","summarize","summarise","review","explain","debug","translate","write","draft",
          "verify","check","reconcile","optimize","rewrite","refactor","find","help","please","call","email",
          "send","create","make","give","show","list","fix","update","process","prepare","format"}
_nlp = None

def _get_nlp():
    global _nlp
    if _nlp is None:
        import spacy
        _nlp = spacy.load("en_core_web_sm")
    return _nlp

def _find_names(text):
    spans = []
    for m in _NAME_CUE.finditer(text):
        if not any(w in _NOT_NAMES for w in m.group(1).split()):
            spans.append((m.start(1), m.end(1)))
    try:
        for ent in _get_nlp()(text).ents:
            if ent.label_ != "PERSON": continue
            s = ent.start_char
            words = list(re.finditer(r"[A-Za-z][A-Za-z'\u2019-]*", ent.text))
            while words and words[0].group().lower() in _VERBS:
                words.pop(0)
            if len(words) < 2 or not all(w.group()[0].isupper() for w in words):
                continue
            end = s + words[-1].end()
            if words[-1].group().lower().endswith(("'s", "\u2019s")):
                end -= 2
            spans.append((s + words[0].start(), end))
    except Exception:
        pass
    return spans

def _overlaps(a, b): return a[0] < b[1] and b[0] < a[1]

def detect_pii(text: str, use_names: bool = False):
    found, spans = [], []
    def add(t, c, s, e, sev):
        if any(_overlaps((s, e), x) for x in spans): return
        spans.append((s, e))
        found.append({"type": t, "category": c, "start": s, "end": e, "severity": sev})

    for m in _CNIC_PLAIN.finditer(text):
        add("CNIC", "pii", m.start(1), m.end(1), 75)
    for t, c, rx, sev in _COMPILED:
        for m in rx.finditer(text):
            add(t, c, m.start(), m.end(), sev)
    for m in _CARD.finditer(text):               # card last, so CNIC/phone win overlaps
        trimmed = m.group().rstrip(" -")
        if luhn_ok(trimmed):
            add("CREDIT_CARD", "financial", m.start(), m.start() + len(trimmed), 90)
    if use_names:
        for s, e in _find_names(text):
            add("PERSON", "pii", s, e, 30)
    return sorted(found, key=lambda e: e["start"])

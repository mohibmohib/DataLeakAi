from .classifier import PromptClassifier
from .secret_detector import detect_secrets
from .pii_detector import detect_pii
from .redactor import merge_entities, redact
from .risk_engine import compute_risk
from .policy_engine import decide, DEFAULT_POLICY
from .explainer import explain

class DataLeakGateway:
    def __init__(self, policy: dict = None, use_names: bool = True):
        self.clf = PromptClassifier()
        self.policy = policy or DEFAULT_POLICY
        self.use_names = use_names

    def analyze(self, prompt: str) -> dict:
        entities = merge_entities(detect_secrets(prompt) + detect_pii(prompt, use_names=self.use_names))
        ml = self.clf.predict(prompt)
        risk = compute_risk(entities, ml)
        decision = decide(risk, entities, self.policy)
        sanitized = redact(prompt, entities) if entities and decision["action"] != "BLOCK" else None
        return {"action": decision["action"], "risk": risk, "decision": decision,
                "entities": entities, "sanitized_prompt": sanitized,
                "forward_prompt": prompt if decision["action"] in ("ALLOW", "WARN")
                                  else (sanitized if decision["action"] == "REDACT" else None),
                "explanation": explain(risk, decision)}

import os, joblib
from .preprocessing import clean_text

MODEL_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "models")

class PromptClassifier:
    def __init__(self, model_dir: str = MODEL_DIR):
        self.tfidf = joblib.load(os.path.join(model_dir, "tfidf.pkl"))
        self.clf   = joblib.load(os.path.join(model_dir, "classifier.pkl"))
        self.le    = joblib.load(os.path.join(model_dir, "label_encoder.pkl"))

    def predict(self, text: str) -> dict:
        X = self.tfidf.transform([clean_text(text)])
        proba = self.clf.predict_proba(X)[0]
        i = int(proba.argmax())
        return {
            "label": str(self.le.classes_[i]),
            "confidence": float(proba[i]),
            "probabilities": {str(c): float(p) for c, p in zip(self.le.classes_, proba)},
        }

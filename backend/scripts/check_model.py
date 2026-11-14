import os
import pickle
import numpy as np

# Resolve path to backend/models/
_BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_PATH = os.path.join(_BASE_DIR, "models", "model.pkl")
VECTORIZER_PATH = os.path.join(_BASE_DIR, "models", "vectorizer.pkl")

with open(MODEL_PATH, "rb") as f:
    m = pickle.load(f)
with open(VECTORIZER_PATH, "rb") as f:
    v = pickle.load(f)

print("classes:", m.classes_)

names = np.array(v.get_feature_names_out())
order = np.argsort(m.coef_[0])
print("\nWords pushing toward CLASS 1:", list(names[order[-30:]][::-1]))
print("\nWords pushing toward CLASS 0:", list(names[order[:30]]))

tests = {
    "scam": "Earn Rs 3000 per day from home. Pay Rs 250 registration fee. WhatsApp only. Join today!",
    "legit": "We are hiring a Software Engineer with 2+ years of experience in Java and Spring. Responsibilities include designing APIs. Apply via our careers page. Interview process: 3 rounds.",
}
for k, t in tests.items():
    print(k, "-> [P(class0), P(class1)] =", m.predict_proba(v.transform([t]))[0])

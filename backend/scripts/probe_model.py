import os
import sys

_BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BASE_DIR not in sys.path:
    sys.path.insert(0, _BASE_DIR)

from services.predictor import get_ml_score
from services.rule_engine import get_rule_analysis

cases = {
    "indian fee scam (software-flavoured)": "Hiring Python developer intern. Work from home. Pay Rs 500 registration fee for training kit. Contact on WhatsApp only. Join today.",
    "task scam": "Simple tasks, like YouTube videos and earn Rs 3000 per day. Telegram only. No experience needed.",
    "legit oil & gas": "Subsea Engineer needed offshore for an established energy company. Bachelor's degree in engineering required. 5 years experience. Apply via careers page.",
    "legit startup": "We are a growing fintech startup hiring a backend engineer. Our team builds payment APIs in Java. Interview: 3 rounds, no fees at any stage.",
}

for name, t in cases.items():
    print(f"{name}: ML={get_ml_score(t)}  RULES={get_rule_analysis(t)['rule_score']}")

import sys
import os
import json
import threading
import time
import urllib.request

sys.stdout.reconfigure(encoding='utf-8')

_BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BASE_DIR not in sys.path:
    sys.path.insert(0, _BASE_DIR)

from app import app
from tests.fixtures.mock_fixtures import FIXTURES
from werkzeug.serving import make_server

# Build test fixtures set including XYZ and TCS
BENCHMARK_FIXTURES = {
    "A (Pune screenshot)": {
        "text": FIXTURES["A"],
        "is_ocr": True
    },
    "B (fee scam)": {
        "text": FIXTURES["B"],
        "is_ocr": False
    },
    "C (\"hi are we still meeting at 5?\")": {
        "text": "hi are we still meeting at 5?",
        "is_ocr": False
    },
    "D (Infosys invite)": {
        "text": FIXTURES["D"],
        "is_ocr": False
    },
    "E (Zoho invite)": {
        "text": FIXTURES["E"],
        "is_ocr": False
    },
    "XYZ intern message": {
        "text": (
            "Software Intern - Remote\n"
            "Company: XYZ Solutions\n"
            "We are looking for interns to work on exciting projects.\n"
            "Stipend: Negotiable\n"
            "Contact: xyzcompany.hr@gmail.com\n"
            "Requirements: None. Freshers welcome.\n"
            "No formal interview. Just send your resume on WhatsApp.\n"
            "Joining: Immediate"
        ),
        "is_ocr": False
    },
    "TCS message with hr@tcs-hiring.in": {
        "text": FIXTURES["F"],
        "is_ocr": False
    }
}


class ServerThread(threading.Thread):
    def __init__(self, app, port=5007):
        threading.Thread.__init__(self)
        self.server = make_server('127.0.0.1', port, app)
        self.ctx = app.app_context()
        self.ctx.push()

    def run(self):
        self.server.serve_forever()

    def shutdown(self):
        self.server.shutdown()


def query_server(text, is_ocr=False, port=5007):
    req_data = json.dumps({
        "text": text,
        "input_type": "ocr" if is_ocr else "text"
    }).encode('utf-8')

    req = urllib.request.Request(
        f"http://127.0.0.1:{port}/analyze",
        data=req_data,
        headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=35) as response:
        return json.loads(response.read().decode('utf-8'))


def main():
    port = 5007
    server = ServerThread(app, port=port)
    server.start()
    time.sleep(0.5)

    try:
        print(f"{'Fixture':<35} | {'Rule':<5} | {'ML':<4} | {'AI R1':<5} | {'AI R2':<5} | {'Overall':<7} | {'Level':<7}")
        print("-" * 80)
        for name, data in BENCHMARK_FIXTURES.items():
            r1 = query_server(data["text"], is_ocr=data["is_ocr"], port=port)
            r2 = query_server(data["text"], is_ocr=data["is_ocr"], port=port)
            rule_s = r1.get("rule_score", 0)
            ml_s = r1.get("ml_score", 0)
            ai_1 = r1.get("llm_score", 0)
            ai_2 = r2.get("llm_score", 0)
            overall = r1.get("risk_score", 0)
            level = r1.get("risk_level", "Unknown")
            print(f"{name:<35} | {rule_s:<5} | {ml_s:<4} | {ai_1:<5} | {ai_2:<5} | {overall:<7} | {level:<7}")
    finally:
        server.shutdown()


if __name__ == "__main__":
    main()

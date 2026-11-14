import sys
import os
import threading
import time
import json
import urllib.request

# Ensure UTF-8 output
sys.stdout.reconfigure(encoding='utf-8')

_BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BASE_DIR not in sys.path:
    sys.path.insert(0, _BASE_DIR)

from services import rule_engine
from app import app
from tests.fixtures.mock_fixtures import FIXTURES
from werkzeug.serving import make_server


class ServerThread(threading.Thread):
    def __init__(self, app, port=5006):
        threading.Thread.__init__(self)
        self.server = make_server('127.0.0.1', port, app)
        self.ctx = app.app_context()
        self.ctx.push()

    def run(self):
        self.server.serve_forever()

    def shutdown(self):
        self.server.shutdown()


def query_server(text, port=5006, is_ocr=False):
    req_data = json.dumps({
        "text": text,
        "input_type": "ocr" if is_ocr else "text"
    }).encode('utf-8')

    req = urllib.request.Request(
        f"http://127.0.0.1:{port}/analyze",
        data=req_data,
        headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=30) as response:
        return json.loads(response.read().decode('utf-8'))


def main():
    port = 5006
    server = ServerThread(app, port=port)
    server.start()
    time.sleep(0.5)

    orig_guard = rule_engine.is_legitimate_recruitment_context

    results = {"guard_on": {}, "guard_off": {}}

    try:
        # Guard ON
        print("=== RUNNING WITH GUARD ON ===")
        rule_engine.is_legitimate_recruitment_context = orig_guard
        for key, text in FIXTURES.items():
            is_ocr = (key == "A")
            res = query_server(text, port=port, is_ocr=is_ocr)
            results["guard_on"][key] = res
            print(f"Fixture {key} (Guard ON): Risk={res['risk_score']}, Level={res['risk_level']}, Rule={res['rule_score']}, ML={res['ml_score']}, LLM={res['llm_score']}, Cat={res['scam_category']}")

        # Guard OFF
        print("\n=== RUNNING WITH GUARD OFF ===")
        rule_engine.is_legitimate_recruitment_context = lambda text: False
        for key, text in FIXTURES.items():
            is_ocr = (key == "A")
            res = query_server(text, port=port, is_ocr=is_ocr)
            results["guard_off"][key] = res
            print(f"Fixture {key} (Guard OFF): Risk={res['risk_score']}, Level={res['risk_level']}, Rule={res['rule_score']}, ML={res['ml_score']}, LLM={res['llm_score']}, Cat={res['scam_category']}")

        print("\nComparison completed successfully!")

    finally:
        server.shutdown()
        rule_engine.is_legitimate_recruitment_context = orig_guard


if __name__ == "__main__":
    main()

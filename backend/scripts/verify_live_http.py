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


def query_server(text, is_ocr=False, port=5006):
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

    try:
        print("=== RUNNING LIVE HTTP FIXTURE VERIFICATION ===")
        print(f"{'Fixture':<10} | {'Risk':<5} | {'Level':<7} | {'Rule':<5} | {'ML':<4} | {'LLM':<4} | {'Category'}")
        print("-" * 80)
        for key, text in FIXTURES.items():
            is_ocr = (key == "A")
            res = query_server(text, is_ocr=is_ocr, port=port)
            print(f"Fixture {key:<2} | {res['risk_score']:<5} | {res['risk_level']:<7} | {res['rule_score']:<5} | {res['ml_score']:<4} | {str(res['llm_score']):<4} | {res['scam_category']}")
        print("\nAll live HTTP fixture queries completed successfully!")
    finally:
        server.shutdown()


if __name__ == "__main__":
    main()

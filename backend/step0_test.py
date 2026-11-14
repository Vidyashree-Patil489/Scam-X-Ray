import sys
import os
import threading
import time
import json
import urllib.request

# Ensure UTF-8 output
sys.stdout.reconfigure(encoding='utf-8')

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rule_engine
from app import app
from werkzeug.serving import make_server

FIXTURES = {
    "A": (
        "lo EARNS: we have\n"
        "received your job application from\n"
        "Online Job Portal.\n"
        "You are invited to proceed with\n"
        "the next step for the position\n"
        "of Software Developer, Web\n"
        "Developer, Graphic Designer.\n"
        "Interview Time: Tomorrow 10:30\n"
        "AM.\n"
        "Venue: Will be provided after\n"
        "sharing your updated CV.\n"
        "Share your CV on WhatsApp:\n"
        "98765 43210.\n"
        "HR Team."
    ),
    "B": (
        "Dear Candidate, Congratulations! You are selected for Data Entry Operator at Global Tech. "
        "Registration fee Rs. 1500/- refundable. Pay to UPI id globaltech@upi to confirm your offer letter. Call 9876543210."
    ),
    "C": (
        "Hey, are we still meeting for lunch tomorrow at 1pm? Let me know if that works for you."
    ),
    "D": (
        "Dear candidate, Following your application for the Senior Software Engineer role at Infosys Limited, "
        "we would like to invite you for a technical interview tomorrow at 11:00 AM. Location: Infosys Campus, "
        "Electronic City, Hosur Road, Bengaluru. Gate 1 reception. Please carry a photo ID. Contact: hr.recruitment@infosys.com."
    ),
    "E": (
        "Hi Alex, I came across your profile and think you'd be a great fit for our Product Designer opening at Zoho Corporation. "
        "We are holding interviews this week. If you're interested, please select a slot at https://meet.google.com/abc-defg-hij "
        "or reply to this email. Best regards, Priya Sharma, Talent Acquisition, Zoho."
    ),
    "F": (
        "TCS Technologies Pvt Ltd. Interview Time: Tomorrow. Venue: TCS Campus, Whitefield, Bengaluru, Gate 1 reception. "
        "Share your CV on WhatsApp 98765 43210 to confirm your slot. Contact: hr@tcs-hiring.in"
    ),
    "G": (
        "Wipro Ltd is hiring. Interview tomorrow. Location: Pune. Send your CV on WhatsApp 98765 43210 for the detailed address."
    ),
    "H": (
        "Hiring at Zoho Corporation: Software Developer, Web Developer & Data Analyst. Apply at careers.zoho.com. "
        "Interview details will be shared by email after shortlisting."
    ),
    "I": (
        "Infosys Limited. Interview tomorrow at Infosys Campus, Electronic City, Bengaluru, Gate 2 reception. "
        "Contact: hr@infosys-careers.in"
    )
}

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
    payload = json.dumps({"text": text, "input_type": "ocr" if is_ocr else "text"}).encode('utf-8')
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}/analyze",
        data=payload,
        headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode('utf-8'))

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

        with open("step0_results.json", "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        print("\nSaved untrimmed results to step0_results.json")

    finally:
        server.shutdown()
        rule_engine.is_legitimate_recruitment_context = orig_guard

if __name__ == "__main__":
    main()

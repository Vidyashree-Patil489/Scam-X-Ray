import sys
import os
import json
import threading
import time
import urllib.request

sys.stdout.reconfigure(encoding='utf-8')
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from app import app
from werkzeug.serving import make_server

FIXTURES = {
    "A (Pune screenshot)": {
        "text": (
            "lo EARNS: we have\n"
            "received your job application from\n"
            "Online Job Portal.\n"
            "You are invited to proceed with\n"
            "the next step for the position\n"
            "of Software Developer, Web\n"
            "Developer & Data Analyst.\n"
            "Interview Time: Tomorrow\n"
            "Location: Pune\n"
            "Please share your CV on this\n"
            "WhatsApp number so we can\n"
            "review it and provide the detailed\n"
            "interview address. 12:32 pm\n"
            "4 Interested\n"
            " STOP"
        ),
        "is_ocr": True
    },
    "B (fee scam)": {
        "text": (
            "Urgent opening: WFH Data Entry Associate. Earn ₹45,000/month. No experience needed.\n"
            "Pay ₹500 refundable registration fee to activate server account. WhatsApp only:\n"
            "+91 98765 43210. Limited slots, apply within 24 hours!"
        ),
        "is_ocr": False
    },
    "C (\"hi are we still meeting at 5?\")": {
        "text": "hi are we still meeting at 5?",
        "is_ocr": False
    },
    "D (Infosys invite)": {
        "text": (
            "Hi Priya, thank you for\n"
            "applying to the Data Analyst internship at Infosys. Your interview is on Tuesday\n"
            "18 Nov at 11 AM at Infosys Campus, Electronic City, Bengaluru, Gate 2 reception.\n"
            "Please bring your ID and resume. Contact: hr.recruitment@infosys.com. Regards,\n"
            "Ananya Rao, Talent Acquisition."
        ),
        "is_ocr": False
    },
    "E (Zoho invite)": {
        "text": (
            "Dear Rahul, your\n"
            "technical round with Zoho is scheduled tomorrow at 10:30 AM on Google Meet.\n"
            "Link: meet.google.com/abc-defg-hij. Please keep a government photo ID ready.\n"
            "Reply to this email to confirm. - Meena S, HR, Zoho Corporation"
        ),
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
        "text": (
            "TCS Technologies Pvt Ltd. Interview Time: Tomorrow. Venue: TCS Campus, Whitefield, "
            "Bengaluru, Gate 1 reception. Share your CV on WhatsApp 98765 43210 to confirm your slot. "
            "Contact: hr@tcs-hiring.in"
        ),
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

def query_server(text, port=5007, is_ocr=False):
    payload = json.dumps({"text": text, "input_type": "ocr" if is_ocr else "text"}).encode('utf-8')
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}/analyze",
        data=payload,
        headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode('utf-8'))

def main():
    port = 5007
    server = ServerThread(app, port=port)
    server.start()
    time.sleep(0.5)

    runs = {"run1": {}, "run2": {}}

    try:
        print("=== RUN 1 ===")
        for name, item in FIXTURES.items():
            res1 = query_server(item["text"], port=port, is_ocr=item["is_ocr"])
            runs["run1"][name] = res1
            print(f"Run 1: {name} -> Rule={res1['rule_score']}, ML={res1['ml_score']}, AI={res1['llm_score']}, Overall={res1['risk_score']} ({res1['risk_level']})")

        print("\n=== RUN 2 (measuring AI variance) ===")
        for name, item in FIXTURES.items():
            res2 = query_server(item["text"], port=port, is_ocr=item["is_ocr"])
            runs["run2"][name] = res2
            print(f"Run 2: {name} -> Rule={res2['rule_score']}, ML={res2['ml_score']}, AI={res2['llm_score']}, Overall={res2['risk_score']} ({res2['risk_level']})")

        with open("fixture_runs.json", "w", encoding="utf-8") as f:
            json.dump(runs, f, indent=2, ensure_ascii=False)
        print("\nSaved fixture_runs.json successfully!")

    finally:
        server.shutdown()

if __name__ == "__main__":
    main()

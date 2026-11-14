import sys
import os
import threading
import time
import json
import urllib.request

# Ensure UTF-8 output
sys.stdout.reconfigure(encoding='utf-8')

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
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

OCR_VARIANTS = {
    "A_variant_1": (
        "lo EARNS: we have\n"
        "received your job app1ication from\n"
        "Online Job Portal.\n"
        "You are invited to proceed with\n"
        "the next step for the position\n"
        "of Software Developer, Web\n"
        "Developer, Graphic Designer.\n"
        "Interview Time: Tomorrow 10:30\n"
        "AM.\n"
        "Venue: Wi11 be provided after\n"
        "sharing your updated CV.\n"
        "Share your CV on WhatsApp:\n"
        "98765 43210.\n"
        "HR Team."
    ),
    "A_variant_2": (
        "Io EARNS: we have received your job application from Online Job Portal .\n"
        "You are invited to proceed with the next step for the position of Software Developer, "
        "Web Developer, Graphic Designer .\n"
        "Interview Time : Tomorrow 10:30 AM .\n"
        "Venue : Will be provided after sharing your updated CV .\n"
        "Share your CV on WhatsApp : 98765 43210 .\n"
        "HR Team ."
    )
}

class ServerThread(threading.Thread):
    def __init__(self, app, port=5005):
        threading.Thread.__init__(self)
        self.server = make_server('127.0.0.1', port, app)
        self.ctx = app.app_context()
        self.ctx.push()

    def run(self):
        self.server.serve_forever()

    def shutdown(self):
        self.server.shutdown()

def query_server(text=None, url=None, port=5005, is_ocr=False):
    payload_dict = {}
    if text is not None:
        payload_dict["text"] = text
        payload_dict["input_type"] = "ocr" if is_ocr else "text"
    if url is not None:
        payload_dict["url"] = url
        payload_dict["input_type"] = "url"

    payload = json.dumps(payload_dict).encode('utf-8')
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}/analyze",
        data=payload,
        headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=35) as resp:
        return json.loads(resp.read().decode('utf-8'))

def main():
    port = 5005
    server = ServerThread(app, port=port)
    server.start()
    time.sleep(0.5)

    final_results = {}

    try:
        print("=== RUNNING LIVE HTTP SERVER ON PORT 5005 ===")
        for key, text in FIXTURES.items():
            is_ocr = (key == "A")
            res = query_server(text, port=port, is_ocr=is_ocr)
            final_results[key] = res
            print(f"Fixture {key}: Risk={res['risk_score']}, Level={res['risk_level']}, Rule={res['rule_score']}, ML={res['ml_score']}, LLM={res['llm_score']}, Cat={res['scam_category']}")
            print(f"   Flags: {res['rule_flags']}")

        print("\n=== RUNNING OCR NOISE VARIANTS OF FIXTURE A ===")
        for key, text in OCR_VARIANTS.items():
            res = query_server(text, port=port, is_ocr=True)
            final_results[key] = res
            print(f"{key}: Risk={res['risk_score']}, Level={res['risk_level']}, Rule={res['rule_score']}, ML={res['ml_score']}, LLM={res['llm_score']}, Cat={res['scam_category']}")
            print(f"   Flags: {res['rule_flags']}")

        # URL sanity checks
        print("\n=== RUNNING URL REGRESSION CHECK ===")
        for u in ["https://github.com", "https://paypa1-secure-login.com/"]:
            u_res = query_server(url=u, port=port)
            final_results[f"URL_{u}"] = u_res
            print(f"{u}: Verdict={u_res['url_verdict']}, Score={u_res['url_score']}, Risk={u_res['risk_score']}, Level={u_res['risk_level']}")

        with open("final_http_results.json", "w", encoding="utf-8") as f:
            json.dump(final_results, f, indent=2, ensure_ascii=False)
        print("\nSaved full untrimmed results to final_http_results.json")

    finally:
        server.shutdown()

if __name__ == "__main__":
    main()

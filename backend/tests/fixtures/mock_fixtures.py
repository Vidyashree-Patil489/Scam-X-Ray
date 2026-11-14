import re
import tldextract

COMPANY_OFFICIAL_DOMAINS = {
    "tcs": {"tcs.com"},
    "tata consultancy": {"tcs.com"},
    "tata consultancy services": {"tcs.com"},
    "infosys": {"infosys.com"},
    "wipro": {"wipro.com"},
    "zoho": {"zoho.com"},
    "cognizant": {"cognizant.com"},
    "accenture": {"accenture.com"},
    "microsoft": {"microsoft.com"},
    "google": {"google.com"},
    "amazon": {"amazon.com"},
    "ibm": {"ibm.com"},
    "oracle": {"oracle.com"},
    "deloitte": {"deloitte.com"},
    "capgemini": {"capgemini.com"},
    "hcl": {"hcltech.com", "hcl.com"},
    "tech mahindra": {"techmahindra.com"},
    "flipkart": {"flipkart.com"},
}

USER_CONTENT_OR_SHORTENER_DOMAINS = {
    "github.io", "gitlab.io", "vercel.app", "netlify.app", "firebaseapp.com",
    "web.app", "pages.dev", "herokuapp.com", "render.com",
    "bit.ly", "tinyurl.com", "cutt.ly", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "shorturl.at",
    "drive.google.com", "docs.google.com", "forms.gle", "forms.office.com", "notion.site",
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "rediffmail.com",
    "proton.me", "protonmail.com", "icloud.com", "mail.com",
}

EXCLUDED_LINK_DOMAINS = {
    "meet.google.com", "teams.microsoft.com", "zoom.us", "webex.com",
    "linkedin.com", "maps.google.com", "google.com/maps"
}

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

# OCR Noise Variants of Fixture A
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
        "Io EARNS: we have received your job application from Online Job Portal. "
        "You are invited to proceed with the next step for the position of Software Developer, "
        "Web Developer, Graphic Designer. Interview Time: Tomorrow 10:30 AM. "
        "Venue: Will be provided after sharing your updated CV. "
        "Share your CV on WhatsApp: 98765 43210. HR Team."
    ),
    "A_variant_3": (
        "1o EARNS: we have\n"
        "received your job application from\n"
        "Online Job Portal .\n"
        "You are invited to proceed with\n"
        "the next step for the position\n"
        "of Software Developer, Web Developer, Graphic Designer .\n"
        "Interview Time : Tomorrow 10:30 AM .\n"
        "Venue : Will be provided after sharing your updated CV .\n"
        "Share your CV on WhatsApp : 98765 43210 .\n"
        "HR Team ."
    )
}



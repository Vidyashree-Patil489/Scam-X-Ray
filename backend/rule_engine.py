import re
import tldextract

ROLES_PATTERN = (
    r"(?:telecaller|back[\s-]office|receptionist|data\s+entry|hr\s+executive|"
    r"computer\s+operator|helper|sales\s+executive|office\s+assistant|accountant|"
    r"software\s+developer|web\s+developer|data\s+analyst|python\s+developer|"
    r"graphic\s+designer|content\s+writer)"
)

RULES = [
    {
        "name": "OTP or PIN request",
        "category": "financial",
        "severity": 35,
        "patterns": [
            r"\bshare\s+(?:your\s+)?otp\b",
            r"\bprovide\s+(?:your\s+)?otp\b",
            r"\benter\s+(?:your\s+)?otp\b",
            r"\bshare\s+(?:your\s+)?pin\b",
            r"\bprovide\s+(?:your\s+)?upi\s+pin\b",
            r"\bshare\s+(?:your\s+)?cvv\b",
        ],
    },
    {
        "name": "Urgency or threat",
        "category": "phishing",
        "severity": 12,
        "patterns": [
            r"\blimited\s+slots?\b",
            r"\bregistration\s+closes?\b",
            r"\bjoin\s+today\b",
            r"\bactivate\s+.*?\s+instantly\b",
            r"\baccount\s+will\s+be\s+blocked\b",
            r"\bact\s+immediately\b",
            r"\bwithin\s+\d+\s+minutes\b",
            r"\bwithin\s+24\s+hours\b",
            r"\burgent(?:ly)?\b",
            r"\bfinal\s+warning\b",
            r"\bexpires\s+today\b",
            r"\bsame[\s-]day\b",
            r"\bhurry\b",
            r"\bonly\s+\d+\s+(?:seats?|vacanc(?:y|ies)|slots?)\s+(?:left|remaining)\b",
            r"\btoday\s+only\b",
        ],
    },
    {
        "name": "Rapid next-day interview pressure",
        "category": "phishing",
        "severity": 18,
        "patterns": [
            r"\b(?:interview|test|technical\s+round|assessment|walk[\s-]?in|reporting)\s*(?:time|timing|date|schedule|slot)?\s*[:\-]?\s*(?:is\s+)?(?:scheduled\s+)?(?:for\s+)?(?:tomorrow|today|within\s+24\s*hours?)\b",
            r"\b(?:interview|walk[\s-]?in)\s+(?:for\s+)?(?:tomorrow|today)\b",
            r"\bcome\s+for\s+(?:the\s+)?interview\s+(?:tomorrow|today)\b",
            r"\binterview\s+timing:?\s*\d+\b",
        ],
    },
    {
        "name": "Unexpected payment request",
        "category": "financial",
        "severity": 25,
        "patterns": [
            r"\brefundable\s+.*?\s+deposit\b",
            r"\bactivation\s+deposit\b",
            r"\bserver\s+activation\b",
            r"\bdeposit\s+of\s+[₹$]?\s*\d+",
            r"\bregistration\s+fee\b",
            r"\bprocessing\s+fee\b",
            r"\bpay\s+(?:now|first|in\s+advance)\b",
            r"\bsecurity\s+deposit\b",
            r"\btransfer\s+(?:money|funds)\b",
            r"\bsend\s+money\b",
            r"\bpay\s+to\s+receive\b",
            r"\bpay\s+.*?\s+to\s+unlock\b",
        ],
    },
    {
        "name": "Prize or reward bait",
        "category": "reward",
        "severity": 18,
        "patterns": [
            r"\byou\s+(?:have\s+)?won\b",
            r"\bclaim\s+your\s+(?:prize|reward)\b",
            r"\bfree\s+gift\b",
            r"\blucky\s+winner\b",
            r"\bcashback\s+waiting\b",
            r"\bclaim\s+.*?\s+reward\b",
        ],
    },
    {
        "name": "Credential or KYC request",
        "category": "phishing",
        "severity": 25,
        "patterns": [
            r"\bverify\s+your\s+(?:bank\s+)?account\b",
            r"\bupdate\s+your\s+kyc\b",
            r"\bkyc\s+expired\b",
            r"\bconfirm\s+your\s+password\b",
            r"\benter\s+your\s+password\b",
            r"\bverify\s+your\s+identity\b",
            r"\bclick\s+here\s+to\s+verify\b",
        ],
    },
    {
        "name": "Impersonation indicators",
        "category": "impersonation",
        "severity": 15,
        "patterns": [
            r"\bwe\s+are\s+from\s+(?:your\s+)?bank\b",
            r"\bpretending\s+to\s+be\b",
            r"\bon\s+behalf\s+of\s+(?:your\s+)?bank\b",
            r"\bcustoms\s+department\b",
            r"\bpolice\s+case\s+registered\b",
            r"\bdigital\s+arrest\b",
        ],
    },
    {
        "name": "Suspicious job offer",
        "category": "job",
        "severity": 18,
        "patterns": [
            r"\bno\s+prior\s+experience\b",
            r"\bworking\s+just\s+\d+\s+hours?\b",
            r"\bearn\s+[₹$]?\s*[\d,]+\s+.*?month\b",
            r"\b\d+\s+hours?\s+daily\b",
            r"\bno\s+interview\s+required\b",
            r"\bguaranteed\s+income\b",
            r"\bearn\s+.*?\s+per\s+day\b",
            r"\bpay\s+.*?\s+to\s+join\b",
            r"\bno\s+experience\s+needed\b",
            r"\bno\s+experience\s+required\b",
            r"\bno\s+(?:skills?|qualification|degree)\s+(?:required|needed)\b",
            r"\banyone\s+can\s+(?:apply|earn)\b",
            r"\b(?:simple|easy)\s+(?:tasks?|work)\b",
            r"\btask[\s-]based\b",
            r"\b(?:like|subscribe|rate|review)\b[\s\S]{0,30}\b(?:youtube|videos?|products?|reels?|posts?)\b",
        ],
    },
    {
        "name": "Anonymous recruiter or vague job portal",
        "category": "job",
        "severity": 18,
        "patterns": [
            r"\bonline\s+job\s+portal\b",
            r"\bjob\s+portal\b",
            r"\bdirect\s+company\s+hiring\b",
            r"\bhr\s+consultancy\b",
            r"\brecruitment\s+hub\b",
            r"\bcorporate\s+hiring\s+desk\b",
            r"\bdirect\s+hiring\b",
            r"\b(?:you\s+are\s+)?(?:invited|selected|shortlisted|eligible)\s+(?:to\s+)?proceed\s+with\s+(?:the\s+)?next\s+step\b",
            r"\b(?:you\s+have\s+been\s+|you\s+are\s+)?(?:selected|shortlisted|invited)\s+for\s+(?:the\s+)?(?:next\s+step|interview|round)\b",
            r"\bapplication\s+from\s+(?:the\s+)?(?:online\s+)?job\s+portal\b",
        ],
    },
    {
        "name": "Multiple clustered job roles in informal notice",
        "category": "job",
        "severity": 18,
        "patterns": [
            rf"\b{ROLES_PATTERN}\s*(?:[/,|]|\band\b|&)\s*{ROLES_PATTERN}\b",
            rf"\b{ROLES_PATTERN}\s*,\s*{ROLES_PATTERN}\s*(?:[/,|&]|\band\b)\s*{ROLES_PATTERN}\b",
        ],
    },
    {
        "name": "Unverified CV or resume solicitation on chat apps",
        "category": "job",
        "severity": 20,
        "patterns": [
            r"\b(?:share|send|forward|submit|drop|whatsapp)\s+(?:your\s+)?(?:cv|resume|biodata|profile|documents?)\s+(?:on|to|at|via|through|over)?\s*(?:this\s+)?(?:whats\s?app|telegram)(?:\s+number)?\b",
            r"\b(?:cv|resume)\s+(?:on|to|at)\s+(?:whats\s?app|telegram|this\s+number|\+?\d{10,12})\b",
            r"\bwhats\s?app\s+(?:your\s+)?(?:cv|resume)\b",
            r"\b(?:share|send|forward)\s+(?:your\s+)?(?:cv|resume)\b",
            r"\b(?:share|send)\s+(?:cv|resume)\b",
            r"\bwhatsapp\s+cv\b",
        ],
    },
    {
        "name": "Withheld interview address or venue",
        "category": "job",
        "severity": 25,
        "patterns": [
            # Active phrasing: provide / share / send / give the detailed interview address
            r"\b(?:provide|share|send|give|release|disclose)\s+(?:the\s+)?(?:detailed\s+|full\s+)?(?:interview\s+)?(?:address|venue|location)\b",
            # Passive phrasing: address will be shared / provided / sent
            r"\b(?:address|venue|location)\s+(?:will\s+be|is)\s+(?:shared|sent|given|provided|disclosed)\b",
            # Conditional withholding: address after/once cv/resume/reply
            r"\b(?:address|venue|location)\b[\s\S]{0,50}\b(?:after|once|upon)\b[\s\S]{0,40}\b(?:cv|resume|sharing|sending|confirm|received?)\b",
            r"\b(?:share|send)\s+(?:your\s+)?(?:cv|resume)\b[\s\S]{0,60}\b(?:provide|share|send|give)\s+(?:the\s+)?(?:detailed\s+)?(?:interview\s+)?(?:address|venue|location)\b",
            r"\b(?:share|send|forward)\s+(?:your\s+)?(?:cv|resume)\b[\s\S]{0,50}\bfor\s+(?:the\s+)?(?:detailed\s+|full\s+)?(?:interview\s+)?(?:address|venue|location)\b",
            r"\baddress\s+on\s+whats\s?app\b",
            r"\bshare\s+cv\s+for\s+address\b",
        ],
    },
    {
        "name": "Suspicious communication channel",
        "category": "other",
        "severity": 12,
        "patterns": [
            r"\bwhats\s?app[\s-]+only\b",
            r"\btelegram[\s-]+only\b",
            r"\b(?:contact|message|text|apply|reach|dm)\b[\s\S]{0,40}\b(?:whats\s?app|telegram)\b",
            r"\b(?:telegram|whatsapp)\s+(?:group|channel)\b",
            r"\bjoin\s+(?:our\s+|the\s+)?(?:telegram|whatsapp)\b",
            r"\btelegram:\s*@[\w]+",
            r"\bdo\s+not\s+tell\s+anyone\b",
            r"\bkeep\s+this\s+confidential\b",
            r"[\w.+-]+@(?:gmail|yahoo|outlook|hotmail|rediffmail)\.com",
        ],
    },
    {
        "name": "Upfront fee for a job",
        "category": "job",
        "severity": 35,
        "patterns": [
            r"(?:₹|rs\.?|inr)\s?\d[\d,]*\s*(?:/-)?\s*(?:as\s+|for\s+)?(?:a\s+|the\s+)?(?:\w+\s+){0,2}?(?:fee|fees|deposit|charges?)\b",
            r"\b(?:registration|training|kit|joining|onboarding|verification|security|processing|refundable)\s+(?:fee|fees|charges?|deposit|amount)\b",
            r"\b(?:pay|deposit|send|transfer)\b[\s\S]{0,40}(?:₹|rs\.?|inr)\s?\d",
        ],
    },
    {
        "name": "Unrealistic earnings",
        "category": "job",
        "severity": 25,
        "patterns": [
            r"(?:₹|rs\.?|inr)\s?\d[\d,]*\s*(?:/-)?\s*(?:per\s+day|a\s+day|/day|daily)\b",
            r"\bearn\s+up\s+to\b",
            r"\bdaily\s+(?:payout|payment|income|salary)\b",
            r"\bsame[\s-]day\s+(?:payment|payout|salary)\b",
            r"\bhigh\s+(?:income|salary|pay)\s+[\s\S]{0,20}(?:no|without)\s+(?:skills?|experience|qualification)\b",
        ],
    },
]


# Canonical official domains for prominent employers
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
}

# Free webmails, public hosting, shorteners and cloud storage domains never represent official company domains
USER_CONTENT_OR_SHORTENER_DOMAINS = {
    "github.io", "gitlab.io", "vercel.app", "netlify.app", "firebaseapp.com",
    "web.app", "pages.dev", "herokuapp.com", "render.com",
    "bit.ly", "tinyurl.com", "cutt.ly", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "shorturl.at",
    "drive.google.com", "docs.google.com", "forms.gle", "forms.office.com", "notion.site",
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "rediffmail.com",
    "proton.me", "protonmail.com", "icloud.com", "mail.com",
}

# Video conferencing, meeting, and professional networking platforms are valid interview links, not company lookalikes
EXCLUDED_LINK_DOMAINS = {
    "meet.google.com", "teams.microsoft.com", "zoom.us", "webex.com",
    "linkedin.com", "maps.google.com"
}

SUPPRESSED_BY_LEGITIMATE_GUARD = {
    "Rapid next-day interview pressure",
    "Anonymous recruiter or vague job portal",
    "Multiple clustered job roles in informal notice",
}


def extract_named_companies(text: str) -> list[str]:
    """Find corporate entities and named employers in text (excluding URL hosts/emails)."""
    if not text:
        return []
    # Strip URLs and emails so hostnames/handles aren't mistaken for named employers
    text_no_urls = re.sub(r"https?://\S+|www\.\S+|\b[A-Za-z0-9._%+-]+@\S+", " ", text)
    detected = []

    # Known company patterns
    known_patterns = [
        (r"\b(?:tcs|tata\s+consultancy(?:\s+services)?)\b", "tcs"),
        (r"\binfosys\b", "infosys"),
        (r"\bwipro\b", "wipro"),
        (r"\bzoho(?:\s+corporation)?\b", "zoho"),
        (r"\bcognizant\b", "cognizant"),
        (r"\baccenture\b", "accenture"),
        (r"\bmicrosoft\b", "microsoft"),
        (r"\bgoogle\b", "google"),
        (r"\bamazon\b", "amazon"),
        (r"\bibm\b", "ibm"),
        (r"\boracle\b", "oracle"),
        (r"\bdeloitte\b", "deloitte"),
        (r"\bcapgemini\b", "capgemini"),
        (r"\bhcl\b", "hcl"),
        (r"\btech\s+mahindra\b", "tech mahindra"),
        (r"\bflipkart\b", "flipkart"),
    ]
    for pattern, canonical in known_patterns:
        if re.search(pattern, text_no_urls, re.IGNORECASE):
            detected.append(canonical)

    # General corporate suffixes: e.g. "Acme Technologies Pvt Ltd", "Wayne Corp"
    general_patterns = [
        r"\b([A-Z][a-zA-Z0-9&.\s]{1,30}?)\s+(?:Limited|Ltd|Corporation|Corp|Technologies|Pvt(?:\s+Ltd)?|Private\s+Limited|Inc)\b",
        r"\b(?:at|with|from|joining)\s+([A-Z][a-zA-Z0-9&.\s]{1,25}(?:Ltd|Limited|Corp|Corporation|Inc|Technologies|Pvt|Private))\b",
        r"\bHR,\s*([A-Z][a-zA-Z0-9&.\s]{1,30})\b",
    ]
    for gp in general_patterns:
        for m in re.finditer(gp, text_no_urls, re.IGNORECASE):
            company_raw = m.group(1).strip()
            cleaned = re.sub(r"\b(?:Limited|Ltd|Corporation|Corp|Technologies|Pvt|Private|Inc|LLC|Solutions)\b", "", company_raw, flags=re.IGNORECASE).strip()
            if cleaned and len(cleaned) >= 3:
                detected.append(cleaned.lower())

    unique = []
    for d in detected:
        if d not in unique:
            unique.append(d)
    return unique


def extract_contacts(text: str) -> list[dict]:
    """
    Extract email addresses and URLs from text.
    Returns list of dicts:
      {'type': 'email'|'link', 'raw': str, 'reg_domain': str, 'domain_label': str, 'full_host': str}
    """
    if not text:
        return []
    contacts = []
    seen = set()

    # 1. Email addresses
    for m in re.finditer(r"\b[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b", text):
        raw = m.group(0)
        host = m.group(1).lower()
        ext = tldextract.extract(host)
        reg_domain = f"{ext.domain}.{ext.suffix}".lower()
        domain_label = ext.domain.lower()
        if reg_domain and (raw, reg_domain) not in seen:
            seen.add((raw, reg_domain))
            contacts.append({
                "type": "email",
                "raw": raw,
                "reg_domain": reg_domain,
                "domain_label": domain_label,
                "full_host": host,
            })

    # 2. URLs / Web links (including bare domains like careers.zoho.com)
    url_pattern = r"\b(?:https?://|www\.)[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?:/[^\s]*)?|\b[a-zA-Z0-9.-]+\.(?:com|org|net|in|co|xyz|io|tech|ai|biz|info)(?:/[^\s]*)?"
    for m in re.finditer(url_pattern, text, re.IGNORECASE):
        raw = m.group(0)
        if "@" in raw:
            continue
        clean_url = raw.rstrip(".,;:!?)'\"")
        host = clean_url.split("://")[-1].split("/")[0].split(":")[0].lower()
        if host.startswith("www."):
            host = host[4:]
        ext = tldextract.extract(host)
        reg_domain = f"{ext.domain}.{ext.suffix}".lower()
        domain_label = ext.domain.lower()
        if reg_domain and (clean_url, reg_domain) not in seen:
            seen.add((clean_url, reg_domain))
            contacts.append({
                "type": "link",
                "raw": clean_url,
                "reg_domain": reg_domain,
                "domain_label": domain_label,
                "full_host": host,
            })

    return contacts


def does_domain_correspond_to_company(reg_domain: str, domain_label: str, company: str) -> bool:
    """
    Check if a domain corresponds to a named company.
    Judged by:
    1. Official domain mapping in COMPANY_OFFICIAL_DOMAINS
    2. Exact token match between company name and domain label
    Lookalikes (e.g. tcs-hiring.in, infosys-careers.in, zoho-jobs.xyz) MUST NOT qualify.
    User content / shortener / free webmail domains MUST NOT qualify.
    """
    if not reg_domain or not company:
        return False

    if reg_domain in USER_CONTENT_OR_SHORTENER_DOMAINS:
        return False

    company_lower = company.lower()

    # 1. Known official domains check
    for comp_key, official_domains in COMPANY_OFFICIAL_DOMAINS.items():
        if comp_key == company_lower or comp_key in company_lower or company_lower in comp_key:
            if reg_domain in official_domains:
                return True

    # 2. Token match between company name and domain label
    comp_tokens = [t for t in re.split(r"[\s&.-]+", company_lower) if t and t not in (
        "ltd", "limited", "corp", "corporation", "inc", "pvt", "private", "technologies", "tech", "solutions"
    )]

    for token in comp_tokens:
        if len(token) >= 3 and domain_label == token:
            return True

    return False


def is_legitimate_recruitment_context(text: str) -> bool:
    """
    Tightened legitimate-context guard:
    Returns True only when the email domain or link domain's registrable domain
    actually corresponds to the named company (e.g. 'Infosys' with infosys.com, 'Zoho' with zoho.com).
    A company name or suffix alone never counts.
    Lookalikes (tcs-hiring.in, infosys-careers.in, zoho-jobs.xyz) do not qualify.
    """
    if not text:
        return False

    named_companies = extract_named_companies(text)
    if not named_companies:
        return False

    contacts = extract_contacts(text)
    if not contacts:
        return False

    for contact in contacts:
        reg_domain = contact["reg_domain"]
        domain_label = contact["domain_label"]
        for company in named_companies:
            if does_domain_correspond_to_company(reg_domain, domain_label, company):
                return True

    return False


def get_rule_analysis(text: str) -> dict:
    """Return matched rule evidence, categories, and a bounded heuristic score."""
    text = text or ""
    matches = []
    categories = set()
    seen = set()

    is_legit_context = is_legitimate_recruitment_context(text)

    for rule in RULES:
        # Legitimate-context guard: may ONLY suppress the 3 allowed rules
        if is_legit_context and rule["name"] in SUPPRESSED_BY_LEGITIMATE_GUARD:
            continue

        for pattern in rule["patterns"]:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                evidence = match.group(0)
                key = (rule["name"], evidence.lower())

                if key not in seen:
                    seen.add(key)
                    matches.append({
                        "rule": rule["name"],
                        "category": rule["category"],
                        "severity": rule["severity"],
                        "evidence": evidence,
                    })
                    categories.add(rule["category"])

                break

    # Contact-Domain Mismatch Indicator:
    # When text names a company AND contains an email address or link whose registrable domain
    # does not correspond to that company, add flag: "Contact domain does not match the named company: <domain>"
    # Must fire when guard is on or off.
    named_companies = extract_named_companies(text)
    if named_companies:
        contacts = extract_contacts(text)
        flagged_mismatch_domains = set()

        for contact in contacts:
            reg_domain = contact["reg_domain"]
            full_host = contact["full_host"]

            # Exclude standard video meeting/conferencing links and standard profile links
            if contact["type"] == "link" and any(platform in full_host or platform in reg_domain for platform in EXCLUDED_LINK_DOMAINS):
                continue

            if reg_domain in flagged_mismatch_domains:
                continue

            corresponds = any(
                does_domain_correspond_to_company(reg_domain, contact["domain_label"], comp)
                for comp in named_companies
            )

            if not corresponds:
                flagged_mismatch_domains.add(reg_domain)
                rule_name = f"Contact domain does not match the named company: {reg_domain}"
                matches.append({
                    "rule": rule_name,
                    "category": "job",
                    "severity": 25,
                    "evidence": contact["raw"],
                })
                categories.add("job")

    score = min(100, sum(item["severity"] for item in matches))

    # OTP/PIN/CVV requests are especially concerning.
    if any(item["rule"] == "OTP or PIN request" for item in matches):
        score = max(score, 70)

    # Asking a job seeker to pay upfront is the strongest job-scam signal.
    if any(item["rule"] == "Upfront fee for a job" for item in matches):
        score = max(score, 71)

    # Several different signals, including a money signal, together mean High.
    rules_hit = {item["rule"] for item in matches}
    money_rules = {"Upfront fee for a job", "Unrealistic earnings", "Unexpected payment request"}
    if len(rules_hit) >= 3 and rules_hit & money_rules:
        score = max(score, 71)

    # Multiple recruitment fraud signals together indicate significant threat
    recruitment_fraud_rules = {
        "Unverified CV or resume solicitation on chat apps",
        "Withheld interview address or venue",
        "Anonymous recruiter or vague job portal",
        "Rapid next-day interview pressure",
        "Multiple clustered job roles in informal notice",
    }
    recruitment_matches = [
        item for item in matches
        if item["rule"] in recruitment_fraud_rules or item["rule"].startswith("Contact domain does not match")
    ]
    recruitment_hits = {item["rule"] for item in recruitment_matches}

    # Requirement 3: The 4+ signals floor (75) must only count signals with severity >= 20
    high_sev_recruitment_hits = {
        item["rule"] for item in recruitment_matches
        if item["severity"] >= 20
    }

    if len(high_sev_recruitment_hits) >= 4:
        score = max(score, 75)
    elif len(recruitment_hits) >= 3:
        score = max(score, 65)
    elif len(recruitment_hits) >= 2:
        score = max(score, 45)

    return {
        "rule_score": score,
        "categories": sorted(categories),
        "matches": matches,
        "rule_flags": [
            f"{item['rule']}: matched '{item['evidence']}'"
            for item in matches
        ],
    }

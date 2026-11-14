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

MEETING_DOMAINS = {
    "meet.google.com", "teams.microsoft.com", "zoom.us", "webex.com"
}

def extract_named_companies(text: str) -> list[str]:
    """Find company names in text."""
    detected = []
    # Known companies
    known_patterns = [
        (r"\b(tcs|tata\s+consultancy(?:\s+services)?)\b", "tcs"),
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
        if re.search(pattern, text, re.IGNORECASE):
            detected.append(canonical)

    # General corporate suffixes: e.g. "Acme Technologies Pvt Ltd", "Wayne Corp"
    general_patterns = [
        r"\b([A-Z][a-zA-Z0-9&.\s]{1,30}?)\s+(?:Limited|Ltd|Corporation|Corp|Technologies|Pvt(?:\s+Ltd)?|Private\s+Limited|Inc)\b",
        r"\b(?:at|with|from|joining)\s+([A-Z][a-zA-Z0-9&.\s]{1,25}(?:Ltd|Limited|Corp|Corporation|Inc|Technologies|Pvt|Private))\b",
    ]
    for gp in general_patterns:
        for m in re.finditer(gp, text, re.IGNORECASE):
            company_raw = m.group(1).strip()
            # Clean up suffix words to find root name
            cleaned = re.sub(r"\b(?:Limited|Ltd|Corporation|Corp|Technologies|Pvt|Private|Inc|LLC|Solutions)\b", "", company_raw, flags=re.IGNORECASE).strip()
            if cleaned and len(cleaned) >= 3:
                detected.append(cleaned.lower())

    # Deduplicate while preserving order
    unique = []
    for d in detected:
        if d not in unique:
            unique.append(d)
    return unique

def extract_contacts(text: str):
    """
    Extract emails and web links from text.
    Returns list of dicts: {'type': 'email'|'link', 'raw': str, 'reg_domain': str, 'domain_label': str, 'full_host': str}
    """
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
        # Skip if part of an email address already found
        if "@" in raw:
            continue
        # Strip trailing punctuation common in English sentences
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
    Check if domain corresponds to company.
    Judged by:
    1. Direct match in COMPANY_OFFICIAL_DOMAINS
    2. Exact token match between company name and domain label
    Lookalikes (e.g. tcs-hiring.in, infosys-careers.in, zoho-jobs.xyz) MUST NOT qualify.
    User content / shortener / free webmail domains MUST NOT qualify.
    """
    if not reg_domain or not company:
        return False

    if reg_domain in USER_CONTENT_OR_SHORTENER_DOMAINS:
        return False

    # 1. Check known company mapping
    company_lower = company.lower()
    for comp_key, official_domains in COMPANY_OFFICIAL_DOMAINS.items():
        if comp_key == company_lower or comp_key in company_lower or company_lower in comp_key:
            if reg_domain in official_domains:
                return True

    # 2. Token match between company name and domain label
    # e.g., company "Zoho Corporation" -> token "zoho", domain label "zoho" -> match!
    # "tcs-hiring" != "tcs", "infosys-careers" != "infosys"
    comp_tokens = [t for t in re.split(r"[\s&.-]+", company_lower) if t and t not in (
        "ltd", "limited", "corp", "corporation", "inc", "pvt", "private", "technologies", "tech", "solutions"
    )]

    for token in comp_tokens:
        if len(token) >= 3 and domain_label == token:
            # Exact match of domain label with primary company token
            return True

    return False

# Quick test
test_cases = [
    ("TCS", "tcs.com", "tcs", True),
    ("TCS", "tcs-hiring.in", "tcs-hiring", False),
    ("Infosys Limited", "infosys.com", "infosys", True),
    ("Infosys Limited", "infosys-careers.in", "infosys-careers", False),
    ("Zoho Corporation", "zoho.com", "zoho", True),
    ("Zoho Corporation", "zoho-jobs.xyz", "zoho-jobs", False),
    ("Zoho Corporation", "careers.zoho.com", "zoho", True),
]

for comp, reg, label, expected in test_cases:
    actual = does_domain_correspond_to_company(reg, label, comp)
    assert actual == expected, f"Failed for {comp}, {reg}: expected {expected}, got {actual}"

print("All assertion tests passed successfully!")

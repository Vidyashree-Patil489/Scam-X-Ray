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
    "linkedin.com", "maps.google.com"
}

SUPPRESSED_BY_LEGITIMATE_GUARD = {
    "Rapid next-day interview pressure",
    "Anonymous recruiter or vague job portal",
    "Multiple clustered job roles in informal notice",
}

def extract_named_companies(text: str) -> list[str]:
    if not text:
        return []
    detected = []
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
        if re.search(pattern, text, re.IGNORECASE):
            detected.append(canonical)

    general_patterns = [
        r"\b([A-Z][a-zA-Z0-9&.\s]{1,30}?)\s+(?:Limited|Ltd|Corporation|Corp|Technologies|Pvt(?:\s+Ltd)?|Private\s+Limited|Inc)\b",
        r"\b(?:at|with|from|joining)\s+([A-Z][a-zA-Z0-9&.\s]{1,25}(?:Ltd|Limited|Corp|Corporation|Inc|Technologies|Pvt|Private))\b",
        r"\bHR,\s*([A-Z][a-zA-Z0-9&.\s]{1,30})\b",
    ]
    for gp in general_patterns:
        for m in re.finditer(gp, text, re.IGNORECASE):
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
    if not text:
        return []
    contacts = []
    seen = set()

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
    if not reg_domain or not company:
        return False

    if reg_domain in USER_CONTENT_OR_SHORTENER_DOMAINS:
        return False

    company_lower = company.lower()
    for comp_key, official_domains in COMPANY_OFFICIAL_DOMAINS.items():
        if comp_key == company_lower or comp_key in company_lower or company_lower in comp_key:
            if reg_domain in official_domains:
                return True

    comp_tokens = [t for t in re.split(r"[\s&.-]+", company_lower) if t and t not in (
        "ltd", "limited", "corp", "corporation", "inc", "pvt", "private", "technologies", "tech", "solutions"
    )]

    for token in comp_tokens:
        if len(token) >= 3 and domain_label == token:
            return True

    return False

def is_legitimate_recruitment_context(text: str) -> bool:
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

# Import rules from rule_engine
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from rule_engine import RULES

def test_rule_analysis(text: str, guard_active: bool = True) -> dict:
    text = text or ""
    matches = []
    categories = set()
    seen = set()

    is_legit = is_legitimate_recruitment_context(text) if guard_active else False

    for rule in RULES:
        if is_legit and rule["name"] in SUPPRESSED_BY_LEGITIMATE_GUARD:
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

    # Mismatch rule
    named_companies = extract_named_companies(text)
    if named_companies:
        contacts = extract_contacts(text)
        flagged_mismatch_domains = set()

        for contact in contacts:
            reg_domain = contact["reg_domain"]
            full_host = contact["full_host"]

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

    if any(item["rule"] == "OTP or PIN request" for item in matches):
        score = max(score, 70)
    if any(item["rule"] == "Upfront fee for a job" for item in matches):
        score = max(score, 71)

    rules_hit = {item["rule"] for item in matches}
    money_rules = {"Upfront fee for a job", "Unrealistic earnings", "Unexpected payment request"}
    if len(rules_hit) >= 3 and rules_hit & money_rules:
        score = max(score, 71)

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
        "is_legit_guard": is_legit,
    }

# Test fixtures A through I
from test_fixtures_mock import FIXTURES, OCR_VARIANTS

print("=== TESTING FIXTURES ===")
for k, t in FIXTURES.items():
    res = test_rule_analysis(t)
    matched_names = [m["rule"] for m in res["matches"]]
    print(f"Fixture {k}: Guard={res['is_legit_guard']}, RuleScore={res['rule_score']}, Matches={matched_names}")

print("\n=== TESTING OCR VARIANTS OF FIXTURE A ===")
for k, t in OCR_VARIANTS.items():
    res = test_rule_analysis(t)
    matched_names = [m["rule"] for m in res["matches"]]
    print(f"Variant {k}: Guard={res['is_legit_guard']}, RuleScore={res['rule_score']}, Matches={matched_names}")

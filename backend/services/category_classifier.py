"""
Threat Classification and Indicator Extraction for ScamXRay.
Derives deterministic categories, classification criteria, radar indicator scores,
and URL legitimacy verdicts from actual rule matches, model scores, and URL inspections.
"""

def classify_threat(
    text: str,
    url: str,
    matches: list,
    categories: list,
    url_result: dict,
    ml_score: float,
    risk_score: int,
) -> dict:
    """
    Returns:
    - scam_category: String
    - classification_criteria: List[str]
    - radar_indicators: Dict[str, int]
    - url_verdict: String ('Likely Legitimate' | 'Suspicious / Potentially Fraudulent' | 'Unverified')
    - url_verdict_reason: String
    """
    text = (text or "").strip()
    url = (url or "").strip()
    text_lower = text.lower()
    matches = matches or []
    categories = categories or []
    url_result = url_result or {}
    url_flags = url_result.get("url_flags", [])
    raw_url_score = url_result.get("url_score")
    url_score = int(raw_url_score) if raw_url_score is not None else 0
    hostname = url_result.get("hostname", "")
    is_trusted = bool(url_result.get("is_trusted", False))
    is_reserved_example = bool(url_result.get("is_reserved_example", False))

    # 1. URL Verdict Determination (Three distinct categories: Likely Legitimate, Suspicious / Potentially Fraudulent, Unverified)
    url_verdict = None
    url_verdict_reason = None

    if url:
        if not hostname:
            url_verdict = "Unverified"
            url_verdict_reason = (
                "Could not extract a valid resolvable hostname from this URL. "
                "The link may be malformed or invalid."
            )
        elif is_reserved_example:
            url_verdict = "Unverified"
            url_verdict_reason = (
                f"The domain '{hostname}' is an RFC 2606 / RFC 6761 reserved example domain "
                "designated exclusively for documentation and testing. It does not represent an active, "
                "verified commercial or business entity."
            )
        elif is_trusted:
            url_verdict = "Likely Legitimate"
            url_verdict_reason = (
                f"The domain '{hostname}' is an established, recognized organization in ScamXRay's "
                "verified registry, operating over secure HTTPS with no structural deception detected."
            )
        elif url_score >= 60:
            url_verdict = "Suspicious / Potentially Fraudulent"
            reasons = "; ".join(url_flags[:3]) if url_flags else "Multiple critical deception indicators detected."
            url_verdict_reason = (
                f"The link exhibits high-risk indicators commonly associated with cyber threats: {reasons}. "
                "Do not enter passwords, payment details, or personal information."
            )
        elif url_score >= 20:
            url_verdict = "Suspicious / Potentially Fraudulent"
            reasons = "; ".join(url_flags[:2]) if url_flags else "Cautionary structural indicators found."
            url_verdict_reason = (
                f"The link contains suspicious characteristics: {reasons}. "
                "Exercise caution and verify the destination independently."
            )
        else:
            url_verdict = "Unverified"
            url_verdict_reason = (
                f"The domain '{hostname}' has no obvious malicious patterns in its syntax, but it is not "
                "a recognized verified business in ScamXRay's trusted registry. Without external registry, "
                "SSL certificate, or reputation telemetry, legitimacy cannot be confirmed."
            )

    # 2. Derive Radar Indicator Scores (0-100) using honest detection signals
    urgency_matches = [
        m for m in matches
        if m.get("rule") in ["Urgency or threat", "Rapid next-day interview pressure"]
    ]
    urgency_score = min(100, sum(m.get("severity", 0) for m in urgency_matches) * 2) if urgency_matches else 0

    payment_matches = [
        m for m in matches
        if m.get("rule") in ["Unexpected payment request", "Upfront fee for a job"]
    ]
    payment_score = min(100, sum(m.get("severity", 0) for m in payment_matches) * 2) if payment_matches else 0

    impersonation_matches = [
        m for m in matches
        if m.get("rule") in ["Impersonation indicators", "Anonymous recruiter or vague job portal"]
    ]
    brand_imitated = any("imitates" in f for f in url_flags)
    impersonation_score = 0
    if impersonation_matches:
        impersonation_score = min(100, sum(m.get("severity", 0) for m in impersonation_matches) * 2)
    if brand_imitated:
        impersonation_score = max(impersonation_score, 75)

    radar_indicators = {
        "urgency": urgency_score,
        "payment": payment_score,
        "url_risk": url_score if url else None,
        "ml_score": int(ml_score) if ml_score is not None else 0,
        "impersonation": impersonation_score,
    }

    # 3. Deterministic Scam Category Classification
    matched_rules = {m.get("rule") for m in matches}
    scam_category = "Unclassified"
    criteria = []

    # Case A: URL-only scan
    if url and not text:
        if is_reserved_example:
            scam_category = "Unverified (Reserved Example Domain)"
            criteria = ["Domain is reserved under RFC 2606 for documentation/testing", "Not a verified commercial entity"]
        elif is_trusted:
            scam_category = "Likely Legitimate URL"
            criteria = ["Recognized authoritative domain in trusted registry", "Secure HTTPS protocol verified", "No deceptive syntax"]
        elif any("imitates" in f for f in url_flags):
            scam_category = "Brand Impersonation Link"
            criteria = [f for f in url_flags if "imitates" in f]
        elif any("kyc" in f or "login" in f or "verify" in f or "otp" in f for f in url_flags):
            scam_category = "Phishing Link"
            criteria = [f for f in url_flags if any(k in f for k in ["kyc", "login", "verify", "otp"])]
        elif any("Telegram" in f or "WhatsApp" in f for f in url_flags):
            scam_category = "Suspicious Communication Link"
            criteria = ["Link directs to unofficial messaging platform (Telegram/WhatsApp)."]
        elif url_score >= 60:
            scam_category = "Potentially Fraudulent Link"
            criteria = url_flags[:3]
        elif url_score >= 20:
            scam_category = "Suspicious Link"
            criteria = url_flags[:2]
        else:
            scam_category = "Unverified URL"
            criteria = ["Domain syntax is standard, but domain is not in verified trusted registry", "Independent reputation verification required"]

    # Case B: Text or OCR scan
    else:
        recruitment_fraud_rules = {
            "Unverified CV or resume solicitation on chat apps",
            "Withheld interview address or venue",
            "Anonymous recruiter or vague job portal",
            "Rapid next-day interview pressure",
            "Multiple clustered job roles in informal notice",
        }
        recruitment_hits = matched_rules & recruitment_fraud_rules

        # Check for Upfront Fee Job Scams
        if "Upfront fee for a job" in matched_rules or (
            "Unexpected payment request" in matched_rules and any(w in text_lower for w in ["job", "salary", "hiring", "interview", "wfh", "data entry"])
        ):
            scam_category = "Fake Job Posting"
            for m in matches:
                if m.get("category") == "job" or m.get("rule") in ["Upfront fee for a job", "Unexpected payment request", "Unrealistic earnings"]:
                    criteria.append(f"{m.get('rule')}: matched '{m.get('evidence')}'")
            if not criteria:
                criteria.append("Upfront onboarding deposit or processing fee requested.")

        # Check for Recruitment Scam / Informal Job Bait (e.g. WhatsApp CV solicitation, withheld venue)
        elif len(recruitment_hits) >= 2 or "Withheld interview address or venue" in matched_rules or "Unverified CV or resume solicitation on chat apps" in matched_rules:
            scam_category = "Potential Recruitment Scam"
            for m in matches:
                if m.get("rule") in recruitment_fraud_rules or m.get("category") == "job":
                    criteria.append(f"{m.get('rule')}: matched '{m.get('evidence')}'")
            if not criteria:
                criteria.append("Suspicious informal recruitment cues: CV requested via messaging app with withheld address.")

        # Check Internship Scam
        elif any(w in text_lower for w in ["internship", "intern", "stipend"]) and (
            recruitment_hits or "Suspicious job offer" in matched_rules or "Unrealistic earnings" in matched_rules
        ):
            scam_category = "Internship Scam"
            for m in matches:
                if m.get("category") == "job" or m.get("rule") in recruitment_fraud_rules:
                    criteria.append(f"{m.get('rule')}: matched '{m.get('evidence')}'")
            if not criteria:
                criteria.append("Internship opportunity conditioned on payment or unofficial communication channels.")

        # Suspicious Job Offer (General)
        elif "Suspicious job offer" in matched_rules or "Unrealistic earnings" in matched_rules:
            scam_category = "Suspicious Job Offer"
            for m in matches:
                if m.get("category") == "job":
                    criteria.append(f"{m.get('rule')}: matched '{m.get('evidence')}'")

        # Identity Theft Attempt
        elif "OTP or PIN request" in matched_rules or (
            "Credential or KYC request" in matched_rules
            and any(w in text_lower for w in ["aadhaar", "pan", "identity", "id proof", "passport", "bank details"])
        ):
            scam_category = "Identity Theft Attempt"
            for m in matches:
                if m.get("rule") in ["OTP or PIN request", "Credential or KYC request"]:
                    criteria.append(f"Sensitive credentials requested: matched '{m.get('evidence')}'")

        # Phishing
        elif "Credential or KYC request" in matched_rules or any("imitates" in f for f in url_flags):
            scam_category = "Phishing"
            for m in matches:
                if m.get("rule") == "Credential or KYC request":
                    criteria.append(f"Credential harvesting or fake verification prompt: matched '{m.get('evidence')}'")
            for f in url_flags:
                if "imitates" in f:
                    criteria.append(f)

        # Impersonation
        elif "Impersonation indicators" in matched_rules or any("imitates" in f for f in url_flags):
            scam_category = "Impersonation"
            for m in matches:
                if m.get("rule") == "Impersonation indicators":
                    criteria.append(f"Authority impersonation: matched '{m.get('evidence')}'")

        # Prize or Lottery Scam
        elif "Prize or reward bait" in matched_rules:
            scam_category = "Prize or Lottery Scam"
            for m in matches:
                if m.get("rule") == "Prize or reward bait":
                    criteria.append(f"Prize bait: matched '{m.get('evidence')}'")

        # Investment Scam / Financial Fraud
        elif any(w in text_lower for w in ["crypto", "forex", "trading", "investment", "guaranteed profit", "double your"]) or "Unexpected payment request" in matched_rules:
            if any(w in text_lower for w in ["crypto", "forex", "trading", "investment"]):
                scam_category = "Investment Scam"
                criteria.append("Unregulated high-yield investment scheme or trading promises.")
            else:
                scam_category = "Financial Fraud"
                for m in matches:
                    if m.get("rule") == "Unexpected payment request":
                        criteria.append(f"Advance fee demand: matched '{m.get('evidence')}'")

        # Suspicious Communication
        elif "Suspicious communication channel" in matched_rules or "Urgency or threat" in matched_rules:
            scam_category = "Suspicious Communication"
            for m in matches:
                criteria.append(f"{m.get('rule')}: matched '{m.get('evidence')}'")

        # Fallback
        else:
            if risk_score >= 30:
                scam_category = "Suspicious Communication"
                criteria.append(f"Potential threat cues flagged with risk score {risk_score}/100.")
            else:
                scam_category = "Unclassified"
                criteria.append("No explicit scam indicators or high-risk rule patterns matched.")

    return {
        "scam_category": scam_category,
        "classification_criteria": criteria,
        "radar_indicators": radar_indicators,
        "url_verdict": url_verdict,
        "url_verdict_reason": url_verdict_reason,
    }

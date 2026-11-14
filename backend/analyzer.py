import os
import json
import re
from urllib.parse import urlparse

from groq import Groq
from dotenv import load_dotenv

load_dotenv()

_api_key = os.getenv("GROQ_API_KEY")
_client = Groq(api_key=_api_key) if _api_key else None
MODEL = "openai/gpt-oss-20b"

FALLBACK = {
    "explanation": "We couldn't generate an AI explanation right now. Please review the detected red flags carefully.",
    "safety_tips": [
        "Never pay any fee to get a job. Real employers don't charge you.",
        "Verify the company on its official website and LinkedIn.",
        "Be careful if they only talk to you on WhatsApp or Telegram.",
    ],
    "llm_score": None,
}


def _build_prompt(job_text, rule_flags, ml_score, is_ocr=False):
    flags_text = "\n".join(f"- {f}" for f in rule_flags) if rule_flags else "None detected"

    visual_instruction = (
        "CRITICAL VISUAL LIMITATION: You are analyzing plain extracted text ONLY. "
        "You CANNOT see images, graphics, colors, document layout, letterheads, typography, stamps, watermarks, logos, or sender avatars. "
        "NEVER make claims about visual elements you cannot see (such as logos, letterhead design, image quality, blurriness, graphic styling, or sender profile pictures). "
        "Confine your analysis and reasoning strictly to the literal text words provided."
    )

    return f"""You are a scam safety assistant for college students in India.

Content to check (job posting, message, or URL):
\"\"\"
{job_text[:3000]}
\"\"\"

IMPORTANT: This text may come from OCR of a screenshot or poster. OCR often produces garbled words, stray symbols, missing headings and broken line order. Never treat messy formatting, strange characters or missing text as a warning sign. Judge only the real content: what is asked of the person, money, contact channels, urgency, salary promises, and how professional the details are.

{visual_instruction}

Red flags detected by rules:
{flags_text}

ML similarity to known fake postings (0-100). Weak signal, trained mostly on US data. If no red flags were detected by rules, do not call it a scam based on this alone, say it needs verification: {ml_score}

Respond with ONLY a JSON object, no markdown, no extra text, in exactly this format:
{{"risk_score": 0,
  "explanation": "a detailed explanation, 6 to 8 sentences",
  "safety_tips": ["tip 1", "tip 2", "tip 3"]}}

risk_score is an integer 0-100 of how likely this is a scam, using your own judgment of the content and the flags.

The explanation must cover, in simple student-friendly language:
1. Your overall verdict and why.
2. What looks normal or reassuring (if anything).
3. What looks suspicious (if anything), quoting the exact phrases.
4. What the student should verify before replying or paying anything.
Do not repeat the safety tips inside the explanation.

Give exactly 3 actionable safety tips.
Never state or guess any company's or bank's official domain name. Tell the user to find the official site themselves via a search engine or the app, or to use the phone number on their bank card."""


def strip_visual_claims(text: str) -> str:
    """
    Strips sentences that make claims about visual elements (logos, letterheads,
    layout, image quality, sender profile) that plain extracted OCR text cannot see.
    """
    if not text:
        return text
    sentences = re.split(r'(?<=[.!?])\s+', text.strip())
    visual_pattern = re.compile(
        r'\b(logos?|letterheads?|watermarks?|stamps?|seals?|profile pictures?|avatars?|image quality|visual layout|blurry text|graphics?)\b',
        re.IGNORECASE
    )
    cleaned = [s for s in sentences if not visual_pattern.search(s)]
    return " ".join(cleaned) if cleaned else text


def get_claude_explanation(job_text, rule_flags, ml_score, is_ocr=False):
    if not _client:
        return FALLBACK
    prompt = _build_prompt(job_text, rule_flags, ml_score, is_ocr=is_ocr)

    try:
        response = _client.chat.completions.create(
            model=MODEL,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.2,
            max_tokens=2500,
            reasoning_effort="low",
        )

        raw_text = (response.choices[0].message.content or "").strip()

        match = re.search(r"\{.*\}", raw_text, re.DOTALL)
        if not match:
            print("AI raw output (no JSON found):", repr(raw_text))
            return FALLBACK

        try:
            data = json.loads(match.group(0))
        except json.JSONDecodeError:
            print("AI raw output (bad JSON):", repr(raw_text))
            return FALLBACK

        explanation = str(data.get("explanation", "")).strip() or FALLBACK["explanation"]
        if is_ocr:
            explanation = strip_visual_claims(explanation)

        tips = data.get("safety_tips", [])
        if not isinstance(tips, list):
            tips = []
        tips = [str(t).strip() for t in tips if str(t).strip()][:3]

        try:
            llm_score = max(0, min(100, int(round(float(data.get("risk_score"))))))
        except (TypeError, ValueError):
            llm_score = None

        return {
            "explanation": explanation,
            "safety_tips": tips or FALLBACK["safety_tips"],
            "llm_score": llm_score,
        }
    except Exception as e:
        print("AI generation failed:", str(e))
        return FALLBACK


# =====================================================================
# URL-SPECIFIC EVIDENCE-BASED AI EXPLANATION ENGINE
# =====================================================================

def _build_templated_url_explanation(url: str, verdict: str, threat_score: int, indicators: list, verification_checks: list, is_reserved: bool = False) -> str:
    """Deterministic, factual explanation grounded solely in verified findings using exact statuses."""
    performed = [c["name"] for c in verification_checks if c.get("status") == "performed"]
    failed = [c["name"] for c in verification_checks if c.get("status") == "failed"]
    not_performed = [c["name"] for c in verification_checks if c.get("status") == "not_performed"]

    status_items = []
    if performed:
        status_items.append(f"Verification checks performed: {', '.join(performed)}.")
    if failed:
        status_items.append(f"Checks failed: {', '.join(failed)}.")
    if not_performed:
        status_items.append(f"Checks not performed: {', '.join(not_performed)}.")
    status_summary = " ".join(status_items)

    if verdict == "Suspicious / Potentially Fraudulent":
        indicator_summary = "; ".join(f"{i['description']} ('{i['value']}')" for i in indicators[:2])
        return (
            f"Structural analysis of '{url}' identified {len(indicators)} significant threat indicator(s): {indicator_summary}. "
            f"The computed threat score is {threat_score}/100 based directly on these indicators. {status_summary} "
            "Interaction with this link is not advised."
        )
    elif verdict == "Likely Legitimate":
        return (
            f"The URL '{url}' passed positive verification checks with zero structural threat indicators. "
            f"{status_summary} Valid TLS encryption and established domain registration were confirmed. "
            "Basic checks passed; this is not a guarantee of safety."
        )
    else:  # Unverified
        if is_reserved or any("example" in c.get("details", "").lower() for c in verification_checks):
            return (
                f"The domain in '{url}' is an RFC 2606 / RFC 6761 reserved example domain designated exclusively for documentation and testing. "
                f"It does not represent an active commercial website. No threat indicators were detected in the URL structure. {status_summary}"
            )
        if indicators:
            ind_desc = "; ".join(f"{i['description']} ('{i['value']}')" for i in indicators[:2])
            return (
                f"Structural analysis of '{url}' identified {len(indicators)} caution indicator(s): {ind_desc}. "
                f"Threat signals remain below the threshold for automated fraudulent classification. {status_summary} "
                "Domain remains unverified; verify the organization independently."
            )
        return (
            f"No threat indicators were detected in the URL structure of '{url}'. However, positive verification evidence is incomplete: {status_summary} "
            "Absence of overt attack syntax does not prove legitimacy. Exercise caution before entering credentials."
        )


def _build_url_safety_tips(verdict: str, indicators: list, is_reserved: bool = False, url: str = "") -> list[str]:
    if is_reserved:
        return [
            "This domain is an RFC-reserved example namespace designated exclusively for documentation and testing.",
            "Reserved example domains do not host active commercial applications or credentials prompts; no action is required.",
            "If this link appeared in a message claiming to be an active portal, treat the communication as a placeholder or spoofing test.",
        ]

    # Likely Legitimate gets at most two lines
    if verdict == "Likely Legitimate":
        return [
            "Confirm that the browser address bar displays the expected domain name without typos.",
            "Ensure the site uses a secure HTTPS connection before submitting any data.",
        ]

    tips = []
    ind_ids = {i.get("id") for i in indicators}
    parsed = urlparse(url if "://" in url else "http://" + url) if url else None
    h_lower = (parsed.hostname or "").lower() if parsed else ""
    p_lower = (parsed.path or "").lower() if parsed else ""

    # 1. Brand lookalike
    if "brand_lookalike_domain" in ind_ids or "subdomain_brand_spoof" in ind_ids:
        tips.append("This link resembles a known brand. Type the official address yourself in your browser or use the official mobile app; do not use this link.")

    # 2. Forms / Chat user-content platforms
    is_form_or_chat = any(w in h_lower for w in ["forms.gle", "t.me", "wa.me", "chat.whatsapp.com"]) or ("docs.google.com" in h_lower and "form" in p_lower)
    if is_form_or_chat:
        tips.append("Job offers or communications that move you to an online form, Telegram, or WhatsApp for 'registration' are a common scam pattern; confirm the company independently.")
    elif "user_content_platform" in ind_ids:
        tips.append("This page is hosted on an open user-content platform where anyone can publish content; verify the individual or organization through independent channels.")

    # 3. New domain
    if "new_domain" in ind_ids:
        tips.append("This domain was registered very recently. Exercise extreme caution before providing any personal information or credentials.")

    # 4. Redirect parameter
    if "external_redirect_param" in ind_ids:
        tips.append("This link uses an open redirect parameter that can forward you to an external website. Ensure you remain on the intended destination.")

    if not tips:
        if verdict == "Suspicious / Potentially Fraudulent":
            tips.append("Do not enter passwords, credit cards, or personal credentials on this link.")
            tips.append("Verify the destination domain directly through official search or verified apps.")
        else:
            tips.append("Verify the authenticity of unknown domains through independent business registries.")
            tips.append("Do not enter sensitive corporate or financial credentials on unverified websites.")

    return tips[:3]


def validate_url_ai_output(ai_exp: str, verdict: str, indicators: list, verification_checks: list = None, is_reserved: bool = False, fallback: str = "") -> str:
    """
    Validate LLM explanation text against deterministic evidence.
    1. Discards text if it claims fraud without critical/high indicators.
    2. Discards text if it flags query parameters without an external redirect indicator.
    3. Discards text if it calls a check that was not_performed 'failed'.
    4. Discards text if it uses the word 'reserved' when is_reserved is False.
    """
    fraud_keywords = ["scam", "fraud", "phishing", "malicious", "high risk", "dangerous", "fake website", "stolen", "credential theft"]
    has_fraud_claim = any(re.search(r"\b" + re.escape(w) + r"\b", ai_exp, re.IGNORECASE) for w in fraud_keywords)
    has_critical_or_high = any(i.get("severity") in ["critical", "high"] for i in indicators)

    if has_fraud_claim and (not has_critical_or_high or verdict != "Suspicious / Potentially Fraudulent"):
        return fallback or "No active threat indicators detected; unverified domain."

    if "query" in ai_exp.lower() and not any(i.get("id") == "external_redirect_param" for i in indicators):
        return fallback or "No active threat indicators detected; unverified domain."

    # Backend check: AI explanation may use the word 'reserved' only if is_reserved is True
    if not is_reserved and re.search(r"\breserved\b", ai_exp, re.IGNORECASE):
        return fallback or "No active threat indicators detected; domain unverified."

    # Backend check: reject text calling a not_performed check 'failed'
    if verification_checks:
        not_perf = [c.get("name", "").lower() for c in verification_checks if c.get("status") == "not_performed"]
        for np_name in not_perf:
            tokens = [t for t in re.split(r"\s+", np_name) if len(t) > 2]
            for token in tokens:
                p1 = rf"\b{re.escape(token)}\b[^\.\,\;]{{0,25}}\bfailed\b"
                p2 = rf"\bfailed\b[^\.\,\;]{{0,25}}\b{re.escape(token)}\b"
                if re.search(p1, ai_exp, re.IGNORECASE) or re.search(p2, ai_exp, re.IGNORECASE):
                    return fallback or "No active threat indicators detected; domain unverified."

    return ai_exp


def get_url_ai_explanation(url: str, verdict: str, threat_score: int, indicators: list, verification_checks: list, is_reserved: bool = False) -> dict:
    """
    Produce an evidence-based explanation for URL scans.
    Validates AI text against listed indicators.
    Returns llm_score = None (N/A for URL-only scans).
    """
    templated_exp = _build_templated_url_explanation(url, verdict, threat_score, indicators, verification_checks, is_reserved=is_reserved)
    templated_tips = _build_url_safety_tips(verdict, indicators, is_reserved=is_reserved, url=url)

    if not _client:
        return {
            "explanation": templated_exp,
            "safety_tips": templated_tips,
            "llm_score": None,
        }

    prompt = f"""You are ScamXRay's URL Security Intelligence Assistant.
Analyze the provided URL verification results and explain them clearly.

URL: {url}
Deterministic Verdict: {verdict}
Threat Score: {threat_score}/100

Deterministic Threat Indicators:
{json.dumps(indicators, indent=2)}

Verification Checks Performed:
{json.dumps(verification_checks, indent=2)}

CRITICAL RULES:
1. Explain ONLY what the provided indicators and verification checks prove.
2. State clearly which verification checks were performed, which failed, and which were not performed.
3. NEVER call a verification check that is marked 'not_performed' 'failed'.
4. NEVER claim to have visited the site, tested live payloads, checked third-party reputation feeds, or queried external databases unless a performed check explicitly proves it.
5. NEVER treat unusual or random-looking query parameter names or values as evidence of fraud.
6. NEVER contradict the deterministic verdict:
   - If the verdict is "Unverified", explain that the domain could not be verified and lacks positive proof, but do NOT call it a confirmed scam or fraudulent.
   - If the verdict is "Likely Legitimate", explain the positive verification evidence (valid TLS, established domain, reachable). Basic checks passed; this is not a guarantee of safety.
   - If the verdict is "Suspicious / Potentially Fraudulent", cite the exact indicator IDs and values from the evidence list.
7. Do NOT invent a risk score.
8. Return ONLY a JSON object:
{{"explanation": "3 to 4 factual sentences", "safety_tips": ["tip 1", "tip 2", "tip 3"]}}"""

    try:
        response = _client.chat.completions.create(
            model=MODEL,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.1,
            max_tokens=800,
            reasoning_effort="low",
        )
        raw_text = (response.choices[0].message.content or "").strip()
        match = re.search(r"\{.*\}", raw_text, re.DOTALL)
        if not match:
            return {"explanation": templated_exp, "safety_tips": templated_tips, "llm_score": None}

        data = json.loads(match.group(0))
        ai_exp = str(data.get("explanation", "")).strip()

        # BACKEND VALIDATION:
        ai_exp = validate_url_ai_output(
            ai_exp,
            verdict,
            indicators,
            verification_checks=verification_checks,
            is_reserved=is_reserved,
            fallback=templated_exp,
        )

        tips = data.get("safety_tips", [])
        if not isinstance(tips, list) or not tips:
            tips = templated_tips
        else:
            tips = [str(t).strip() for t in tips if str(t).strip()][:3]

        return {
            "explanation": ai_exp or templated_exp,
            "safety_tips": tips,
            "llm_score": None,
        }
    except Exception:
        return {
            "explanation": templated_exp,
            "safety_tips": templated_tips,
            "llm_score": None,
        }

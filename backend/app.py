import os
from flask import Flask, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv

load_dotenv()

from services.rule_engine import get_rule_analysis
from services.predictor import get_ml_score
from services.url_analyzer import analyze_url_comprehensive
from services.analyzer import get_claude_explanation, get_url_ai_explanation
from services.category_classifier import classify_threat

app = Flask(__name__)
CORS(app)


def score_to_risk_level(score: int) -> str:
    if score <= 30:
        return "Low"
    elif score <= 70:
        return "Medium"
    return "High"


# Weighted score aggregation constants for text/OCR scans
WEIGHT_RULES = 0.40
WEIGHT_AI = 0.35
WEIGHT_ML = 0.25
EVIDENCE_FLOOR_RULE_THRESHOLD = 75
EVIDENCE_FLOOR_SCORE = 75


def compute_text_composite_score(
    rule_score: int | None,
    ml_score: float | int | None,
    llm_score: int | None,
) -> int:
    """
    Weighted combination with evidence floor for text/OCR scans.
    Weights: Rules 0.40, AI 0.35, ML 0.25.
    If a layer is unavailable/None, weights are renormalised across available layers.
    Evidence floor: if rule_score >= 75, composite score is at least 75 and at least rule_score.
    """
    weights = {}
    scores = {}

    if rule_score is not None:
        weights["rules"] = WEIGHT_RULES
        scores["rules"] = float(rule_score)

    if llm_score is not None:
        weights["ai"] = WEIGHT_AI
        scores["ai"] = float(llm_score)

    if ml_score is not None:
        weights["ml"] = WEIGHT_ML
        scores["ml"] = float(ml_score)

    if not scores:
        return 0

    total_weight = sum(weights.values())
    raw_composite = sum(scores[k] * (weights[k] / total_weight) for k in scores)

    # Evidence floor: if rule_score >= 75, overall must not drop below rule_score or 75
    if rule_score is not None and rule_score >= EVIDENCE_FLOOR_RULE_THRESHOLD:
        raw_composite = max(raw_composite, float(rule_score), float(EVIDENCE_FLOOR_SCORE))

    return int(round(raw_composite))


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"}), 200


@app.route("/analyze", methods=["POST"])
def analyze():
    body = request.get_json(silent=True)

    if not isinstance(body, dict):
        return jsonify({"error": "Request body must be a JSON object."}), 400

    text = body.get("text", "")
    url = body.get("url", "")

    if not isinstance(text, str) or not isinstance(url, str):
        return jsonify({"error": "'text' and 'url' must be strings."}), 400

    text = text.strip()
    url = url.strip()

    if not text and not url:
        return jsonify({"error": "Provide message text, a URL, or both."}), 400

    # =========================================================================
    # PATH A: URL-ONLY SCAN (Independent 3-layer architecture)
    # =========================================================================
    if url and not text:
        url_result = analyze_url_comprehensive(url, execute_network=True)
        threat_score = url_result["threat_score"]
        indicators = url_result["indicators"]
        verification_checks = url_result["verification_checks"]
        url_verdict = url_result["verdict"]
        url_verdict_reason = url_result["verdict_reason"]

        ai_result = get_url_ai_explanation(
            url=url,
            verdict=url_verdict,
            threat_score=threat_score,
            indicators=indicators,
            verification_checks=verification_checks,
            is_reserved=url_result.get("is_reserved_example", False),
        )

        explanation = ai_result["explanation"]
        safety_tips = ai_result["safety_tips"]
        llm_score = None  # Explicitly N/A for URL-only scans

        # Overall risk derived from threat indicators and verdict only
        if url_verdict == "Suspicious / Potentially Fraudulent":
            risk_score = threat_score
            risk_level = "High" if risk_score > 70 else "Medium"
        elif url_verdict == "Likely Legitimate":
            risk_score = 0
            risk_level = "Low"
        else:  # Unverified
            risk_score = threat_score
            risk_level = "Unverified"

        if url_verdict == "Suspicious / Potentially Fraudulent":
            scam_category = "Potentially Fraudulent Link"
        elif url_result.get("is_reserved_example"):
            scam_category = "Unverified (Reserved Example Domain)"
        elif url_verdict == "Likely Legitimate":
            scam_category = "Likely Legitimate URL"
        else:
            scam_category = "Unverified URL"

        if indicators:
            classification_criteria = [
                f"{i['id']}: {i['description']} ('{i['value']}')"
                for i in indicators
            ]
        else:
            classification_criteria = [
                "No structural threat indicators detected in the URL syntax."
            ]

        response = {
            "text": "",
            "jobText": "",
            "rule_flags": [],
            "text_flags": [],
            "url_flags": url_result["url_flags"],
            "rule_score": None,
            "ml_score": None,
            "url_score": threat_score,
            "llm_score": None,
            "url": url_result.get("url", url),
            "categories": [],
            "risk_score": risk_score,
            "risk_level": risk_level,
            "explanation": explanation,
            "safety_tips": safety_tips,
            "scam_category": scam_category,
            "classification_criteria": classification_criteria,
            "radar_indicators": {
                "urgency": 0,
                "payment": 0,
                "url_risk": threat_score,
                "ml_score": 0,
                "impersonation": 75 if any(i["id"] in ("subdomain_brand_spoof", "brand_lookalike_domain") for i in indicators) else 0,
            },
            "url_verdict": url_verdict,
            "url_verdict_reason": url_verdict_reason,
            "indicators": indicators,
            "url_indicators": indicators,
            "verification_checks": verification_checks,
            "matches": [],
        }

        return jsonify(response), 200

    # =========================================================================
    # PATH B: TEXT / OCR SCAN (Preserved recruitment fraud pipeline)
    # =========================================================================
    # Layer 1: rules
    rule_result = get_rule_analysis(text)
    rule_score = int(rule_result.get("rule_score", 0))
    text_flags = rule_result.get("rule_flags", [])
    categories = rule_result.get("categories", [])
    matches = rule_result.get("matches", [])

    # Layer 2: ML
    ml_score = None
    if text:
        try:
            ml_score = get_ml_score(text)
        except Exception:
            app.logger.exception("ML predictor failed")

    # Layer 3: URL (if accompanying URL provided)
    if url:
        try:
            url_result = analyze_url_comprehensive(url, execute_network=True)
        except Exception:
            app.logger.exception("URL analyzer failed")
            url_result = {
                "url": url,
                "hostname": "",
                "registered_domain": "",
                "is_reserved_example": False,
                "threat_score": 40,
                "url_score": 40,
                "indicators": [],
                "url_flags": ["URL analysis could not be completed. Verify this link independently."],
                "verification_checks": [],
                "verdict": "Unverified",
                "verdict_reason": "URL inspection failed to complete.",
            }
    else:
        url_result = {
            "url": "",
            "hostname": "",
            "registered_domain": "",
            "is_reserved_example": False,
            "threat_score": None,
            "url_score": None,
            "indicators": [],
            "url_flags": [],
            "verification_checks": [],
            "verdict": None,
            "verdict_reason": None,
        }

    url_score = url_result.get("url_score")
    url_flags = url_result.get("url_flags", [])
    all_flags = list(text_flags) + list(url_flags)

    # Detect OCR scan
    raw_input_type = str(body.get("input_type", "")).lower()
    is_ocr = "ocr" in raw_input_type or "image" in raw_input_type

    # Defaults if AI is unavailable
    explanation = (
        "Automated analysis completed. Review the detected indicators "
        "and verify the source before taking action."
    )
    safety_tips = [
        "Never pay any fee to get a job. Real employers don't charge you.",
        "Verify the company on its official website and LinkedIn.",
        "Be careful if they only talk to you on WhatsApp or Telegram.",
    ]
    llm_score = None

    try:
        ai_result = get_claude_explanation(
            job_text=text,
            rule_flags=all_flags,
            ml_score=ml_score if ml_score is not None else rule_score,
            is_ocr=is_ocr,
        )
        explanation = ai_result.get("explanation") or explanation
        safety_tips = ai_result.get("safety_tips") or safety_tips
        llm_score = ai_result.get("llm_score")
    except Exception:
        app.logger.exception("AI explanation failed")

    # Overall risk aggregation for text/OCR scans: weighted combination with evidence floor
    risk_score = compute_text_composite_score(rule_score, ml_score, llm_score)

    # If an accompanying URL was also provided and evaluated, factor its threat score
    if url and url_score is not None:
        risk_score = max(risk_score, url_score)

    risk_level = score_to_risk_level(risk_score)

    threat_info = classify_threat(
        text=text,
        url=url,
        matches=matches,
        categories=categories,
        url_result=url_result,
        ml_score=ml_score,
        risk_score=risk_score,
    )

    response = {
        "text": text,
        "jobText": text,
        "rule_flags": text_flags,
        "text_flags": text_flags,
        "url_flags": url_flags,
        "rule_score": rule_score,
        "ml_score": ml_score,
        "url_score": url_score,
        "llm_score": llm_score,
        "url": url_result.get("url", url),
        "categories": categories,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "explanation": explanation,
        "safety_tips": safety_tips,
        "scam_category": threat_info["scam_category"],
        "classification_criteria": threat_info["classification_criteria"],
        "radar_indicators": threat_info["radar_indicators"],
        "url_verdict": url_result.get("verdict") if url else None,
        "url_verdict_reason": url_result.get("verdict_reason") if url else None,
        "indicators": url_result.get("indicators", []) if url else None,
        "verification_checks": url_result.get("verification_checks", []) if url else None,
        "matches": matches,
    }

    return jsonify(response), 200


if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    debug = os.getenv("FLASK_DEBUG", "false").lower() == "true"
    app.run(host="127.0.0.1", port=port, debug=debug)

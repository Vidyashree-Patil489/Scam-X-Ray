import sys
import os
_BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BACKEND_DIR not in sys.path:
    sys.path.insert(0, _BACKEND_DIR)

import unittest
from unittest.mock import patch
import json
from services.url_analyzer import (
    analyze_url,
    extract_threat_indicators,
    compute_threat_score,
    is_ip_private_or_blocked,
    check_server_connectivity,
    RESERVED_EXAMPLE_DOMAINS
)
from services.analyzer import get_url_ai_explanation, validate_url_ai_output
from app import app, compute_text_composite_score, WEIGHT_RULES, WEIGHT_AI, WEIGHT_ML


class URLRegressionTests(unittest.TestCase):
    def setUp(self):
        self.app = app.test_client()

    def test_01_reserved_domain_graceful(self):
        """Test 1: https://graceful.example.com/ -> Unverified, reserved domain, 0 indicators"""
        url = "https://graceful.example.com/"
        res = analyze_url(url, execute_network=True)

        self.assertEqual(res["threat_score"], 0)
        self.assertEqual(len(res["indicators"]), 0)
        self.assertEqual(res["verdict"], "Unverified")
        self.assertTrue(res["is_reserved_example"])
        self.assertIn("reserved", res["verdict_reason"].lower())

    def test_02_reserved_domain_with_query_params(self):
        """Test 2: https://stick.example.com/?lazy=better&conscious=separate
        -> identical verdict/risk to #1; no AI score; random params create no indicator"""
        url1 = "https://graceful.example.com/"
        url2 = "https://stick.example.com/?lazy=better&conscious=separate"

        res1 = analyze_url(url1, execute_network=False)
        res2 = analyze_url(url2, execute_network=False)

        self.assertEqual(res1["verdict"], res2["verdict"])
        self.assertEqual(res1["threat_score"], res2["threat_score"])
        self.assertEqual(len(res2["indicators"]), 0)

        # Test full API response
        response = self.app.post('/analyze', json={'url': url2, 'input_type': 'url'})
        data = json.loads(response.data)

        self.assertEqual(data["risk_score"], 0)
        self.assertEqual(data["url_verdict"], "Unverified")
        self.assertIsNone(data["ml_score"])
        self.assertIsNone(data["rule_score"])
        self.assertIsNone(data["llm_score"])
        self.assertEqual(len(data["indicators"]), 0)

    def test_03_subdomain_brand_spoof(self):
        """Test 3: https://paypal.com.secure-login.xyz/verify -> Suspicious (subdomain_brand_spoof)"""
        url = "https://paypal.com.secure-login.xyz/verify"
        res = analyze_url(url, execute_network=False)

        self.assertEqual(res["verdict"], "Suspicious / Potentially Fraudulent")
        indicator_ids = [ind["id"] for ind in res["indicators"]]
        self.assertIn("subdomain_brand_spoof", indicator_ids)
        self.assertGreaterEqual(res["threat_score"], 35)

    def test_04_userinfo_trick(self):
        """Test 4: http://user@evil-site.com/ -> Suspicious (userinfo_trick)"""
        url = "http://user@evil-site.com/"
        res = analyze_url(url, execute_network=False)

        self.assertEqual(res["verdict"], "Suspicious / Potentially Fraudulent")
        indicator_ids = [ind["id"] for ind in res["indicators"]]
        self.assertIn("userinfo_trick", indicator_ids)
        self.assertGreaterEqual(res["threat_score"], 70)

    def test_05_homoglyph_punycode(self):
        """Test 5: https://xn--pple-43d.com/ -> homoglyph/punycode indicator"""
        url = "https://xn--pple-43d.com/"
        res = analyze_url(url, execute_network=False)

        indicator_ids = [ind["id"] for ind in res["indicators"]]
        self.assertIn("homoglyph_punycode", indicator_ids)

    def test_06_private_and_localhost_ssrf(self):
        """Test 6: http://192.168.1.1/login and http://localhost:5000/
        -> Unverified, blocked from fetching (SSRF protection), not Suspicious purely for being private"""
        for url in ["http://192.168.1.1/login", "http://localhost:5000/"]:
            res = analyze_url(url, execute_network=True)
            self.assertEqual(res["verdict"], "Unverified", f"Failed for {url}")
            self.assertNotEqual(res["verdict"], "Suspicious / Potentially Fraudulent")
            self.assertEqual(res["threat_score"], 0)
            dns_checks = [c for c in res["verification_checks"] if c["name"] == "DNS Resolution"]
            if dns_checks:
                self.assertIn(dns_checks[0]["status"], ["failed", "not_performed"])

    def test_07_failed_network_checks_unverified(self):
        """Test 7: https://example-unknown-shop.com/?id=7f3a9c2e with DNS/RDAP/TLS all failing
        -> Unverified with 'checks failed', NOT Suspicious"""
        url = "https://example-unknown-shop.com/?id=7f3a9c2e"
        with patch('services.url_analyzer.check_server_connectivity', return_value=True), \
             patch('services.url_analyzer.safe_resolve_dns', return_value=(False, [], "NXDOMAIN")), \
             patch('services.url_analyzer.check_tls_cert', return_value=(False, {"valid": False}, "Connection refused")), \
             patch('services.url_analyzer.check_domain_age', return_value=(False, False, "RDAP failed")), \
             patch('services.url_analyzer.check_http_reachability', return_value=(False, "Unreachable")):
            res = analyze_url(url, execute_network=True)
            self.assertEqual(res["threat_score"], 0)
            self.assertEqual(res["verdict"], "Unverified")
            self.assertNotEqual(res["verdict"], "Suspicious / Potentially Fraudulent")

    def test_08_legitimate_verified(self):
        """Test 8: Same URL with mocked valid TLS, 5-year domain age, resolves, no indicators
        -> Likely Legitimate"""
        url = "https://example-unknown-shop.com/?id=7f3a9c2e"
        with patch('services.url_analyzer.check_server_connectivity', return_value=True), \
             patch('services.url_analyzer.safe_resolve_dns', return_value=(True, ["93.184.216.34"], "Resolved to 93.184.216.34")), \
             patch('services.url_analyzer.check_tls_cert', return_value=(True, {"valid": True}, "Valid certificate for domain")), \
             patch('services.url_analyzer.check_domain_age', return_value=(True, True, "Established (registered 2019)")), \
             patch('services.url_analyzer.check_http_reachability', return_value=(True, "HTTP 200 OK")):
            res = analyze_url(url, execute_network=True)
            self.assertEqual(res["threat_score"], 0)
            self.assertEqual(res["verdict"], "Likely Legitimate")

    def test_09_external_redirect_param(self):
        """Test 9: https://safe-looking.com/?next=https://evil.com -> external_redirect_param medium (20 pts)"""
        url = "https://safe-looking.com/?next=https://evil.com"
        res = analyze_url(url, execute_network=False)

        indicator_ids = [ind["id"] for ind in res["indicators"]]
        self.assertIn("external_redirect_param", indicator_ids)
        self.assertEqual(res["threat_score"], 20)
        self.assertEqual(res["verdict"], "Unverified")

    def test_10_redirect_to_private_ip_ssrf(self):
        """Test 10: Mock redirect to a private IP -> blocked by SSRF"""
        self.assertTrue(is_ip_private_or_blocked("127.0.0.1"))
        self.assertTrue(is_ip_private_or_blocked("10.0.0.1"))
        self.assertTrue(is_ip_private_or_blocked("172.16.0.1"))
        self.assertTrue(is_ip_private_or_blocked("192.168.1.1"))
        self.assertTrue(is_ip_private_or_blocked("169.254.169.254"))
        self.assertFalse(is_ip_private_or_blocked("93.184.216.34"))

    def test_11_ai_hallucination_discarded(self):
        """Test 11: AI returns 'highly likely scam' citing only query params -> backend discards it"""
        url = "https://stick.example.com/?lazy=better&conscious=separate"
        verdict = "Unverified"
        indicators = []

        bad_ai_text = "This URL is a dangerous scam because the query parameters lazy=better look suspicious and malicious."
        fallback_msg = "Deterministic fallback: no active threat indicators detected; unverified domain."
        cleaned_text = validate_url_ai_output(bad_ai_text, verdict, indicators, fallback=fallback_msg)
        self.assertNotIn("dangerous scam", cleaned_text.lower())
        self.assertNotIn("malicious", cleaned_text.lower())
        self.assertIn("no active threat indicators", cleaned_text.lower())

    def test_12_whatsapp_recruitment_regression(self):
        """Test 12: Existing text/OCR WhatsApp recruitment case still scores 100/100, High risk, 6+ flags"""
        sample_text = (
            "ONLINE JOB PORTAL\n"
            "Urgent requirement for Back Office / Data Entry / Document Verification.\n"
            "Salary: 25,000 - 35,000 per month.\n"
            "Interview is scheduled for tomorrow at our office. "
            "Contact on WhatsApp to confirm slot. "
            "Send your CV immediately. "
            "Office address will be shared after CV is received."
        )
        response = self.app.post('/analyze', json={'text': sample_text, 'input_type': 'text'})
        data = json.loads(response.data)

        self.assertEqual(data["risk_score"], 100)
        self.assertEqual(data["risk_level"].upper(), "HIGH")
        self.assertGreaterEqual(len(data.get("rule_flags", [])), 6)
        self.assertEqual(data["scam_category"], "Potential Recruitment Scam")
        self.assertIsNone(data.get("url_verdict"))
        self.assertIsNone(data.get("verification_checks"))
        self.assertIsNone(data.get("indicators"))

    def test_13_ocr_response_no_unverified_url_fields(self):
        """Test 13: OCR response contains no url_verdict set to Unverified (must be null/None)"""
        sample_ocr = (
            "URGENT: Part time online typing job. Earn Rs 2000 per day. "
            "No interview required. WhatsApp resume to +919876543210. Pay 500 registration fee to join."
        )
        response = self.app.post('/analyze', json={'text': sample_ocr, 'input_type': 'ocr'})
        data = json.loads(response.data)

        self.assertIsNone(data.get("url_verdict"))
        self.assertIsNone(data.get("verification_checks"))
        self.assertIsNone(data.get("indicators"))
        self.assertEqual(data["risk_level"].upper(), "HIGH")

    def test_14_ai_strip_visual_claims(self):
        """Test 14: strip_visual_claims removes statements asserting visual flaws an OCR text extractor cannot see"""
        from services.analyzer import strip_visual_claims
        explanation = (
            "The message promises rapid employment with no interview required. "
            "The official company logo appears blurry and the letterhead design is amateurish. "
            "Demanding an upfront fee through informal chat apps is a classic hallmark of job fraud."
        )
        cleaned = strip_visual_claims(explanation)
        self.assertNotIn("logo", cleaned.lower())
        self.assertNotIn("letterhead", cleaned.lower())
        self.assertIn("rapid employment", cleaned.lower())
        self.assertIn("upfront fee", cleaned.lower())

    # =========================================================================
    # NEW SPECIFIC REGRESSION TESTS (A THROUGH I)
    # =========================================================================

    def test_a_lookalike_detection_critical(self):
        """Test a: paypa1-secure-login.com and sbi-kyc-update.in -> Suspicious, brand_lookalike_domain critical"""
        for target in ["https://paypa1-secure-login.com/", "https://sbi-kyc-update.in"]:
            res = analyze_url(target, execute_network=False)
            self.assertEqual(res["verdict"], "Suspicious / Potentially Fraudulent")
            ind_ids = {i["id"] for i in res["indicators"]}
            self.assertIn("brand_lookalike_domain", ind_ids)
            crit_ind = next(i for i in res["indicators"] if i["id"] == "brand_lookalike_domain")
            self.assertEqual(crit_ind["severity"], "critical")
            self.assertGreaterEqual(res["threat_score"], 70)

    def test_b_false_positive_suite(self):
        """Test b: False-positive suite, mocked good verification:
        https://www.paypal.com/signin, https://www.amazon.in, https://www.flipkart.com,
        https://onlinesbi.sbi, https://pineapple-recipes.com, https://applebees.com
        -> zero lookalike indicators"""
        candidates = [
            "https://www.paypal.com/signin",
            "https://www.amazon.in",
            "https://www.flipkart.com",
            "https://onlinesbi.sbi",
            "https://pineapple-recipes.com",
            "https://applebees.com"
        ]
        with patch('services.url_analyzer.check_server_connectivity', return_value=True), \
             patch('services.url_analyzer.safe_resolve_dns', return_value=(True, ["1.2.3.4"], "Resolved")), \
             patch('services.url_analyzer.check_tls_cert', return_value=(True, {"valid": True}, "Valid TLS")), \
             patch('services.url_analyzer.check_domain_age', return_value=(True, True, "Established (registered 2015)")), \
             patch('services.url_analyzer.check_http_reachability', return_value=(True, "HTTP 200")):
            for cand in candidates:
                res = analyze_url(cand, execute_network=True)
                lookalike_ids = [i["id"] for i in res["indicators"] if "lookalike" in i["id"] or "spoof" in i["id"]]
                self.assertEqual(lookalike_ids, [], f"Unexpected lookalike flag on legitimate {cand}")
                self.assertEqual(res["threat_score"], 0)
                self.assertEqual(res["verdict"], "Likely Legitimate")

    def test_c_user_content_platforms(self):
        """Test c: github.com/user/repo, someuser.github.io, forms.gle/abc, t.me/channel
        with mocked passing verification -> Unverified, user_content_platform, not Likely Legitimate.
        bare https://github.com/ -> Likely Legitimate"""
        user_content_urls = [
            "https://github.com/someuser/somerepo",
            "https://someuser.github.io",
            "https://forms.gle/abc",
            "https://t.me/channel"
        ]
        with patch('services.url_analyzer.check_server_connectivity', return_value=True), \
             patch('services.url_analyzer.safe_resolve_dns', return_value=(True, ["1.2.3.4"], "Resolved")), \
             patch('services.url_analyzer.check_tls_cert', return_value=(True, {"valid": True}, "Valid TLS")), \
             patch('services.url_analyzer.check_domain_age', return_value=(True, True, "Established (registered 2015)")), \
             patch('services.url_analyzer.check_http_reachability', return_value=(True, "HTTP 200")):
            for u in user_content_urls:
                res = analyze_url(u, execute_network=True)
                self.assertEqual(res["verdict"], "Unverified", f"{u} must be Unverified")
                self.assertNotEqual(res["verdict"], "Likely Legitimate")
                ind_ids = {i["id"] for i in res["indicators"]}
                self.assertIn("user_content_platform", ind_ids)
                self.assertIn("user-content platform", res["verdict_reason"])

            # Bare root github.com/
            res_bare = analyze_url("https://github.com/", execute_network=True)
            self.assertEqual(res_bare["verdict"], "Likely Legitimate")
            self.assertNotIn("user_content_platform", [i["id"] for i in res_bare["indicators"]])

    def test_d_new_domain_age_scoring(self):
        """Test d: Clean domain with mocked age 3 days -> Unverified, new_domain, score 25.
        Same domain with a brand token plus security word -> Suspicious"""
        with patch('services.url_analyzer.check_server_connectivity', return_value=True), \
             patch('services.url_analyzer.safe_resolve_dns', return_value=(True, ["1.2.3.4"], "Resolved")), \
             patch('services.url_analyzer.check_tls_cert', return_value=(True, {"valid": True}, "Valid TLS")), \
             patch('services.url_analyzer.check_domain_age', return_value=(True, False, "Newly registered (3 days ago)")), \
             patch('services.url_analyzer.check_http_reachability', return_value=(True, "HTTP 200")):
            # Clean domain
            res_clean = analyze_url("https://clean-innovative-tech.com", execute_network=True)
            self.assertEqual(res_clean["verdict"], "Unverified")
            self.assertEqual(res_clean["threat_score"], 25)
            self.assertIn("new_domain", [i["id"] for i in res_clean["indicators"]])

            # Brand lookalike domain with new domain age
            res_brand = analyze_url("https://paypal-secure-portal.com", execute_network=True)
            self.assertEqual(res_brand["verdict"], "Suspicious / Potentially Fraudulent")
            self.assertGreaterEqual(res_brand["threat_score"], 70)

    def test_e_paypal_subdomain_spoof_age_label(self):
        """Test e: paypal.com.secure-login.xyz with mocked age 3 -> Suspicious;
        label reads 'Newly registered (3 days ago)', never 'Established'"""
        with patch('services.url_analyzer.check_server_connectivity', return_value=True), \
             patch('services.url_analyzer.safe_resolve_dns', return_value=(True, ["1.2.3.4"], "Resolved")), \
             patch('services.url_analyzer.check_tls_cert', return_value=(True, {"valid": True}, "Valid TLS")), \
             patch('services.url_analyzer.check_domain_age', return_value=(True, False, "Newly registered (3 days ago)")), \
             patch('services.url_analyzer.check_http_reachability', return_value=(True, "HTTP 200")):
            res = analyze_url("https://paypal.com.secure-login.xyz/verify", execute_network=True)
            self.assertEqual(res["verdict"], "Suspicious / Potentially Fraudulent")
            age_check = next(c for c in res["verification_checks"] if c["name"] == "Domain Age (RDAP)")
            self.assertEqual(age_check["details"], "Newly registered (3 days ago)")
            self.assertNotIn("Established", age_check["details"])

    def test_f_redirect_and_same_site_targets(self):
        """Test f: safe-looking.com/?next=https://evil.com (unresolvable) -> Unverified, redirect indicator, score 20.
        shop.example.org/login?next=/account -> no indicator"""
        # safe-looking.com pointing to external target
        res_ext = analyze_url("https://safe-looking.com/?next=https://evil.com", execute_network=False)
        self.assertEqual(res_ext["verdict"], "Unverified")
        self.assertEqual(res_ext["threat_score"], 20)
        self.assertEqual(len(res_ext["indicators"]), 1)
        self.assertEqual(res_ext["indicators"][0]["id"], "external_redirect_param")

        # shop.example.org with relative same-site path
        res_same = analyze_url("https://shop.example.org/login?next=/account", execute_network=False)
        self.assertEqual(len(res_same["indicators"]), 0)
        self.assertEqual(res_same["threat_score"], 0)

    def test_g_safe_looking_explanation_never_says_reserved(self):
        """Test g: Explanation for safe-looking.com never contains 'reserved';
        skipped checks are not_performed with specific reasons"""
        with patch('services.url_analyzer.check_server_connectivity', return_value=True), \
             patch('services.url_analyzer.safe_resolve_dns', return_value=(False, [], "NXDOMAIN")):
            res = analyze_url("https://safe-looking.com/?next=https://evil.com", execute_network=True)
            self.assertEqual(res["verdict"], "Unverified")

            # Check statuses
            checks = {c["name"]: c for c in res["verification_checks"]}
            self.assertEqual(checks["DNS Resolution"]["status"], "failed")
            self.assertEqual(checks["TLS Certificate"]["status"], "not_performed")
            self.assertEqual(checks["TLS Certificate"]["details"], "Skipped: host DNS did not resolve")
            self.assertEqual(checks["Domain Age (RDAP)"]["status"], "not_performed")
            self.assertEqual(checks["Domain Age (RDAP)"]["details"], "Skipped: host DNS did not resolve")
            self.assertEqual(checks["HTTP Reachability"]["status"], "not_performed")
            self.assertEqual(checks["HTTP Reachability"]["details"], "Skipped: host DNS did not resolve")

            # Validate AI explanation
            ai_res = get_url_ai_explanation(
                url="https://safe-looking.com/?next=https://evil.com",
                verdict=res["verdict"],
                threat_score=res["threat_score"],
                indicators=res["indicators"],
                verification_checks=res["verification_checks"],
                is_reserved=res["is_reserved_example"]
            )
            self.assertNotIn("reserved", ai_res["explanation"].lower())
            self.assertNotIn("reserved, private, or unresolvable", json.dumps(res["verification_checks"]).lower())

    def test_h_simulated_no_network_server(self):
        """Test h: Simulated no-network server -> all checks not_performed with
        'Verification unavailable: no network from the server', no domain blame"""
        with patch('services.url_analyzer.check_server_connectivity', return_value=False):
            res = analyze_url("https://unknown-site.org/portal", execute_network=True)
            self.assertEqual(res["verdict"], "Unverified")
            self.assertEqual(res["threat_score"], 0)
            for c in res["verification_checks"]:
                self.assertEqual(c["status"], "not_performed")
                self.assertEqual(c["details"], "Verification unavailable: no network from the server")
            self.assertIn("scanning server has no outbound network connection", res["verdict_reason"])
            self.assertNotIn("domain failed", res["verdict_reason"].lower())

    def test_i_stick_example_preserves_zero_indicators(self):
        """Test i: https://stick.example.com/?lazy=better&conscious=separate still has zero indicators"""
        res = analyze_url("https://stick.example.com/?lazy=better&conscious=separate", execute_network=False)
        self.assertEqual(len(res["indicators"]), 0)
        self.assertEqual(res["threat_score"], 0)
        self.assertEqual(res["verdict"], "Unverified")

    def test_fixtures_a_through_e(self):
        """Test Fixtures A through E with exact OCR noise and legitimate-context guards"""
        from services.rule_engine import get_rule_analysis

        fixture_a = """lo EARNS: we have
received your job application from
Online Job Portal.
You are invited to proceed with
the next step for the position
of Software Developer, Web
Developer & Data Analyst.
Interview Time: Tomorrow
Location: Pune
Please share your CV on this
WhatsApp number so we can
review it and provide the detailed
interview address. 12:32 pm
4 Interested
 STOP"""

        fixture_b = """Urgent opening: WFH Data Entry Associate. Earn ₹45,000/month. No experience needed.
Pay ₹500 refundable registration fee to activate server account. WhatsApp only:
+91 98765 43210. Limited slots, apply within 24 hours!"""

        fixture_c = "hi are we still meeting at 5?"

        fixture_d = """Hi Priya, thank you for
applying to the Data Analyst internship at Infosys. Your interview is on Tuesday
18 Nov at 11 AM at Infosys Campus, Electronic City, Bengaluru, Gate 2 reception.
Please bring your ID and resume. Contact: hr.recruitment@infosys.com. Regards,
Ananya Rao, Talent Acquisition."""

        fixture_e = """Dear Rahul, your
technical round with Zoho is scheduled tomorrow at 10:30 AM on Google Meet.
Link: meet.google.com/abc-defg-hij. Please keep a government photo ID ready.
Reply to this email to confirm. - Meena S, HR, Zoho Corporation"""

        # Fixture A: Real OCR screenshot text
        res_a = get_rule_analysis(fixture_a)
        self.assertGreaterEqual(len(res_a["matches"]), 4)
        self.assertGreater(res_a["rule_score"], 45)
        resp_a = self.app.post('/analyze', json={'text': fixture_a, 'input_type': 'ocr'})
        data_a = json.loads(resp_a.data)
        self.assertEqual(data_a["risk_level"].upper(), "HIGH")
        self.assertEqual(data_a["scam_category"], "Potential Recruitment Scam")

        # Fixture B: Fee scam
        res_b = get_rule_analysis(fixture_b)
        self.assertEqual(res_b["rule_score"], 100)
        resp_b = self.app.post('/analyze', json={'text': fixture_b, 'input_type': 'text'})
        data_b = json.loads(resp_b.data)
        self.assertEqual(data_b["risk_score"], 100)
        self.assertEqual(data_b["scam_category"], "Fake Job Posting")

        # Fixture C: Harmless
        res_c = get_rule_analysis(fixture_c)
        self.assertEqual(len(res_c["matches"]), 0)
        self.assertEqual(res_c["rule_score"], 0)
        resp_c = self.app.post('/analyze', json={'text': fixture_c, 'input_type': 'text'})
        data_c = json.loads(resp_c.data)
        self.assertEqual(data_c["risk_level"].upper(), "LOW")

        # Fixture D: Legitimate interview invite
        res_d = get_rule_analysis(fixture_d)
        self.assertEqual(len(res_d["matches"]), 0)
        self.assertEqual(res_d["rule_score"], 0)
        resp_d = self.app.post('/analyze', json={'text': fixture_d, 'input_type': 'text'})
        data_d = json.loads(resp_d.data)
        self.assertIn(data_d["risk_level"].upper(), ["LOW", "MEDIUM"])
        self.assertNotEqual(data_d["risk_level"].upper(), "HIGH")

        # Fixture E: Legitimate named recruiter via email
        res_e = get_rule_analysis(fixture_e)
        self.assertEqual(len(res_e["matches"]), 0)
        self.assertEqual(res_e["rule_score"], 0)
        resp_e = self.app.post('/analyze', json={'text': fixture_e, 'input_type': 'text'})
        data_e = json.loads(resp_e.data)
        self.assertIn(data_e["risk_level"].upper(), ["LOW", "MEDIUM"])
        self.assertNotEqual(data_e["risk_level"].upper(), "HIGH")

    def test_fixtures_f_through_i(self):
        """Test Fixtures F through I: Domain mismatch and adversarial recruitment checks"""
        from services.rule_engine import get_rule_analysis

        # Fixture F: Spoofed domain + address + whatsapp
        fixture_f = (
            "TCS Technologies Pvt Ltd. Interview Time: Tomorrow. Venue: TCS Campus, Whitefield, "
            "Bengaluru, Gate 1 reception. Share your CV on WhatsApp 98765 43210 to confirm your slot. "
            "Contact: hr@tcs-hiring.in"
        )
        res_f = get_rule_analysis(fixture_f)
        matched_rules_f = {m["rule"] for m in res_f["matches"]}
        self.assertIn("Contact domain does not match the named company: tcs-hiring.in", matched_rules_f)
        self.assertIn("Unverified CV or resume solicitation on chat apps", matched_rules_f)
        resp_f = self.app.post('/analyze', json={'text': fixture_f, 'input_type': 'text'})
        data_f = json.loads(resp_f.data)
        self.assertIn(data_f["risk_level"].upper(), ["MEDIUM", "HIGH"])

        # Fixture G: Withheld address without domain
        fixture_g = (
            "Wipro Ltd is hiring. Interview tomorrow. Location: Pune. "
            "Send your CV on WhatsApp 98765 43210 for the detailed address."
        )
        res_g = get_rule_analysis(fixture_g)
        matched_rules_g = {m["rule"] for m in res_g["matches"]}
        self.assertIn("Rapid next-day interview pressure", matched_rules_g)
        self.assertIn("Unverified CV or resume solicitation on chat apps", matched_rules_g)
        self.assertIn("Withheld interview address or venue", matched_rules_g)
        resp_g = self.app.post('/analyze', json={'text': fixture_g, 'input_type': 'text'})
        data_g = json.loads(resp_g.data)
        self.assertIn(data_g["risk_level"].upper(), ["MEDIUM", "HIGH"])

        # Fixture H: Legitimate multi-role with legitimate corporate portal
        fixture_h = (
            "Hiring at Zoho Corporation: Software Developer, Web Developer & Data Analyst. "
            "Apply at careers.zoho.com. Interview details will be shared by email after shortlisting."
        )
        res_h = get_rule_analysis(fixture_h)
        self.assertEqual(len(res_h["matches"]), 0)
        self.assertEqual(res_h["rule_score"], 0)
        resp_h = self.app.post('/analyze', json={'text': fixture_h, 'input_type': 'text'})
        data_h = json.loads(resp_h.data)
        self.assertEqual(data_h["risk_level"].upper(), "LOW")
        self.assertNotEqual(data_h["risk_level"].upper(), "HIGH")

        # Fixture I: Lookalike email domain + campus address
        fixture_i = (
            "Infosys Limited. Interview tomorrow at Infosys Campus, Electronic City, Bengaluru, "
            "Gate 2 reception. Contact: hr@infosys-careers.in"
        )
        res_i = get_rule_analysis(fixture_i)
        matched_rules_i = {m["rule"] for m in res_i["matches"]}
        self.assertIn("Contact domain does not match the named company: infosys-careers.in", matched_rules_i)
        self.assertIn("Rapid next-day interview pressure", matched_rules_i)
        resp_i = self.app.post('/analyze', json={'text': fixture_i, 'input_type': 'text'})
        data_i = json.loads(resp_i.data)
        self.assertIn(data_i["risk_level"].upper(), ["MEDIUM", "HIGH"])

    def test_ocr_noise_variants_fixture_a(self):
        """Test OCR noise variants of Fixture A to verify rule resilience against OCR imperfections"""
        from services.rule_engine import get_rule_analysis

        variant_1 = (
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
        )

        variant_2 = (
            "1o EARNS: we have received your job application from Online Job Portal .\n"
            "You are invited to proceed with the next step for the position of Software Developer, "
            "Web Developer, Graphic Designer .\n"
            "Interview Time : Tomorrow 10:30 AM .\n"
            "Venue : Will be provided after sharing your updated CV .\n"
            "Share your CV on WhatsApp : 98765 43210 .\n"
            "HR Team ."
        )

        for var in [variant_1, variant_2]:
            res = get_rule_analysis(var)
            matched_names = {m["rule"] for m in res["matches"]}
            self.assertIn("Online Job Portal".lower(), var.lower())
            self.assertIn("Rapid next-day interview pressure", matched_names)
            self.assertIn("Unverified CV or resume solicitation on chat apps", matched_names)
            self.assertGreaterEqual(res["rule_score"], 45)

    def test_composite_score_renormalisation_ai_na(self):
        """Case with AI layer N/A (llm_score is None) -> weights renormalised across rules and ML"""
        # rules=50 (weight 0.40), ml=20 (weight 0.25). Total weight = 0.65
        score = compute_text_composite_score(rule_score=50, ml_score=20, llm_score=None)
        expected = int(round(50 * (WEIGHT_RULES / (WEIGHT_RULES + WEIGHT_ML)) + 20 * (WEIGHT_ML / (WEIGHT_RULES + WEIGHT_ML))))
        self.assertEqual(score, expected)
        self.assertEqual(score, 38)

    def test_composite_score_only_rules(self):
        """Case with only rules (ml_score is None, llm_score is None) -> returns rule score"""
        score = compute_text_composite_score(rule_score=60, ml_score=None, llm_score=None)
        self.assertEqual(score, 60)
        score_low = compute_text_composite_score(rule_score=25, ml_score=None, llm_score=None)
        self.assertEqual(score_low, 25)

    def test_composite_score_evidence_floor(self):
        """Evidence floor: if rule_score >= 75, overall must not drop below rule_score or 75"""
        score_floor = compute_text_composite_score(rule_score=75, ml_score=0, llm_score=0)
        self.assertEqual(score_floor, 75)
        score_floor_99 = compute_text_composite_score(rule_score=99, ml_score=20, llm_score=80)
        self.assertGreaterEqual(score_floor_99, 99)

    def test_text_scoring_fixtures_ranges(self):
        """Verify the 7 required text/OCR fixtures against required risk level ranges"""
        fixtures = {
            "A_Pune_screenshot": {
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
                "allowed_levels": ["HIGH"]
            },
            "B_fee_scam": {
                "text": (
                    "Urgent opening: WFH Data Entry Associate. Earn \u20b945,000/month. No experience needed.\n"
                    "Pay \u20b9500 refundable registration fee to activate server account. WhatsApp only:\n"
                    "+91 98765 43210. Limited slots, apply within 24 hours!"
                ),
                "allowed_levels": ["HIGH"]
            },
            "C_meeting": {
                "text": "hi are we still meeting at 5?",
                "allowed_levels": ["LOW"]
            },
            "D_Infosys_invite": {
                "text": (
                    "Hi Priya, thank you for\n"
                    "applying to the Data Analyst internship at Infosys. Your interview is on Tuesday\n"
                    "18 Nov at 11 AM at Infosys Campus, Electronic City, Bengaluru, Gate 2 reception.\n"
                    "Please bring your ID and resume. Contact: hr.recruitment@infosys.com. Regards,\n"
                    "Ananya Rao, Talent Acquisition."
                ),
                "allowed_levels": ["LOW", "MEDIUM"]
            },
            "E_Zoho_invite": {
                "text": (
                    "Dear Rahul, your\n"
                    "technical round with Zoho is scheduled tomorrow at 10:30 AM on Google Meet.\n"
                    "Link: meet.google.com/abc-defg-hij. Please keep a government photo ID ready.\n"
                    "Reply to this email to confirm. - Meena S, HR, Zoho Corporation"
                ),
                "allowed_levels": ["LOW", "MEDIUM"]
            },
            "XYZ_intern_message": {
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
                "allowed_levels": ["MEDIUM", "HIGH"]
            },
            "TCS_lookalike": {
                "text": (
                    "TCS Technologies Pvt Ltd. Interview Time: Tomorrow. Venue: TCS Campus, Whitefield, "
                    "Bengaluru, Gate 1 reception. Share your CV on WhatsApp 98765 43210 to confirm your slot. "
                    "Contact: hr@tcs-hiring.in"
                ),
                "allowed_levels": ["MEDIUM", "HIGH"]
            }
        }

        for name, data in fixtures.items():
            resp = self.app.post('/analyze', json={'text': data['text'], 'input_type': 'text'})
            self.assertEqual(resp.status_code, 200, f"Failed on fixture {name}")
            res = json.loads(resp.data)
            self.assertIn(
                res["risk_level"].upper(),
                data["allowed_levels"],
                f"Fixture {name} risk level {res['risk_level']} not in {data['allowed_levels']}. Full res: {res}"
            )


if __name__ == '__main__':
    unittest.main()

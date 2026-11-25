import sys
import os
_BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BACKEND_DIR not in sys.path:
    sys.path.insert(0, _BACKEND_DIR)

import unittest
from unittest.mock import patch
import json
import requests
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
        """Test 1: https://graceful.example.com/ -> Unknown, reserved domain, 0 indicators"""
        url = "https://graceful.example.com/"
        res = analyze_url(url, execute_network=True)

        self.assertEqual(res["threat_score"], 0)
        self.assertEqual(len(res["indicators"]), 0)
        self.assertEqual(res["verdict"], "Unknown")
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
        self.assertEqual(data["url_verdict"], "Unknown")
        self.assertIsNone(data["ml_score"])
        self.assertIsNone(data["rule_score"])
        self.assertIsNone(data["llm_score"])
        self.assertEqual(len(data["indicators"]), 0)

    def test_03_subdomain_brand_spoof(self):
        """Test 3: https://paypal.com.secure-login.xyz/verify -> Suspicious (subdomain_brand_spoof)"""
        url = "https://paypal.com.secure-login.xyz/verify"
        res = analyze_url(url, execute_network=False)

        self.assertEqual(res["verdict"], "Suspicious")
        indicator_ids = [ind["id"] for ind in res["indicators"]]
        self.assertIn("subdomain_brand_spoof", indicator_ids)
        self.assertGreaterEqual(res["threat_score"], 35)

    def test_04_userinfo_trick(self):
        """Test 4: http://user@evil-site.com/ -> Suspicious (userinfo_trick)"""
        url = "http://user@evil-site.com/"
        res = analyze_url(url, execute_network=False)

        self.assertEqual(res["verdict"], "Suspicious")
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
        -> Unknown, blocked from fetching (SSRF protection), not Suspicious purely for being private"""
        for url in ["http://192.168.1.1/login", "http://localhost:5000/"]:
            res = analyze_url(url, execute_network=True)
            self.assertEqual(res["verdict"], "Unknown", f"Failed for {url}")
            self.assertNotEqual(res["verdict"], "Suspicious")
            self.assertEqual(res["threat_score"], 0)
            dns_checks = [c for c in res["verification_checks"] if c["name"] == "DNS Resolution"]
            if dns_checks:
                self.assertIn(dns_checks[0]["status"], ["failed", "not_performed"])

    def test_07_failed_network_checks_unverified(self):
        """Test 7: https://example-unknown-shop.com/?id=7f3a9c2e with DNS/RDAP/TLS all failing
        -> Unknown with 'checks failed', NOT Suspicious"""
        url = "https://example-unknown-shop.com/?id=7f3a9c2e"
        with patch('services.url_analyzer.check_server_connectivity', return_value=True), \
             patch('services.url_analyzer.safe_resolve_dns', return_value=(False, [], "NXDOMAIN")), \
             patch('services.url_analyzer.check_tls_cert', return_value=(False, {"valid": False}, "Connection refused")), \
             patch('services.url_analyzer.check_domain_age', return_value=(False, False, "RDAP failed")), \
             patch('services.url_analyzer.check_http_reachability', return_value=(False, "Unreachable")):
            res = analyze_url(url, execute_network=True)
            self.assertEqual(res["threat_score"], 0)
            self.assertEqual(res["verdict"], "Unknown")
            self.assertNotEqual(res["verdict"], "Suspicious")

    def test_08_legitimate_verified(self):
        """Test 8: Same URL with mocked valid TLS, 5-year domain age, resolves, no indicators
        -> No threat found"""
        url = "https://example-unknown-shop.com/?id=7f3a9c2e"
        with patch('services.url_analyzer.check_server_connectivity', return_value=True), \
             patch('services.url_analyzer.safe_resolve_dns', return_value=(True, ["93.184.216.34"], "Resolved to 93.184.216.34")), \
             patch('services.url_analyzer.check_tls_cert', return_value=(True, {"valid": True}, "Valid certificate for domain")), \
             patch('services.url_analyzer.check_domain_age', return_value=(True, True, "Established (registered 2019)")), \
             patch('services.url_analyzer.check_http_reachability', return_value=(True, "HTTP 200 OK")):
            res = analyze_url(url, execute_network=True)
            self.assertEqual(res["threat_score"], 0)
            self.assertEqual(res["verdict"], "No threat found")

    def test_09_external_redirect_param(self):
        """Test 9: https://safe-looking.com/?next=https://evil.com -> external_redirect_param medium (20 pts)"""
        url = "https://safe-looking.com/?next=https://evil.com"
        res = analyze_url(url, execute_network=False)

        indicator_ids = [ind["id"] for ind in res["indicators"]]
        self.assertIn("external_redirect_param", indicator_ids)
        self.assertEqual(res["threat_score"], 20)
        self.assertEqual(res["verdict"], "Unknown")

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
        verdict = "Unknown"
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
            self.assertEqual(res["verdict"], "Suspicious")
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
                self.assertEqual(res["verdict"], "No threat found")

    def test_c_user_content_platforms(self):
        """Test c: github.com/user/repo, someuser.github.io, forms.gle/abc, t.me/channel
        with mocked passing verification -> Unknown, user_content_platform, not No threat found.
        bare https://github.com/ -> No threat found"""
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
                self.assertEqual(res["verdict"], "Unknown", f"{u} must be Unknown")
                self.assertNotEqual(res["verdict"], "No threat found")
                ind_ids = {i["id"] for i in res["indicators"]}
                self.assertIn("user_content_platform", ind_ids)
                self.assertIn("user-content platform", res["verdict_reason"])

            # Bare root github.com/
            res_bare = analyze_url("https://github.com/", execute_network=True)
            self.assertEqual(res_bare["verdict"], "No threat found")
            self.assertNotIn("user_content_platform", [i["id"] for i in res_bare["indicators"]])

    def test_d_new_domain_age_scoring(self):
        """Test d: Clean domain with mocked age 3 days -> Unknown, new_domain, score 25.
        Same domain with a brand token plus security word -> Suspicious"""
        with patch('services.url_analyzer.check_server_connectivity', return_value=True), \
             patch('services.url_analyzer.safe_resolve_dns', return_value=(True, ["1.2.3.4"], "Resolved")), \
             patch('services.url_analyzer.check_tls_cert', return_value=(True, {"valid": True}, "Valid TLS")), \
             patch('services.url_analyzer.check_domain_age', return_value=(True, False, "Newly registered (3 days ago)")), \
             patch('services.url_analyzer.check_http_reachability', return_value=(True, "HTTP 200")):
            # Clean domain
            res_clean = analyze_url("https://clean-innovative-tech.com", execute_network=True)
            self.assertEqual(res_clean["verdict"], "Unknown")
            self.assertEqual(res_clean["threat_score"], 25)
            self.assertIn("new_domain", [i["id"] for i in res_clean["indicators"]])

            # Brand lookalike domain with new domain age
            res_brand = analyze_url("https://paypal-secure-portal.com", execute_network=True)
            self.assertEqual(res_brand["verdict"], "Suspicious")
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
            self.assertEqual(res["verdict"], "Suspicious")
            age_check = next(c for c in res["verification_checks"] if c["name"] == "Domain Age (RDAP)")
            self.assertEqual(age_check["details"], "Newly registered (3 days ago)")
            self.assertNotIn("Established", age_check["details"])

    def test_f_redirect_and_same_site_targets(self):
        """Test f: safe-looking.com/?next=https://evil.com (unresolvable) -> Unknown, redirect indicator, score 20.
        shop.example.org/login?next=/account -> no indicator"""
        # safe-looking.com pointing to external target
        res_ext = analyze_url("https://safe-looking.com/?next=https://evil.com", execute_network=False)
        self.assertEqual(res_ext["verdict"], "Unknown")
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
            self.assertEqual(res["verdict"], "Unknown")

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
            self.assertEqual(res["verdict"], "Unknown")
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
        self.assertEqual(res["verdict"], "Unknown")

    # =========================================================================
    # REPUTATION FEED & FOUR-VERDICT TESTS
    # =========================================================================

    def test_url_openphish_feed_match_malicious(self):
        """1. Feed match -> Malicious (threat score 100, confidence high)"""
        url = "https://active-phish-portal.com/login"
        with patch('services.url_analyzer.check_openphish', return_value={
            "source": "OpenPhish",
            "status": "match",
            "detail": "Exact URL matched active phishing entry in OpenPhish feed (https://active-phish-portal.com/login)"
        }):
            res = analyze_url(url, execute_network=False)
            self.assertEqual(res["verdict"], "Malicious")
            self.assertEqual(res["threat_score"], 100)
            self.assertEqual(res["confidence"], "high")
            ind_ids = [i["id"] for i in res["indicators"]]
            self.assertIn("openphish_reputation_match", ind_ids)
            self.assertIn("OpenPhish", res["verdict_reason"])
            self.assertTrue(any(e["source"] == "OpenPhish Community Feed" for e in res["evidence"]))
            self.assertIn("No match in a feed does not mean the link is safe", res["limitations"])

    def test_url_openphish_feed_unavailable_not_checked_verdict_not_raised(self):
        """2. Feed unavailable -> 'not_checked' and verdict not raised"""
        url = "https://graceful.example.com/"
        with patch('services.url_analyzer.check_openphish', return_value={
            "source": "OpenPhish",
            "status": "not_checked",
            "detail": "OpenPhish feed unavailable and no local cache exists"
        }):
            res = analyze_url(url, execute_network=False)
            self.assertEqual(res["verdict"], "Unknown")
            self.assertEqual(res["threat_score"], 0)
            self.assertNotIn("Malicious", res["verdict"])
            self.assertNotIn("Suspicious", res["verdict"])
            # Evidence shows lookup was not performed / unavailable
            openphish_ev = next(e for e in res["evidence"] if e["source"] == "OpenPhish Community Feed")
            self.assertIn("unavailable", openphish_ev["result"])

    def test_url_lookalike_domain_suspicious(self):
        """3. Lookalike domain -> Suspicious"""
        url = "https://paypa1-secure-login.com/"
        with patch('services.url_analyzer.check_openphish', return_value={
            "source": "OpenPhish", "status": "no_match", "detail": "Not in feed"
        }):
            res = analyze_url(url, execute_network=False)
            self.assertEqual(res["verdict"], "Suspicious")
            self.assertGreaterEqual(res["threat_score"], 35)
            self.assertIn(res["confidence"], ["high", "medium"])
            self.assertTrue(any("lookalike" in i["id"] for i in res["indicators"]))

    def test_url_github_repo_unknown_with_platform_reason(self):
        """4. github.com repo -> Unknown with platform reason"""
        url = "https://github.com/user/project-repo"
        with patch('services.url_analyzer.check_openphish', return_value={
            "source": "OpenPhish", "status": "no_match", "detail": "Not in feed"
        }):
            res = analyze_url(url, execute_network=False)
            self.assertEqual(res["verdict"], "Unknown")
            self.assertEqual(res["threat_score"], 0)
            self.assertIn("user-content platform", res["verdict_reason"].lower())
            self.assertTrue(any(i["id"] == "user_content_platform" for i in res["indicators"]))

    def test_url_unreachable_site_unknown(self):
        """5. Unreachable site -> Unknown (failed checks must never raise threat level)"""
        url = "https://unreachable-test-domain-404xyz.com/"
        with patch('services.url_analyzer.check_server_connectivity', return_value=True), \
             patch('services.url_analyzer.check_openphish', return_value={"source": "OpenPhish", "status": "no_match", "detail": "Clean"}), \
             patch('services.url_analyzer.safe_resolve_dns', return_value=(False, [], "NXDOMAIN host not found")):
            res = analyze_url(url, execute_network=True)
            self.assertEqual(res["verdict"], "Unknown")
            self.assertEqual(res["threat_score"], 0)
            self.assertNotIn("Suspicious", res["verdict"])
            self.assertIn("failed", res["verdict_reason"].lower())

    def test_url_clean_site_all_checks_passed_no_threat_found(self):
        """6. Clean site with all checks passed -> No threat found (NEVER use words 'safe', 'verified', or 'clean')"""
        url = "https://legit-business-portal.com/"
        with patch('services.url_analyzer.check_server_connectivity', return_value=True), \
             patch('services.url_analyzer.check_openphish', return_value={"source": "OpenPhish", "status": "no_match", "detail": "No match"}), \
             patch('services.url_analyzer.safe_resolve_dns', return_value=(True, ["93.184.216.34"], "Resolved to 93.184.216.34")), \
             patch('services.url_analyzer.check_tls_cert', return_value=(True, {"valid": True}, "Valid TLS")), \
             patch('services.url_analyzer.check_domain_age', return_value=(True, True, "Established (registered 2018)")), \
             patch('services.url_analyzer.check_http_reachability', return_value=(True, "HTTP 200 OK")):
            res = analyze_url(url, execute_network=True)
            self.assertEqual(res["verdict"], "No threat found")
            self.assertEqual(res["threat_score"], 0)
            self.assertEqual(res["confidence"], "high")
            # Strict word checks: NEVER use words 'safe', 'verified', or 'clean'
            for forbidden in ["safe", "verified", "clean"]:
                self.assertNotIn(forbidden, res["verdict"].lower(), f"Verdict contains forbidden word '{forbidden}'")
                self.assertNotIn(forbidden, res["verdict_reason"].lower(), f"Reason contains forbidden word '{forbidden}'")

    def test_url_random_query_string_alone_not_suspicious(self):
        """7. Random query string alone does not give Suspicious"""
        url = "https://generic-site-test.com/?session_token=a9f3b281c7e4&rand_param=847392"
        with patch('services.url_analyzer.check_openphish', return_value={"source": "OpenPhish", "status": "no_match", "detail": "No match"}):
            res = analyze_url(url, execute_network=False)
            self.assertNotEqual(res["verdict"], "Suspicious")
            self.assertEqual(res["verdict"], "Unknown")
            self.assertEqual(res["threat_score"], 0)
            self.assertEqual(len(res["indicators"]), 0)

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

    def test_unusual_tld_does_not_block_no_threat_found(self):
        """Issue 1: Uncommon TLD (.xyz) is info (0 pts) and does not block 'No threat found' when checks pass."""
        url = "https://abc.xyz"
        with patch('services.url_analyzer.check_server_connectivity', return_value=True), \
             patch('services.url_analyzer.safe_resolve_dns', return_value=(True, ["1.2.3.4"], "Resolved to 1.2.3.4")), \
             patch('services.url_analyzer.check_tls_cert', return_value=(True, {"valid": True}, "Valid certificate for domain")), \
             patch('services.url_analyzer.check_domain_age', return_value=(True, True, "Established (registered 2015)")), \
             patch('services.url_analyzer.check_http_reachability', return_value=(True, "Reachable (HTTP 200)")):
            res = analyze_url(url, execute_network=True)
            self.assertEqual(res["threat_score"], 0)
            self.assertEqual(res["verdict"], "No threat found")
            tld_ind = next((i for i in res["indicators"] if i["id"] == "suspicious_tld"), None)
            self.assertIsNotNone(tld_ind)
            self.assertEqual(tld_ind["severity"], "info")
            self.assertEqual(tld_ind["points"], 0)
            self.assertIn("Uncommon top-level domain; not a threat signal on its own.", tld_ind["description"])
            self.assertNotIn("associated with elevated abuse frequency", tld_ind["description"])

    def test_network_retries_and_failed_check_stays_safe(self):
        """Issue 2: RDAP and HTTP reachability retry once on timeout; permanent failure stays 'failed' and never raises threat score."""
        from services.url_analyzer import check_domain_age, check_http_reachability
        import requests

        # RDAP: 1st attempt fails, 2nd attempt succeeds
        mock_resp = unittest.mock.MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "events": [{"eventAction": "registration", "eventDate": "2018-01-01T00:00:00Z"}]
        }
        with patch('requests.get', side_effect=[requests.exceptions.Timeout("Timed out"), mock_resp]) as mock_get:
            performed, is_est, msg = check_domain_age("example.com", timeout=5.0, max_retries=1)
            self.assertTrue(performed)
            self.assertTrue(is_est)
            self.assertEqual(mock_get.call_count, 2)

        # HTTP: times out on both attempts -> stays 'failed', does not raise threat level
        with patch('requests.Session.get', side_effect=requests.exceptions.Timeout("HTTP timeout")):
            ok, msg = check_http_reachability("https://example.com", timeout=5.0, max_retries=1)
            self.assertFalse(ok)
            self.assertTrue("Connection timed out" in msg or "HTTP reachability check failed" in msg)

        # When network checks fail after retry, verdict is Unknown and threat score remains 0
        with patch('services.url_analyzer.check_server_connectivity', return_value=True), \
             patch('services.url_analyzer.safe_resolve_dns', return_value=(True, ["1.2.3.4"], "Resolved")), \
             patch('services.url_analyzer.check_tls_cert', return_value=(True, {"valid": True}, "Valid TLS")), \
             patch('services.url_analyzer.check_domain_age', return_value=(False, False, "RDAP timed out")), \
             patch('services.url_analyzer.check_http_reachability', return_value=(False, "HTTP timed out")):
            res = analyze_url("https://example.com", execute_network=True)
            self.assertEqual(res["threat_score"], 0)
            self.assertEqual(res["verdict"], "Unknown")
            self.assertNotEqual(res["verdict"], "Suspicious")

    def test_redirect_normalisation_and_uppercase_hosts(self):
        """Issue 3: WWW.GOOGLE.COM/ normalises to https://www.google.com/, follows redirects safely."""
        from services.url_analyzer import normalize_url, check_http_reachability

        # Normalization
        norm1 = normalize_url("WWW.GOOGLE.COM/")
        self.assertEqual(norm1["normalized_url"], "https://www.google.com/")
        self.assertEqual(norm1["host"], "www.google.com")

        norm2 = normalize_url("www.google.com")
        self.assertEqual(norm2["normalized_url"], "https://www.google.com/")

        norm3 = normalize_url("http://www.google.com")
        self.assertEqual(norm3["normalized_url"], "http://www.google.com/")

        # Relative and protocol-relative redirect handling in check_http_reachability
        redirect_resp_1 = unittest.mock.MagicMock()
        redirect_resp_1.is_redirect = True
        redirect_resp_1.status_code = 301
        redirect_resp_1.headers = {"Location": "/search?q=test"}

        final_resp = unittest.mock.MagicMock()
        final_resp.is_redirect = False
        final_resp.status_code = 200

        with patch('services.url_analyzer.safe_resolve_dns', return_value=(True, ["1.2.3.4"], "Resolved")), \
             patch('requests.Session.get', side_effect=[redirect_resp_1, final_resp]):
            ok, msg = check_http_reachability("WWW.GOOGLE.COM/")
            self.assertTrue(ok)
            self.assertIn("HTTP 200", msg)

    def test_input_validation_whitespace_and_multiple_urls(self):
        """Issue 4: Input with whitespace or multiple URLs returns HTTP 400 with 'Enter one URL at a time'."""
        invalid_inputs = [
            "a b",
            "https://abc.xyz https://google.com",
            "https://abc.xyz,https://google.com",
            "https://abc.xyz\nhttps://google.com",
            "   https://abc.xyz   https://google.com   ",
        ]
        for bad_url in invalid_inputs:
            resp = self.app.post('/analyze', json={'url': bad_url, 'input_type': 'url'})
            self.assertEqual(resp.status_code, 400, f"Expected 400 for input: {repr(bad_url)}")
            data = json.loads(resp.data)
            self.assertEqual(data.get("error"), "Enter one URL at a time", f"Failed on input: {repr(bad_url)}")

        # Ensure single valid URLs with open redirect parameters are NOT falsely rejected
        valid_single_urls = [
            "https://abc.xyz",
            "WWW.GOOGLE.COM/",
            "https://safe-looking.com/?next=https://evil.com",
            "https://www.google.com/search?q=x8f3k2j9d0a1b7c4",
        ]
        for good_url in valid_single_urls:
            resp = self.app.post('/analyze', json={'url': good_url, 'input_type': 'url'})
            self.assertNotEqual(resp.status_code, 400, f"Valid URL was unexpectedly rejected: {good_url}")

    def test_ssrf_hardened_address_blocking(self):
        """Part A: Non-public addresses in any form (trailing-dot, decimal, hex, IPv6, IPv4-mapped, localhost, DNS rebinding)
        are blocked from DNS/TLS/RDAP/HTTP and external reputation calls.
        """
        from services.url_analyzer import analyze_url_comprehensive

        blocked_test_urls = [
            ("http://169.254.169.254.", False),
            ("http://169.254.169.254", False),
            ("http://2130706433", False),
            ("http://0x7f000001", False),
            ("http://[::1]", False),
            ("http://[::ffff:127.0.0.1]", False),
            ("http://localhost", False),
            ("http://sub.localhost:8080", False),
            ("http://test.local", False),
            ("http://app.internal", False),
            ("http://localtest.me", True),  # needs DNS resolution mock to 127.0.0.1
        ]

        expected_detail = "Blocked: private or internal address; ScamXRay does not connect to it"

        for test_url, is_rebind in blocked_test_urls:
            with patch('services.url_analyzer.check_tls_cert') as mock_tls, \
                 patch('services.url_analyzer.check_domain_age') as mock_age, \
                 patch('services.url_analyzer.check_http_reachability') as mock_http, \
                 patch('services.url_analyzer.check_openphish') as mock_op:

                if is_rebind:
                    with patch('services.url_analyzer.safe_resolve_dns', return_value=(False, ["127.0.0.1"], "Blocked: resolved to private or internal address (127.0.0.1)")):
                        res = analyze_url_comprehensive(test_url, execute_network=True)
                else:
                    res = analyze_url_comprehensive(test_url, execute_network=True)

                self.assertEqual(res["verdict"], "Unknown", f"Expected Unknown for {test_url}, got {res['verdict']}")
                self.assertIn("private", res["verdict_reason"].lower(), f"Verdict reason should mention private/internal address for {test_url}")
                
                # Verify network checks were NOT called
                mock_tls.assert_not_called()
                mock_age.assert_not_called()
                mock_http.assert_not_called()
                mock_op.assert_not_called()

                # Verify all verification checks show not_performed with the required detail
                for check in res["verification_checks"]:
                    self.assertEqual(check["status"], "not_performed", f"Check {check['name']} not 'not_performed' for {test_url}")
                    self.assertEqual(check["details"], expected_detail, f"Check {check['name']} detail mismatch for {test_url}")

                # Verify evidence shows not_checked
                for ev in res["evidence"]:
                    if ev.get("source") == "OpenPhish Community Feed":
                        self.assertEqual(ev.get("status"), "not_checked", f"Reputation source {ev['source']} should be not_checked for {test_url}")
                        self.assertIn("blocked", ev.get("result", "").lower())

    def test_unsupported_schemes_rejected_400(self):
        """Part A: Schemes other than http and https return HTTP 400 with 'Only http and https links are supported'."""
        bad_schemes = [
            "file:///etc/passwd",
            "ftp://example.com/files",
            "javascript:alert(1)",
            "data:text/html,<html>test</html>",
            "gopher://gopher.floodgap.com",
            "mailto:admin@example.com",
        ]
        for bad_url in bad_schemes:
            resp = self.app.post('/analyze', json={'url': bad_url, 'input_type': 'url'})
            self.assertEqual(resp.status_code, 400, f"Expected 400 for scheme: {bad_url}")
            data = json.loads(resp.data)
            self.assertEqual(data.get("error"), "Only http and https links are supported", f"Failed for {bad_url}")

    def test_public_ip_literal_is_suspicious_and_checked(self):
        """Part A: Public IP literals such as http://8.8.8.8/login must still be Suspicious and go through normal checks."""
        with patch('services.url_analyzer.check_server_connectivity', return_value=True), \
             patch('services.url_analyzer.check_tls_cert', return_value=(False, {"valid": False}, "URL specifies unencrypted HTTP protocol")), \
             patch('services.url_analyzer.check_domain_age', return_value=(False, False, "Private IP or local host has no public domain registry")), \
             patch('services.url_analyzer.check_http_reachability', return_value=(True, "Reachable (HTTP 200)")):
            res = analyze_url("http://8.8.8.8/login", execute_network=True)
            self.assertEqual(res["verdict"], "Suspicious")
            self.assertGreaterEqual(res["threat_score"], 35)
            self.assertTrue(any(i["id"] == "ip_literal_host" for i in res["indicators"]))
            dns_chk = next(c for c in res["verification_checks"] if c["name"] == "DNS Resolution")
            self.assertEqual(dns_chk["status"], "performed")

    def test_openphish_reputation_and_verdict_rules(self):
        """OpenPhish reputation lookup and verdict rules:
        - match -> Malicious (threat_score 100)
        - no_match + clean infrastructure -> No threat found
        - feed unavailable (failed) + clean infrastructure -> Unknown (A reputation check could not be completed)
        - feed unavailable does not raise verdict to Suspicious or Malicious
        """
        # 1. Match -> Malicious
        with patch('services.url_analyzer.check_openphish', return_value={
            "source": "OpenPhish", "status": "match", "detail": "Matched active OpenPhish entry"
        }), \
             patch('services.url_analyzer.check_server_connectivity', return_value=True), \
             patch('services.url_analyzer.safe_resolve_dns', return_value=(True, ["93.184.216.34"], "Resolved")), \
             patch('services.url_analyzer.check_tls_cert', return_value=(True, {"valid": True}, "Valid TLS")), \
             patch('services.url_analyzer.check_domain_age', return_value=(True, True, "Established (registered 2018)")), \
             patch('services.url_analyzer.check_http_reachability', return_value=(True, "HTTP 200 OK")):
            res_mal = analyze_url("https://phishing-site-test.com/login", execute_network=True)
            self.assertEqual(res_mal["verdict"], "Malicious")
            self.assertEqual(res_mal["threat_score"], 100)
            op_ev = next(e for e in res_mal["evidence"] if e["source"] == "OpenPhish Community Feed")
            self.assertEqual(op_ev["status"], "match")

        # 2. No match + clean infrastructure -> No threat found
        with patch('services.url_analyzer.check_openphish', return_value={
            "source": "OpenPhish", "status": "no_match", "detail": "Not in feed"
        }), \
             patch('services.url_analyzer.check_server_connectivity', return_value=True), \
             patch('services.url_analyzer.safe_resolve_dns', return_value=(True, ["93.184.216.34"], "Resolved")), \
             patch('services.url_analyzer.check_tls_cert', return_value=(True, {"valid": True}, "Valid TLS")), \
             patch('services.url_analyzer.check_domain_age', return_value=(True, True, "Established (registered 2018)")), \
             patch('services.url_analyzer.check_http_reachability', return_value=(True, "HTTP 200 OK")):
            res_clean = analyze_url("https://clean-site-test.com", execute_network=True)
            self.assertEqual(res_clean["verdict"], "No threat found")
            self.assertEqual(res_clean["threat_score"], 0)
            op_ev = next(e for e in res_clean["evidence"] if e["source"] == "OpenPhish Community Feed")
            self.assertEqual(op_ev["status"], "no_match")

        # 3. Feed unavailable (failed) + clean infrastructure -> Unknown
        with patch('services.url_analyzer.check_openphish', return_value={
            "source": "OpenPhish", "status": "not_checked", "detail": "Feed unavailable", "failed": True
        }), \
             patch('services.url_analyzer.check_server_connectivity', return_value=True), \
             patch('services.url_analyzer.safe_resolve_dns', return_value=(True, ["93.184.216.34"], "Resolved")), \
             patch('services.url_analyzer.check_tls_cert', return_value=(True, {"valid": True}, "Valid TLS")), \
             patch('services.url_analyzer.check_domain_age', return_value=(True, True, "Established (registered 2018)")), \
             patch('services.url_analyzer.check_http_reachability', return_value=(True, "HTTP 200 OK")):
            res_unavail = analyze_url("https://clean-site-test.com", execute_network=True)
            self.assertEqual(res_unavail["verdict"], "Unknown")
            self.assertEqual(res_unavail["threat_score"], 0)
            self.assertEqual(res_unavail["verdict_reason"], "A reputation check could not be completed (OpenPhish feed unavailable)")
            op_ev = next(e for e in res_unavail["evidence"] if e["source"] == "OpenPhish Community Feed")
            self.assertEqual(op_ev["status"], "not_checked")

    def test_amazon_india_recruitment_spans_and_flags(self):
        """Test Amazon India fixture: 4 flags, exact phrase spans, and unflagged text has no spans."""
        from services.rule_engine import get_rule_analysis

        fixture = (
            "Amazon India\n"
            "Work From Home 2026 Recruitment\n"
            "@ Salary: Rs.50,000/month\n"
            "@ Hours: 2-3 hours daily only\n"
            "Processing Fee: Rs.599 (One Time)\n"
            "Contact HR Priya: +91 99887 76655\n"
            "WhatsApp Only No Calls Please"
        )

        res = get_rule_analysis(fixture)
        matches = res["matches"]

        # Exactly 4 flags listed
        self.assertEqual(len(matches), 4)
        matched_rules = {m["rule"]: m for m in matches}

        expected_rules = {
            "Unexpected payment request",
            "Suspicious job offer",
            "Suspicious communication channel",
            "Upfront fee for a job",
        }
        self.assertEqual(set(matched_rules.keys()), expected_rules)

        # Check matched_text and spans for each
        # 1. Unexpected payment request
        m_pay = matched_rules["Unexpected payment request"]
        self.assertEqual(m_pay["matched_text"], "Processing Fee")
        self.assertEqual(len(m_pay["spans"]), 1)
        s = m_pay["spans"][0]
        self.assertEqual(fixture[s["start"]:s["end"]], "Processing Fee")

        # 2. Upfront fee for a job
        m_fee = matched_rules["Upfront fee for a job"]
        self.assertEqual(m_fee["matched_text"], "Processing Fee")
        self.assertEqual(len(m_fee["spans"]), 1)
        s = m_fee["spans"][0]
        self.assertEqual(fixture[s["start"]:s["end"]], "Processing Fee")

        # 3. Suspicious job offer
        m_hours = matched_rules["Suspicious job offer"]
        self.assertEqual(m_hours["matched_text"], "2-3 hours daily")
        self.assertEqual(len(m_hours["spans"]), 1)
        s = m_hours["spans"][0]
        self.assertEqual(fixture[s["start"]:s["end"]], "2-3 hours daily")

        # 4. Suspicious communication channel
        m_wa = matched_rules["Suspicious communication channel"]
        self.assertEqual(m_wa["matched_text"], "WhatsApp Only")
        self.assertEqual(len(m_wa["spans"]), 1)
        s = m_wa["spans"][0]
        self.assertEqual(fixture[s["start"]:s["end"]], "WhatsApp Only")

        # Verify every span lines up with fixture text
        for m in matches:
            for sp in m["spans"]:
                self.assertEqual(fixture[sp["start"]:sp["end"]], m["matched_text"])

        # Verify nothing without a flag is covered by spans
        all_flagged_intervals = [
            (sp["start"], sp["end"])
            for m in matches
            for sp in m["spans"]
        ]
        salary_idx = fixture.find("Rs.50,000/month")
        priya_idx = fixture.find("HR Priya: +91 99887 76655")
        no_calls_idx = fixture.find("No Calls Please")

        for start, end in all_flagged_intervals:
            self.assertFalse(start <= salary_idx < end, "Salary should not be inside any flag span")
            self.assertFalse(start <= priya_idx < end, "Contact HR Priya should not be inside any flag span")
            self.assertFalse(start <= no_calls_idx < end, "No Calls Please should not be inside any flag span")

    def test_span_alignment_including_ocr_cleaning(self):
        """Test that spans line up with text (text[start:end] == matched_text) after OCR cleaning."""
        from services.rule_engine import get_rule_analysis
        import re

        raw_ocr = (
            "Amazon India\r\n"
            "Work From Home 2026 Recruitment\r\n\r\n"
            "@ Salary: Rs.50,000/month\r\n"
            "@ Hours:   2-3 hours daily only\r\n\r\n"
            "Processing   Fee: Rs.599 (One Time)\r\n"
            "WhatsApp Only   No Calls Please\x00\x07"
        )
        # Mimic useOCR cleanOCRText
        cleaned = raw_ocr.replace('\r\n', '\n')
        cleaned = re.sub(r'[ \t]+', ' ', cleaned)
        cleaned = re.sub(r'\n{3,}', '\n\n', cleaned)
        cleaned = re.sub(r'[^\x20-\x7E\n₹@.]', '', cleaned).strip()

        res = get_rule_analysis(cleaned)
        self.assertGreater(len(res["matches"]), 0)
        for m in res["matches"]:
            if m["spans"]:
                for sp in m["spans"]:
                    sliced = cleaned[sp["start"]:sp["end"]]
                    self.assertEqual(sliced, m["matched_text"])

    def test_behavioral_flag_has_no_spans(self):
        """Test that behavioral flags like multiple clustered roles appear in list but have spans = []."""
        from services.rule_engine import get_rule_analysis

        text = "Hiring immediately for Back Office / Data Entry / Receptionist. Apply today."
        res = get_rule_analysis(text)
        cluster_m = next((m for m in res["matches"] if m["rule"] == "Multiple clustered job roles in informal notice"), None)
        self.assertIsNotNone(cluster_m)
        self.assertEqual(cluster_m["spans"], [])
        self.assertEqual(cluster_m["matched_text"], "")

    def test_emoji_phrase_highlight_spans(self):
        """Test that emojis (🔴, ✅, 📲, ₹) do not shift rule spans; text[start:end] == matched_text."""
        from services.rule_engine import get_rule_analysis

        text = (
            "🔴 URGENT HIRING 🔴\n\n"
            "Work From Home Opportunity!!\n"
            "Earn ₹45,000 - ₹50,000 Per Week\n"
            "✅ No Experience Required\n"
            "✅ No Interview\n"
            "✅ Immediate Joining\n"
            "✅ Part Time / Full Time\n\n"
            "Registration Fee: ₹499 only\n"
            "(Refundable after 1st salary)\n\n"
            "Contact HR: +91 98765 4321 0\n"
            "WhatsApp Only 📲\n\n"
            "⚠️ Limited Seats Available\n"
            "Apply Before 6PM Today!!"
        )
        res = get_rule_analysis(text)
        self.assertGreaterEqual(len(res["matches"]), 4)

        matched_phrases = set()
        for m in res["matches"]:
            for sp in m["spans"]:
                sliced = text[sp["start"]:sp["end"]]
                self.assertEqual(sliced, m["matched_text"])
                self.assertGreater(sp["end"], sp["start"])
                matched_phrases.add(sliced)

        self.assertIn("URGENT", matched_phrases)
        self.assertIn("No Experience Required", matched_phrases)
        self.assertIn("Registration Fee", matched_phrases)
        self.assertIn("WhatsApp Only", matched_phrases)

    def test_multi_code_point_emoji_sequence_spans(self):
        """Test that multi-code-point emoji sequences (e.g. 👨👩👧, 👨‍👩‍👧) align exact spans."""
        from services.rule_engine import get_rule_analysis

        text = (
            "👨👩👧 URGENT HIRING 👨‍👩‍👧\n"
            "Registration Fee: ₹499 only\n"
            "WhatsApp Only 📲"
        )
        res = get_rule_analysis(text)
        for m in res["matches"]:
            for sp in m["spans"]:
                sliced = text[sp["start"]:sp["end"]]
                self.assertEqual(sliced, m["matched_text"])

    def test_crlf_normalization_in_analyze_endpoint(self):
        """Test that /analyze normalizes CRLF and returns identical matched text and spans."""
        payload_text = (
            "🔴 URGENT HIRING 🔴\r\n"
            "Work From Home Opportunity!!\r\n"
            "Earn ₹45,000 - ₹50,000 Per Week\r\n"
            "✅ No Experience Required\r\n"
            "Registration Fee: ₹499 only\r\n"
            "WhatsApp Only 📲"
        )
        resp = self.app.post("/analyze", json={"text": payload_text, "url": ""})
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()

        returned_text = data["jobText"]
        self.assertNotIn("\r", returned_text)

        matches = data["matches"]
        self.assertGreaterEqual(len(matches), 4)
        for m in matches:
            for sp in m["spans"]:
                sliced = returned_text[sp["start"]:sp["end"]]
                self.assertEqual(sliced, m["matched_text"])




if __name__ == '__main__':
    unittest.main()

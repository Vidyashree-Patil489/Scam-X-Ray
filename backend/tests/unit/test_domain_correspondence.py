import os
import sys
import unittest

# Ensure backend root is in sys.path
_BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _BACKEND_DIR not in sys.path:
    sys.path.insert(0, _BACKEND_DIR)

from services.rule_engine import does_domain_correspond_to_company


class TestDomainCorrespondence(unittest.TestCase):
    """
    Unit tests for company name to email/link domain correspondence logic.
    Ensures legitimate corporate domains match and spoofed/lookalike domains fail.
    """

    def test_01_tcs_official_domain(self):
        self.assertTrue(does_domain_correspond_to_company("tcs.com", "tcs", "TCS"))

    def test_02_tcs_lookalike_domain(self):
        self.assertFalse(does_domain_correspond_to_company("tcs-hiring.in", "tcs-hiring", "TCS"))

    def test_03_infosys_official_domain(self):
        self.assertTrue(does_domain_correspond_to_company("infosys.com", "infosys", "Infosys Limited"))

    def test_04_infosys_lookalike_domain(self):
        self.assertFalse(does_domain_correspond_to_company("infosys-careers.in", "infosys-careers", "Infosys Limited"))

    def test_05_zoho_official_domain(self):
        self.assertTrue(does_domain_correspond_to_company("zoho.com", "zoho", "Zoho Corporation"))

    def test_06_zoho_lookalike_domain(self):
        self.assertFalse(does_domain_correspond_to_company("zoho-jobs.xyz", "zoho-jobs", "Zoho Corporation"))

    def test_07_zoho_subdomain_careers(self):
        self.assertTrue(does_domain_correspond_to_company("zoho.com", "zoho", "Zoho Corporation"))


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3

import unittest

from search_vulns.core import search_vulns
from search_vulns.models.SearchVulnsResult import VersionStatus


class TestSearches(unittest.TestCase):

    def test_search_wp_general(self):
        self.maxDiff = None
        query = "cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*"
        result = search_vulns(query=query, is_product_id_query=True)
        expected_result = {
            "status": VersionStatus.N_A,
            "latest": "6.9.0",
            "reference": "https://endoflife.date/wordpress",
        }
        self.assertEqual(result.version_status.model_dump(), expected_result)

    def test_search_wp_572(self):
        self.maxDiff = None
        query = "cpe:2.3:a:wordpress:wordpress:5.7.2:*:*:*:*:*:*:*"
        result = search_vulns(query=query, is_product_id_query=True)
        expected_result = {
            "status": VersionStatus.EOL,
            "latest": "6.9.0",
            "reference": "https://endoflife.date/wordpress",
        }
        self.assertEqual(result.version_status.model_dump(), expected_result)

    def test_search_jquery_general(self):
        self.maxDiff = None
        query = "cpe:2.3:a:jquery:jquery:*:*:*:*:*:*:*:*"
        result = search_vulns(query=query, is_product_id_query=True)
        expected_result = {
            "status": VersionStatus.N_A,
            "latest": "4.0.0",
            "reference": "https://endoflife.date/jquery",
        }
        self.assertEqual(result.version_status.model_dump(), expected_result)

    def test_search_jquery_213(self):
        self.maxDiff = None
        query = "cpe:2.3:a:jquery:jquery:2.1.3:*:*:*:*:*:*:*"
        result = search_vulns(query=query, is_product_id_query=True)
        expected_result = {
            "status": VersionStatus.EOL,
            "latest": "4.0.0",
            "reference": "https://endoflife.date/jquery",
        }
        self.assertEqual(result.version_status.model_dump(), expected_result)

    def test_search_mongodb_4_4_29(self):
        self.maxDiff = None
        query = "cpe:2.3:a:mongodb:mongodb:4.4.29:*:*:*:*:*:*:*"
        result = search_vulns(query=query, is_product_id_query=True)
        expected_result = {
            "status": VersionStatus.EOL,
            "latest": "8.2.3",
            "reference": "https://endoflife.date/mongodb",
        }
        self.assertEqual(result.version_status.model_dump(), expected_result)

    def test_search_mongodb_7_0_13(self):
        self.maxDiff = None
        query = "cpe:2.3:a:mongodb:mongodb:7.0.13:*:*:*:*:*:*:*"
        result = search_vulns(query=query, is_product_id_query=True)
        expected_result = {
            "status": VersionStatus.OUTDATED,
            "latest": "7.0.28",
            "reference": "https://endoflife.date/mongodb",
        }
        self.assertEqual(result.version_status.model_dump(), expected_result)


if __name__ == "__main__":
    unittest.main()

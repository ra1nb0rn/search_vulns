#!/usr/bin/env python3

import os
import unittest
import sys

SEARCH_VULNS_PATH = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
sys.path.insert(1, SEARCH_VULNS_PATH)
from search_vulns_modules.search_vulns_functions import search_vulns

class TestSearches(unittest.TestCase):

    def test_search_fastify_bearer_auth_50(self):
        self.maxDiff = None
        query = 'cpe:2.3:a:fastify:bearer-auth:5.0:*:*:*:*:node.js:*:*'
        result,_ = search_vulns(query=query, add_other_exploit_refs=True, is_good_cpe=True)
        expected_cves = []
        self.assertEqual(set(expected_cves), set(list(result[query]['vulns'].keys())))


    def test_search_vbulletin_vbulletin_55(self):
        self.maxDiff = None
        query = 'cpe:2.3:a:vbulletin:vbulletin:5.5:*:*:*:*:*:*:*'
        result,_ = search_vulns(query=query, add_other_exploit_refs=True, is_good_cpe=True)
        expected_cves = ['CVE-2023-39777', 'CVE-2020-12720', 'CVE-2019-17271', 'CVE-2019-17132', 'CVE-2019-17131', 'CVE-2019-17130', 'CVE-2019-16759']
        self.assertEqual(set(expected_cves), set(list(result[query]['vulns'].keys())))


    def test_search_vbulletin_vbulletin_56(self):
        self.maxDiff = None
        query = 'cpe:2.3:a:vbulletin:vbulletin:5.6:*:*:*:*:*:*:*'
        result,_ = search_vulns(query=query, add_other_exploit_refs=True, is_good_cpe=True)
        expected_cves = ['CVE-2023-39777', 'CVE-2020-7373', 'CVE-2020-17496', 'CVE-2020-12720']
        self.assertEqual(set(expected_cves), set(list(result[query]['vulns'].keys())))



if __name__ == '__main__':
    unittest.main()
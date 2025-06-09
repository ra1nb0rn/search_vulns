#!/usr/bin/env python3

import os
import sys
import unittest

SEARCH_VULNS_PATH = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
sys.path.insert(1, SEARCH_VULNS_PATH)
import search_vulns


class TestSearches(unittest.TestCase):

    def test_search_nginx(self):
        self.maxDiff = None
        query = "cpe:2.3:a:nginx:nginx:1.24.0-3:*:*:*:*:*:*:debian_trixie"
        result = search_vulns.search_vulns(query=query, include_patched=True)
        expected_open = ["CVE-2024-7347", "CVE-2025-23419"]
        expected_backpatched = ["CVE-2023-44487"]
        result_open, result_backpatched = [], []

        for vuln_id, vuln in result["vulns"].items():
            if vuln.reported_patched_by:
                result_backpatched.append(vuln_id)
            else:
                result_open.append(vuln_id)

        self.assertEqual(set(expected_backpatched), set(result_backpatched))
        self.assertEqual(set(expected_open), set(result_open))

    def test_search_curl(self):
        self.maxDiff = None
        query = "curl 7.88.1-11+deb12u10"
        result = search_vulns.search_vulns(query=query, include_patched=True)

        expected_open = ["CVE-2025-0725", "CVE-2024-32928"]
        expected_backpatched = [
            "CVE-2023-46219",
            "CVE-2023-38039",
            "CVE-2023-28322",
            "CVE-2024-9681",
            "CVE-2023-27534",
            "CVE-2023-28321",
            "CVE-2023-28320",
            "CVE-2023-27533",
            "CVE-2023-46218",
            "CVE-2023-28319",
            "CVE-2023-38545",
            "CVE-2023-27536",
            "CVE-2023-38546",
            "CVE-2024-7264",
            "CVE-2023-27537",
            "CVE-2023-27535",
            "CVE-2023-27538",
            "CVE-2024-2004",
            "CVE-2024-8096",
            "CVE-2024-2398",
            "CVE-2025-0167",
            "CVE-2024-11053",
        ]
        result_open, result_backpatched = [], []

        for vuln_id, vuln in result["vulns"].items():
            if vuln.reported_patched_by:
                result_backpatched.append(vuln_id)
            else:
                result_open.append(vuln_id)

        self.assertEqual(set(expected_backpatched), set(result_backpatched))
        self.assertEqual(set(expected_open), set(result_open))

    def test_search_thunderbird(self):
        self.maxDiff = None
        query = "squid 5.7-2 Debian 12"
        result = search_vulns.search_vulns(query=query, include_patched=True)

        expected_open = ["CVE-2023-49288", "CVE-2024-45802", "CVE-2023-5824", "CVE-2023-46728"]
        expected_backpatched = [
            "CVE-2024-23638",
            "CVE-2023-50269",
            "CVE-2023-46847",
            "CVE-2024-25617",
            "CVE-2023-46846",
            "CVE-2024-25111",
            "CVE-2023-49286",
            "CVE-2023-46724",
            "CVE-2023-49285",
            "CVE-2023-46848",
            "CVE-2024-37894",
        ]
        result_open, result_backpatched = [], []

        for vuln_id, vuln in result["vulns"].items():
            if vuln.reported_patched_by:
                result_backpatched.append(vuln_id)
            else:
                result_open.append(vuln_id)

        self.assertEqual(set(expected_backpatched), set(result_backpatched))
        self.assertEqual(set(expected_open), set(result_open))


if __name__ == "__main__":
    unittest.main()

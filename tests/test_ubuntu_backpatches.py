#!/usr/bin/env python3

import unittest

from search_vulns.core import search_vulns


class TestSearches(unittest.TestCase):

    def test_search_openssh(self):
        self.maxDiff = None
        query = "cpe:2.3:a:openssh:openssh:8.2:p1:*:*:*:*:*:ubuntu_focal_8.2p1-4ubuntu0.13"
        result = search_vulns(query=query, include_patched=True)

        expected_open = ["CVE-2007-2768", "CVE-2008-3844", "CVE-2025-61984", "CVE-2025-61985"]
        expected_backpatched = [
            "CVE-2020-14145",
            "CVE-2020-15778",
            "CVE-2025-26465",
            "CVE-2023-51385",
            "CVE-2023-38408",
            "CVE-2023-48795",
            "CVE-2023-51767",
            "CVE-2021-36368",
            "CVE-2014-9278",
            "CVE-2021-41617",
            "CVE-2016-20012",
            "CVE-2025-32728",
            "CVE-2020-12062",
            "CVE-2021-28041",
        ]
        result_open, result_backpatched = [], []

        for vuln_id, vuln in result["vulns"].items():
            if vuln.reported_patched_by:
                result_backpatched.append(vuln_id)
            else:
                result_open.append(vuln_id)

        self.assertEqual(set(expected_backpatched), set(result_backpatched))
        self.assertEqual(set(expected_open), set(result_open))

    def test_search_squid(self):
        self.maxDiff = None
        query = "squid 5.7-2 Ubuntu Focal"
        result = search_vulns(query=query, include_patched=True)

        expected_open = ["CVE-2024-45802"]
        expected_backpatched = [
            "CVE-2023-46728",
            "CVE-2023-49285",
            "CVE-2024-23638",
            "CVE-2025-59362",
            "CVE-2023-50269",
            "CVE-2023-5824",
            "CVE-2024-37894",
            "CVE-2023-46848",
            "CVE-2023-46724",
            "CVE-2024-25111",
            "CVE-2025-62168",
            "CVE-2023-46846",
            "CVE-2023-49286",
            "CVE-2023-46847",
            "CVE-2024-25617",
            "CVE-2023-49288",
            "CVE-2025-54574",
        ]
        result_open, result_backpatched = [], []

        for vuln_id, vuln in result["vulns"].items():
            if vuln.reported_patched_by:
                result_backpatched.append(vuln_id)
            else:
                result_open.append(vuln_id)

        self.assertEqual(set(expected_backpatched), set(result_backpatched))
        self.assertEqual(set(expected_open), set(result_open))

    def test_search_mariadb(self):
        self.maxDiff = None
        query = "apache tomcat 9.0.70-2 ubuntu 25.04"
        result = search_vulns(query=query, include_patched=True)

        expected_open = [
            "CVE-2024-38286",
            "CVE-2023-42795",
            "CVE-2023-45648",
            "CVE-2024-34750",
            "CVE-2024-24549",
            "CVE-2023-44487",
            "CVE-2023-46589",
            "CVE-2025-24813",
            "CVE-2023-28708",
            "CVE-2024-23672",
            "CVE-2024-50379",
            "CVE-2016-6325",
            "CVE-2016-5425",
        ]
        expected_backpatched = [
            "CVE-2025-55752",
            "CVE-2025-48989",
            "CVE-2023-42794",
            "CVE-2025-52520",
            "CVE-2025-52434",
            "CVE-2024-54677",
            "CVE-2024-52316",
            "CVE-2025-55754",
            "CVE-2025-55668",
            "CVE-2024-56337",
            "CVE-2025-49124",
            "CVE-2025-61795",
            "CVE-2023-41080",
            "CVE-2025-46701",
            "CVE-2025-31651",
            "CVE-2025-49125",
            "CVE-2025-48988",
            "CVE-2025-53506",
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

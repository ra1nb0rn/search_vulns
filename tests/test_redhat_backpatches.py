#!/usr/bin/env python3

import unittest

from search_vulns.core import search_vulns


class TestSearches(unittest.TestCase):

    def test_search_nginx(self):
        self.maxDiff = None
        query = "nginx 1.20.1-22 RHEL 9.2"
        result = search_vulns(query=query, include_patched=True)

        expected_open = ["CVE-2025-53859"]
        expected_backpatched = [
            "CVE-2024-7347",
            "CVE-2022-41742",
            "CVE-2022-41741",
            "CVE-2025-23419",
            "CVE-2021-3618",
            "CVE-2023-44487",
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
        query = "cpe:2.3:a:squid-cache:squid:5.5:*:*:*:*:*:*:rhel_9.2_5.5-5"
        result = search_vulns(query=query, include_patched=True, is_product_id_query=True)

        expected_open = ["CVE-2022-41317", "CVE-2025-59362"]
        expected_backpatched = [
            "CVE-2023-46728",
            "CVE-2023-50269",
            "CVE-2024-25617",
            "CVE-2025-54574",
            "CVE-2023-46847",
            "CVE-2023-5824",
            "CVE-2023-46848",
            "CVE-2025-62168",
            "CVE-2023-49288",
            "CVE-2024-25111",
            "CVE-2023-46846",
            "CVE-2024-23638",
            "CVE-2023-49285",
            "CVE-2022-41318",
            "CVE-2024-45802",
            "CVE-2021-46784",
            "CVE-2023-49286",
            "CVE-2024-37894",
            "CVE-2023-46724",
        ]
        result_open, result_backpatched = [], []

        for vuln_id, vuln in result["vulns"].items():
            if vuln.reported_patched_by:
                result_backpatched.append(vuln_id)
            else:
                result_open.append(vuln_id)

        self.assertEqual(set(expected_backpatched), set(result_backpatched))
        self.assertEqual(set(expected_open), set(result_open))

    def test_search_apache(self):
        self.maxDiff = None
        query = "apache 2.4.37-43.el8_5.0"
        result = search_vulns(query=query, include_patched=True)

        expected_open = [
            "CVE-1999-0289",
            "CVE-2024-43204",
            "CVE-1999-1412",
            "CVE-2025-3891",
            "CVE-2024-42516",
            "CVE-1999-0678",
            "CVE-2007-0450",
            "CVE-1999-1237",
            "CVE-2007-0086",
            "CVE-2019-17567",
            "CVE-2024-24795",
            "CVE-2025-53020",
            "CVE-2010-1151",
            "CVE-2008-2717",
        ]
        expected_backpatched = [
            "CVE-2022-36760",
            "CVE-2018-17189",
            "CVE-2019-9517",
            "CVE-2021-40438",
            "CVE-2023-45802",
            "CVE-2022-22721",
            "CVE-2006-20001",
            "CVE-2022-23943",
            "CVE-2019-10097",
            "CVE-2020-35452",
            "CVE-2020-11993",
            "CVE-2025-23048",
            "CVE-2019-0220",
            "CVE-2020-9490",
            "CVE-2025-65082",
            "CVE-2022-37436",
            "CVE-2023-27522",
            "CVE-2019-10082",
            "CVE-2024-38476",
            "CVE-2022-22720",
            "CVE-2022-30556",
            "CVE-2024-38474",
            "CVE-2021-44790",
            "CVE-2022-29404",
            "CVE-2022-31813",
            "CVE-2025-66200",
            "CVE-2019-0197",
            "CVE-2019-0215",
            "CVE-2019-10092",
            "CVE-2024-38473",
            "CVE-2021-26691",
            "CVE-2020-11984",
            "CVE-2019-0190",
            "CVE-2020-1934",
            "CVE-2019-10081",
            "CVE-2022-28330",
            "CVE-2018-17199",
            "CVE-2019-10098",
            "CVE-2024-27316",
            "CVE-2019-0211",
            "CVE-2021-34798",
            "CVE-2025-58098",
            "CVE-2024-38472",
            "CVE-2024-39573",
            "CVE-2024-40898",
            "CVE-2019-0196",
            "CVE-2025-49630",
            "CVE-2021-36160",
            "CVE-2022-26377",
            "CVE-2025-49812",
            "CVE-2021-39275",
            "CVE-2020-13938",
            "CVE-2019-0217",
            "CVE-2024-38475",
            "CVE-2024-47252",
            "CVE-2025-55753",
            "CVE-2021-33193",
            "CVE-2025-59775",
            "CVE-2021-44224",
            "CVE-2021-26690",
            "CVE-2020-1927",
            "CVE-2022-28615",
            "CVE-2022-28614",
            "CVE-2023-25690",
            "CVE-2023-38709",
            "CVE-2024-43394",
            "CVE-2023-31122",
            "CVE-2022-22719",
            "CVE-2024-38477",
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

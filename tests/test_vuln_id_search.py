#!/usr/bin/env python3

import unittest

from search_vulns.core import search_vulns


class TestSearches(unittest.TestCase):

    def test_search_cve_ghsa_ids1(self):
        self.maxDiff = None
        query = "CVE-2024-27286, GHSA-hfjr-m75m-wmh7, CVE-2024-12345678"
        result = search_vulns(query)
        expected_vulns = {
            "CVE-2024-27286": {
                "published": "2024-03-20 20:15:08",
                "cvss_ver": "3.1",
                "cvss": "6.5",
                "cvss_vec": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
                "cisa_known_exploited": False,
            },
            "CVE-2024-12345678": {
                "published": "",
                "cvss_ver": "",
                "cvss": "-1.0",
                "cvss_vec": "",
                "cisa_known_exploited": False,
            },
            "GHSA-hfjr-m75m-wmh7": {
                "published": "2022-05-24 16:59:38",
                "cvss_ver": "3.1",
                "cvss": "7.8",
                "cvss_vec": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
                "cisa_known_exploited": False,
            },
        }

        self.assertEqual(set(expected_vulns.keys()), set(result["vulns"].keys()))

        for vuln_id, vuln in result["vulns"].items():
            vuln_attrs = vuln.to_dict()
            self.assertEqual(vuln_attrs["published"], expected_vulns[vuln_id]["published"])
            self.assertEqual(vuln_attrs["cvss_ver"], expected_vulns[vuln_id]["cvss_ver"])
            self.assertEqual(vuln_attrs["cvss"], expected_vulns[vuln_id]["cvss"])
            self.assertEqual(vuln_attrs["cvss_vec"], expected_vulns[vuln_id]["cvss_vec"])
            self.assertEqual(
                vuln_attrs["cisa_known_exploited"],
                expected_vulns[vuln_id]["cisa_known_exploited"],
            )

    def test_search_cve_ghsa_ids2(self):
        self.maxDiff = None
        # GHSA-6c3j-c64m-qhgq should be deduplicated to CVE-2019-11358
        query = (
            "CVE-2015-9251 ;;asd GHSA-6c3j-c64m-qhgq iuhnd CVE-2019-11358 .121w CVE-2007-2379"
        )
        result = search_vulns(query)
        expected_vulns = {
            "CVE-2015-9251": {
                "published": "2018-01-18 23:29:00",
                "cvss_ver": "3.0",
                "cvss": "6.1",
                "cvss_vec": "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                "cisa_known_exploited": False,
                "aliases": {
                    "CVE-2015-9251": "https://nvd.nist.gov/vuln/detail/CVE-2015-9251",
                    "GHSA-rmxg-73gg-4p98": "https://github.com/advisories/GHSA-rmxg-73gg-4p98",
                },
            },
            "CVE-2019-11358": {
                "published": "2019-04-20 00:29:00",
                "cvss_ver": "3.1",
                "cvss": "6.1",
                "cvss_vec": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                "cisa_known_exploited": False,
                "aliases": {
                    "CVE-2019-11358": "https://nvd.nist.gov/vuln/detail/CVE-2019-11358",
                    "GHSA-6c3j-c64m-qhgq": "https://github.com/advisories/GHSA-6c3j-c64m-qhgq",
                },
            },
            "CVE-2007-2379": {
                "published": "2007-04-30 23:19:00",
                "cvss_ver": "2.0",
                "cvss": "5.0",
                "cvss_vec": "AV:N/AC:L/Au:N/C:P/I:N/A:N",
                "cisa_known_exploited": False,
                "aliases": {"CVE-2007-2379": "https://nvd.nist.gov/vuln/detail/CVE-2007-2379"},
            },
        }
        self.assertEqual(set(expected_vulns.keys()), set(result["vulns"].keys()))
        for vuln_id, vuln in result["vulns"].items():
            vuln_attrs = vuln.to_dict()
            self.assertEqual(vuln_attrs["published"], expected_vulns[vuln_id]["published"])
            self.assertEqual(vuln_attrs["cvss_ver"], expected_vulns[vuln_id]["cvss_ver"])
            self.assertEqual(vuln_attrs["cvss"], expected_vulns[vuln_id]["cvss"])
            self.assertEqual(vuln_attrs["cvss_vec"], expected_vulns[vuln_id]["cvss_vec"])
            self.assertEqual(
                vuln_attrs["cisa_known_exploited"],
                expected_vulns[vuln_id]["cisa_known_exploited"],
            )
            self.assertEqual(vuln_attrs["aliases"], expected_vulns[vuln_id]["aliases"])


if __name__ == "__main__":
    unittest.main()

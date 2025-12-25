#!/usr/bin/env python3

import unittest

from search_vulns.core import search_vulns


class TestSearches(unittest.TestCase):

    def test_search_handlebars_js_300(self):
        self.maxDiff = None
        query = "cpe:2.3:a:handlebarsjs:handlebars:3.0.0:*:*:*:*:node.js:*:*"
        result = search_vulns(query=query, is_product_id_query=False)
        expected_vulns = {
            "CVE-2021-23369": "GHSA-f2jv-r9rf-7988",
            "CVE-2019-20920": "GHSA-3cqr-58rm-57f8",
            "CVE-2021-23383": "GHSA-765h-qjxv-5f44",
            "CVE-2019-19919": "GHSA-w457-6q6x-cgp9",
            "CVE-2015-8861": "GHSA-9prh-257w-9277",
            "GHSA-g9r4-xpmj-mj65": {
                "published": "2020-09-04 15:06:32",
                "cvss_ver": "",
                "cvss": "-1.0",
                "cvss_vec": "",
                "aliases": {
                    "GHSA-g9r4-xpmj-mj65": "https://github.com/advisories/GHSA-g9r4-xpmj-mj65"
                },
            },
            "GHSA-q42p-pg8m-cqh6": {
                "published": "2019-06-05 14:07:48",
                "cvss_ver": "3.1",
                "cvss": "7.3",
                "cvss_vec": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L",
                "aliases": {
                    "GHSA-q42p-pg8m-cqh6": "https://github.com/advisories/GHSA-q42p-pg8m-cqh6"
                },
            },
            "GHSA-2cf5-4w76-r9qv": {
                "published": "2020-09-04 14:57:38",
                "cvss_ver": "3.1",
                "cvss": "7.3",
                "cvss_vec": "CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:C/C:L/I:H/A:L",
                "aliases": {
                    "GHSA-2cf5-4w76-r9qv": "https://github.com/advisories/GHSA-2cf5-4w76-r9qv"
                },
            },
            "GHSA-q2c6-c6pm-g3gh": {
                "published": "2020-09-04 15:07:38",
                "cvss_ver": "",
                "cvss": "-1.0",
                "cvss_vec": "",
                "aliases": {
                    "GHSA-q2c6-c6pm-g3gh": "https://github.com/advisories/GHSA-q2c6-c6pm-g3gh"
                },
            },
        }
        expected_ghsa_vulns = [
            expected_vulns[vuln_id] if vuln_id.startswith("CVE") else vuln_id
            for vuln_id in expected_vulns
        ]
        expected_not_matching = {}
        actual_ghsa_vulns = []
        actual_not_matching = {}
        for vuln_id, vuln in result["vulns"].items():
            vuln = vuln.to_dict()
            if vuln_id.startswith("CVE-"):
                if "ghsa" in vuln["match_sources"]:
                    # check that ghsa vulns for the software are reported
                    self.assertIn(expected_vulns[vuln_id], vuln["aliases"])
                    for alias in vuln["aliases"]:
                        if alias.startswith("GHSA-"):
                            actual_ghsa_vulns.append(alias)
                else:
                    # check that cve<->ghsa matchings work, even if the software is not vulnerable via GHSA
                    for alias in vuln["aliases"]:
                        if alias.startswith("GHSA-"):
                            actual_not_matching[vuln_id] = alias
            elif vuln_id.startswith("GHSA-"):
                # check that GHSA attributes match
                actual_ghsa_vulns.append(vuln_id)
                self.assertEqual(vuln["published"], expected_vulns[vuln_id]["published"])
                self.assertEqual(vuln["cvss_ver"], expected_vulns[vuln_id]["cvss_ver"])
                self.assertEqual(vuln["cvss"], expected_vulns[vuln_id]["cvss"])
                self.assertEqual(vuln["cvss_vec"], expected_vulns[vuln_id]["cvss_vec"])
                self.assertEqual(vuln["aliases"], expected_vulns[vuln_id]["aliases"])
                if "exploits" in expected_vulns[vuln_id]:
                    self.assertEqual(
                        sorted(vuln["exploits"]), sorted(expected_vulns[vuln_id]["exploits"])
                    )
        self.assertEqual(sorted(actual_ghsa_vulns), sorted(expected_ghsa_vulns))
        self.assertEqual(actual_not_matching, expected_not_matching)

    def test_search_rosariosis_7_0_0(self):
        self.maxDiff = None
        query = "cpe:2.3:a:rosariosis:rosariosis:7.0.0:*:*:*:*:*:*:*"
        result = search_vulns(
            query=query, is_product_id_query=False, include_single_version_vulns=True
        )
        expected_vulns = {
            "CVE-2021-44427": "GHSA-wf5p-f5xr-c4jj",
            "CVE-2022-2067": "GHSA-3pqv-6pm3-g46j",
            "CVE-2022-2714": "GHSA-vh4m-mw8w-g4w8",
            "CVE-2022-3072": "GHSA-2mh7-qxcw-q39g",
            "CVE-2023-2665": "GHSA-36cm-h8gv-mg97",
            "CVE-2022-1997": "GHSA-wjh9-344g-vc49",
            "CVE-2021-44567": "GHSA-82rr-mq4r-p4r3",
            "CVE-2022-2036": "GHSA-4hpr-hh77-6q9p",
            "CVE-2021-44565": "GHSA-44cg-qcpr-fwjh",
            "CVE-2023-0994": "GHSA-prjg-28jg-m3p5",
            "CVE-2023-2202": "GHSA-g66v-3v62-g375",
            "GHSA-f8hp-grmr-pp7j": {
                "published": "2023-05-02 18:30:20",
                "cvss_ver": "3.1",
                "cvss": "5.4",
                "cvss_vec": "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N",
                "aliases": {
                    "CVE-2023-29918": "https://nvd.nist.gov/vuln/detail/CVE-2023-29918",
                    "GHSA-f8hp-grmr-pp7j": "https://github.com/advisories/GHSA-f8hp-grmr-pp7j",
                },
                "sources": ["ghsa"],
                "exploits": [
                    "https://www.exploit-db.com/exploits/51622",
                    "https://docs.google.com/document/d/1JAhJOlfKKD5Y5zEKo0_8a3A-nQ7Dz_GIMmlXmOvXV48/edit?usp=sharing",
                ],
            },
            "GHSA-287r-574x-f4h4": {
                "published": "2022-02-02 00:01:46",
                "cvss_ver": "3.1",
                "cvss": "6.1",
                "cvss_vec": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                "aliases": {
                    "CVE-2021-45416": "https://nvd.nist.gov/vuln/detail/CVE-2021-45416",
                    "GHSA-287r-574x-f4h4": "https://github.com/advisories/GHSA-287r-574x-f4h4",
                },
                "sources": ["ghsa"],
            },
            "CVE-2024-3138": "GHSA-r32g-w9cv-9fgc",
        }
        expected_ghsa_vulns = [
            expected_vulns[vuln_id] if vuln_id.startswith("CVE") else vuln_id
            for vuln_id in expected_vulns
        ]
        expected_not_matching = {}
        actual_ghsa_vulns = []
        actual_not_matching = {}

        for vuln_id, vuln in result["vulns"].items():
            vuln = vuln.to_dict()
            if vuln_id.startswith("CVE-"):
                if "ghsa" in vuln["match_sources"]:
                    # check that ghsa vulns for the software are reported
                    self.assertIn(expected_vulns[vuln_id], vuln["aliases"])
                    for alias in vuln["aliases"]:
                        if alias.startswith("GHSA-"):
                            actual_ghsa_vulns.append(alias)
                else:
                    # check that cve<->ghsa matchings work, even if the software is not vulnerable via GHSA
                    for alias in vuln["aliases"]:
                        if alias.startswith("GHSA-"):
                            actual_not_matching[vuln_id] = alias
            elif vuln_id.startswith("GHSA-"):
                # check that GHSA attributes match
                actual_ghsa_vulns.append(vuln_id)
                self.assertEqual(vuln["published"], expected_vulns[vuln_id]["published"])
                self.assertEqual(vuln["cvss_ver"], expected_vulns[vuln_id]["cvss_ver"])
                self.assertEqual(vuln["cvss"], expected_vulns[vuln_id]["cvss"])
                self.assertEqual(vuln["cvss_vec"], expected_vulns[vuln_id]["cvss_vec"])
                self.assertEqual(vuln["aliases"], expected_vulns[vuln_id]["aliases"])
                if "exploits" in expected_vulns[vuln_id]:
                    self.assertEqual(
                        sorted(vuln["exploits"]), sorted(expected_vulns[vuln_id]["exploits"])
                    )
        self.assertEqual(sorted(actual_ghsa_vulns), sorted(expected_ghsa_vulns))
        self.assertEqual(actual_not_matching, expected_not_matching)

    def test_search_vmware_spring_framework_5_3_26(self):
        self.maxDiff = None
        query = "cpe:2.3:a:vmware:spring_framework:5.3.26:*:*:*:*:*:*:*"
        result = search_vulns(query=query, is_product_id_query=False)
        expected_vulns = {
            "CVE-2023-20863": "GHSA-wxqc-pxw9-g2p8",
            "CVE-2016-1000027": "GHSA-4wrc-f8pq-fpqp",
            "CVE-2024-22262": "GHSA-2wrp-6fg6-hmc5",
            "CVE-2024-22243": "GHSA-ccgv-vj62-xf9h",
            "CVE-2024-22259": "GHSA-hgjh-9rj2-g67j",
            "CVE-2024-38808": "GHSA-9cmq-m9j5-mvww",
            "CVE-2024-38809": "GHSA-2rmj-mq67-h97g",
            "GHSA-cx7f-g6mp-7hqm": {
                "published": "2024-09-13 06:30:42",
                "cvss_ver": "3.1",
                "cvss": "7.5",
                "cvss_vec": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                "aliases": {
                    "CVE-2024-38816": "https://nvd.nist.gov/vuln/detail/CVE-2024-38816",
                    "GHSA-cx7f-g6mp-7hqm": "https://github.com/advisories/GHSA-cx7f-g6mp-7hqm",
                },
            },
            "CVE-2024-38820": "GHSA-4gc7-5j7h-4qph",
            "CVE-2024-38828": "GHSA-w3c8-7r8f-9jp8",
            "CVE-2024-38819": "GHSA-g5vr-rgqm-vf78",
            "CVE-2025-22233": "GHSA-4wp7-92pw-q264",
            "GHSA-r936-gwx5-v52f": {
                "published": "2025-08-18 09:31:44",
                "cvss_ver": "3.1",
                "cvss": "5.9",
                "cvss_vec": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
                "cisa_known_exploited": False,
                "aliases": {
                    "CVE-2025-41242": "https://nvd.nist.gov/vuln/detail/CVE-2025-41242",
                    "GHSA-r936-gwx5-v52f": "https://github.com/advisories/GHSA-r936-gwx5-v52f",
                },
            },
            "GHSA-jmp9-x22r-554x": {
                "published": "2025-09-16 15:32:34",
                "cvss_ver": "3.1",
                "cvss": "7.5",
                "cvss_vec": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                "cisa_known_exploited": False,
                "aliases": {
                    "CVE-2025-41249": "https://nvd.nist.gov/vuln/detail/CVE-2025-41249",
                    "GHSA-jmp9-x22r-554x": "https://github.com/advisories/GHSA-jmp9-x22r-554x",
                },
            },
        }
        expected_ghsa_vulns = [
            expected_vulns[vuln_id] if vuln_id.startswith("CVE") else vuln_id
            for vuln_id in expected_vulns
        ]
        expected_not_matching = {}
        actual_ghsa_vulns = []
        actual_not_matching = {}

        for vuln_id, vuln in result["vulns"].items():
            vuln = vuln.to_dict()
            if vuln_id.startswith("CVE-"):
                if "ghsa" in vuln["match_sources"]:
                    # check that ghsa vulns for the software are reported
                    self.assertIn(expected_vulns[vuln_id], vuln["aliases"])
                    for alias in vuln["aliases"]:
                        if alias.startswith("GHSA-"):
                            actual_ghsa_vulns.append(alias)
                else:
                    # check that cve<->ghsa matchings work, even if the software is not vulnerable via GHSA
                    for alias in vuln["aliases"]:
                        if alias.startswith("GHSA-"):
                            actual_not_matching[vuln_id] = alias
            elif vuln_id.startswith("GHSA-"):
                # check that GHSA attributes match
                actual_ghsa_vulns.append(vuln_id)
                self.assertEqual(vuln["published"], expected_vulns[vuln_id]["published"])
                self.assertEqual(vuln["cvss_ver"], expected_vulns[vuln_id]["cvss_ver"])
                self.assertEqual(vuln["cvss"], expected_vulns[vuln_id]["cvss"])
                self.assertEqual(vuln["cvss_vec"], expected_vulns[vuln_id]["cvss_vec"])
                self.assertEqual(vuln["aliases"], expected_vulns[vuln_id]["aliases"])
                if "exploits" in expected_vulns[vuln_id]:
                    self.assertEqual(
                        sorted(vuln["exploits"]), sorted(expected_vulns[vuln_id]["exploits"])
                    )
        self.assertEqual(sorted(actual_ghsa_vulns), sorted(expected_ghsa_vulns))
        self.assertEqual(actual_not_matching, expected_not_matching)

    def test_search_jquery_2_1_3(self):
        self.maxDiff = None
        query = "cpe:2.3:a:jquery:jquery:2.1.3:*:*:*:*:*:*:*"
        result = search_vulns(query=query, is_product_id_query=False)
        expected_vulns = {
            "CVE-2020-11022": "GHSA-gxr4-xjj5-5px2",
            "CVE-2020-11023": "GHSA-jpcq-cgw6-v4j6",
            "CVE-2019-11358": "GHSA-6c3j-c64m-qhgq",
            "CVE-2015-9251": "GHSA-rmxg-73gg-4p98",
        }
        expected_ghsa_vulns = [
            expected_vulns[vuln_id] if vuln_id.startswith("CVE") else vuln_id
            for vuln_id in expected_vulns
        ]
        expected_not_matching = {}
        actual_ghsa_vulns = []
        actual_not_matching = {}

        for vuln_id, vuln in result["vulns"].items():
            vuln = vuln.to_dict()
            if vuln_id.startswith("CVE-"):
                if "ghsa" in vuln["match_sources"]:
                    # check that ghsa vulns for the software are reported
                    self.assertIn(expected_vulns[vuln_id], vuln["aliases"])
                    for alias in vuln["aliases"]:
                        if alias.startswith("GHSA-"):
                            actual_ghsa_vulns.append(alias)
                else:
                    # check that cve<->ghsa matchings work, even if the software is not vulnerable via GHSA
                    for alias in vuln["aliases"]:
                        if alias.startswith("GHSA-"):
                            actual_not_matching[vuln_id] = alias
            elif vuln_id.startswith("GHSA-"):
                # check that GHSA attributes match
                actual_ghsa_vulns.append(vuln_id)
                self.assertEqual(vuln["published"], expected_vulns[vuln_id]["published"])
                self.assertEqual(vuln["cvss_ver"], expected_vulns[vuln_id]["cvss_ver"])
                self.assertEqual(vuln["cvss"], expected_vulns[vuln_id]["cvss"])
                self.assertEqual(vuln["cvss_vec"], expected_vulns[vuln_id]["cvss_vec"])
                self.assertEqual(vuln["aliases"], expected_vulns[vuln_id]["aliases"])
                if "exploits" in expected_vulns[vuln_id]:
                    self.assertEqual(
                        sorted(vuln["exploits"]), sorted(expected_vulns[vuln_id]["exploits"])
                    )
        self.assertEqual(sorted(actual_ghsa_vulns), sorted(expected_ghsa_vulns))
        self.assertEqual(actual_not_matching, expected_not_matching)

    def test_search_electron_20_0_0(self):
        self.maxDiff = None
        query = "cpe:2.3:a:electronjs:electron:20.0.0:*:*:*:*:*:*:*"
        result = search_vulns(query=query, is_product_id_query=False)
        expected_vulns = {
            "CVE-2023-44402": "GHSA-7m48-wc93-9g85",
            "CVE-2023-29198": "GHSA-p7v2-p9m8-qqg7",
            "CVE-2023-39956": "GHSA-7x97-j373-85x5",
            "CVE-2022-36077": "GHSA-p2jh-44qj-pf2v",
            "GHSA-qqvq-6xgj-jw8g": {
                "published": "2023-09-28 18:30:45",
                "cvss_ver": "3.1",
                "cvss": "8.8",
                "cvss_vec": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
                "aliases": {
                    "CVE-2023-5217": "https://nvd.nist.gov/vuln/detail/CVE-2023-5217",
                    "GHSA-qqvq-6xgj-jw8g": "https://github.com/advisories/GHSA-qqvq-6xgj-jw8g",
                },
            },
            "CVE-2024-46993": "GHSA-6r2x-8pq8-9489",
            "CVE-2025-55305": "GHSA-vmqv-hx8q-j7mg",
        }
        expected_ghsa_vulns = [
            expected_vulns[vuln_id] if vuln_id.startswith("CVE") else vuln_id
            for vuln_id in expected_vulns
        ]
        expected_not_matching = {}
        actual_ghsa_vulns = []
        actual_not_matching = {}

        for vuln_id, vuln in result["vulns"].items():
            vuln = vuln.to_dict()
            if vuln_id.startswith("CVE-"):
                if "ghsa" in vuln["match_sources"]:
                    # check that ghsa vulns for the software are reported
                    self.assertIn(expected_vulns[vuln_id], vuln["aliases"])
                    for alias in vuln["aliases"]:
                        if alias.startswith("GHSA-"):
                            actual_ghsa_vulns.append(alias)
                else:
                    # check that cve<->ghsa matchings work, even if the software is not vulnerable via GHSA
                    for alias in vuln["aliases"]:
                        if alias.startswith("GHSA-"):
                            actual_not_matching[vuln_id] = alias
            elif vuln_id.startswith("GHSA-"):
                # check that GHSA attributes match
                actual_ghsa_vulns.append(vuln_id)
                self.assertEqual(vuln["published"], expected_vulns[vuln_id]["published"])
                self.assertEqual(vuln["cvss_ver"], expected_vulns[vuln_id]["cvss_ver"])
                self.assertEqual(vuln["cvss"], expected_vulns[vuln_id]["cvss"])
                self.assertEqual(vuln["cvss_vec"], expected_vulns[vuln_id]["cvss_vec"])
                self.assertEqual(vuln["aliases"], expected_vulns[vuln_id]["aliases"])
                if "exploits" in expected_vulns[vuln_id]:
                    self.assertEqual(
                        sorted(vuln["exploits"]), sorted(expected_vulns[vuln_id]["exploits"])
                    )
        self.assertEqual(sorted(actual_ghsa_vulns), sorted(expected_ghsa_vulns))
        self.assertEqual(actual_not_matching, expected_not_matching)

    def test_search_typo3_7_4_22(self):
        self.maxDiff = None
        query = "cpe:2.3:a:typo3:typo3:7.4.22:*:*:*:*:*:*:*"
        result = search_vulns(query=query, is_product_id_query=False)
        expected_vulns = {
            "CVE-2022-31046": "GHSA-8gmv-9hwg-w89g",
            "CVE-2022-31047": "GHSA-fh99-4pgr-8j99",
            "CVE-2021-32768": "GHSA-c5c9-8c6m-727v",
            "CVE-2021-21339": "GHSA-qx3w-4864-94ch",
            "CVE-2021-21338": "GHSA-4jhw-2p6j-5wmp",
            "CVE-2022-36107": "GHSA-9c6w-55cp-5w25",
            "CVE-2022-23501": "GHSA-jfp7-79g7-89rf",
            "CVE-2022-36105": "GHSA-m392-235j-9r7r",
            "CVE-2018-6905": "GHSA-3w22-wrwx-2r75",
            "CVE-2021-32767": "GHSA-34fr-fhqr-7235",
            "CVE-2021-21370": "GHSA-x7hc-x7fm-f7qh",
            "GHSA-f777-f784-36gm": {
                "published": "2024-06-07 19:52:43",
                "cvss_ver": "3.1",
                "cvss": "8.1",
                "cvss_vec": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
                "aliases": {
                    "GHSA-f777-f784-36gm": "https://github.com/advisories/GHSA-f777-f784-36gm"
                },
            },
            "GHSA-7q33-hxwj-7p8v": {
                "published": "2024-06-07 19:44:49",
                "cvss_ver": "3.1",
                "cvss": "5.4",
                "cvss_vec": "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N",
                "aliases": {
                    "GHSA-7q33-hxwj-7p8v": "https://github.com/advisories/GHSA-7q33-hxwj-7p8v"
                },
            },
            "GHSA-66c2-7g4p-wx4p": {
                "published": "2024-05-30 15:13:09",
                "cvss_ver": "3.1",
                "cvss": "5.3",
                "cvss_vec": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                "aliases": {
                    "GHSA-66c2-7g4p-wx4p": "https://github.com/advisories/GHSA-66c2-7g4p-wx4p"
                },
            },
            "GHSA-5cxf-xx9j-54jc": {
                "published": "2024-06-03 14:29:56",
                "cvss_ver": "",
                "cvss": "-1.0",
                "cvss_vec": "",
                "aliases": {
                    "GHSA-5cxf-xx9j-54jc": "https://github.com/advisories/GHSA-5cxf-xx9j-54jc"
                },
            },
            "GHSA-g4c9-qfvw-fmr4": {
                "published": "2024-05-30 14:57:50",
                "cvss_ver": "3.1",
                "cvss": "6.1",
                "cvss_vec": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                "aliases": {
                    "GHSA-g4c9-qfvw-fmr4": "https://github.com/advisories/GHSA-g4c9-qfvw-fmr4"
                },
            },
            "GHSA-56f9-5563-m2h7": {
                "published": "2022-05-17 03:59:51",
                "cvss_ver": "3.0",
                "cvss": "5.4",
                "cvss_vec": "CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N",
                "aliases": {
                    "CVE-2015-8755": "https://nvd.nist.gov/vuln/detail/CVE-2015-8755",
                    "GHSA-56f9-5563-m2h7": "https://github.com/advisories/GHSA-56f9-5563-m2h7",
                },
            },
            "GHSA-29m4-mx89-3mjg": {
                "published": "2024-05-30 15:33:17",
                "cvss_ver": "3.1",
                "cvss": "5.3",
                "cvss_vec": "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H",
                "aliases": {
                    "GHSA-29m4-mx89-3mjg": "https://github.com/advisories/GHSA-29m4-mx89-3mjg"
                },
            },
            "GHSA-jxg5-35fj-ccwf": {
                "published": "2022-05-17 03:02:43",
                "cvss_ver": "3.0",
                "cvss": "8.1",
                "cvss_vec": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "aliases": {
                    "CVE-2016-5091": "https://nvd.nist.gov/vuln/detail/CVE-2016-5091",
                    "GHSA-jxg5-35fj-ccwf": "https://github.com/advisories/GHSA-jxg5-35fj-ccwf",
                },
            },
            "GHSA-f3wf-q4fj-3gxf": {
                "published": "2024-06-07 19:56:24",
                "cvss_ver": "3.1",
                "cvss": "6.5",
                "cvss_vec": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
                "aliases": {
                    "GHSA-f3wf-q4fj-3gxf": "https://github.com/advisories/GHSA-f3wf-q4fj-3gxf"
                },
            },
            "GHSA-ppvg-hw62-6ph9": {
                "published": "2024-05-30 15:11:42",
                "cvss_ver": "3.1",
                "cvss": "7.5",
                "cvss_vec": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
                "aliases": {
                    "GHSA-ppvg-hw62-6ph9": "https://github.com/advisories/GHSA-ppvg-hw62-6ph9"
                },
            },
            "GHSA-6fc6-cj2j-h22x": {
                "published": "2024-06-03 17:00:44",
                "cvss_ver": "",
                "cvss": "-1.0",
                "cvss_vec": "",
                "aliases": {
                    "GHSA-6fc6-cj2j-h22x": "https://github.com/advisories/GHSA-6fc6-cj2j-h22x"
                },
            },
            "GHSA-6f9m-v7mp-7jjq": {
                "published": "2024-06-05 16:52:44",
                "cvss_ver": "",
                "cvss": "-1.0",
                "cvss_vec": "",
                "aliases": {
                    "GHSA-6f9m-v7mp-7jjq": "https://github.com/advisories/GHSA-6f9m-v7mp-7jjq"
                },
            },
            "GHSA-8c25-vj2w-p72j": {
                "published": "2024-05-30 14:59:25",
                "cvss_ver": "3.1",
                "cvss": "6.1",
                "cvss_vec": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                "aliases": {
                    "GHSA-8c25-vj2w-p72j": "https://github.com/advisories/GHSA-8c25-vj2w-p72j"
                },
            },
            "GHSA-6487-3qvg-8px9": {
                "published": "2024-06-07 19:55:04",
                "cvss_ver": "3.1",
                "cvss": "5.3",
                "cvss_vec": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                "aliases": {
                    "GHSA-6487-3qvg-8px9": "https://github.com/advisories/GHSA-6487-3qvg-8px9"
                },
            },
            "GHSA-hjx5-v9xg-7h25": {
                "published": "2024-05-30 15:36:27",
                "cvss_ver": "3.1",
                "cvss": "7.5",
                "cvss_vec": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                "aliases": {
                    "GHSA-hjx5-v9xg-7h25": "https://github.com/advisories/GHSA-hjx5-v9xg-7h25"
                },
            },
            "GHSA-x4rj-f7m6-42c3": {
                "published": "2024-05-30 13:49:16",
                "cvss_ver": "3.1",
                "cvss": "7.5",
                "cvss_vec": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
                "aliases": {
                    "GHSA-x4rj-f7m6-42c3": "https://github.com/advisories/GHSA-x4rj-f7m6-42c3"
                },
            },
            "GHSA-gqqf-g5r7-84vf": {
                "published": "2022-09-15 03:26:51",
                "cvss_ver": "3.1",
                "cvss": "6.1",
                "cvss_vec": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                "aliases": {
                    "GHSA-gqqf-g5r7-84vf": "https://github.com/advisories/GHSA-gqqf-g5r7-84vf"
                },
            },
            "GHSA-8m6j-p5jv-v69w": {
                "published": "2024-06-07 19:43:19",
                "cvss_ver": "3.1",
                "cvss": "5.4",
                "cvss_vec": "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N",
                "aliases": {
                    "GHSA-8m6j-p5jv-v69w": "https://github.com/advisories/GHSA-8m6j-p5jv-v69w"
                },
            },
            "GHSA-ppgf-8745-8pgx": {
                "published": "2024-06-05 16:41:48",
                "cvss_ver": "",
                "cvss": "-1.0",
                "cvss_vec": "",
                "aliases": {
                    "GHSA-ppgf-8745-8pgx": "https://github.com/advisories/GHSA-ppgf-8745-8pgx"
                },
            },
            "GHSA-g585-crjf-vhwq": {
                "published": "2024-06-07 18:30:35",
                "cvss_ver": "3.1",
                "cvss": "7.5",
                "cvss_vec": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                "aliases": {
                    "GHSA-g585-crjf-vhwq": "https://github.com/advisories/GHSA-g585-crjf-vhwq"
                },
            },
            "GHSA-75mx-chcf-2q32": {
                "published": "2024-05-30 21:25:26",
                "cvss_ver": "3.1",
                "cvss": "6.1",
                "cvss_vec": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                "aliases": {
                    "GHSA-75mx-chcf-2q32": "https://github.com/advisories/GHSA-75mx-chcf-2q32"
                },
            },
            "GHSA-2rcw-9hrm-8q7q": {
                "published": "2024-06-07 19:47:52",
                "cvss_ver": "3.1",
                "cvss": "5.4",
                "cvss_vec": "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N",
                "aliases": {
                    "GHSA-2rcw-9hrm-8q7q": "https://github.com/advisories/GHSA-2rcw-9hrm-8q7q"
                },
            },
            "GHSA-cc97-g92w-jm65": {
                "published": "2024-05-30 13:52:08",
                "cvss_ver": "3.1",
                "cvss": "9.8",
                "cvss_vec": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "aliases": {
                    "GHSA-cc97-g92w-jm65": "https://github.com/advisories/GHSA-cc97-g92w-jm65"
                },
            },
            "GHSA-j5v7-9xr5-m7gx": {
                "published": "2022-05-17 03:59:52",
                "cvss_ver": "3.0",
                "cvss": "5.4",
                "cvss_vec": "CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N",
                "aliases": {
                    "CVE-2015-8759": "https://nvd.nist.gov/vuln/detail/CVE-2015-8759",
                    "GHSA-j5v7-9xr5-m7gx": "https://github.com/advisories/GHSA-j5v7-9xr5-m7gx",
                },
            },
            "CVE-2025-7900": "GHSA-rc5f-3hfv-jxp2",
        }
        expected_ghsa_vulns = [
            expected_vulns[vuln_id] if vuln_id.startswith("CVE") else vuln_id
            for vuln_id in expected_vulns
        ]
        expected_not_matching = {
            "CVE-2019-19848": "GHSA-77p4-wfr8-977w",
            "CVE-2019-19849": "GHSA-rcgc-4xfc-564v",
        }
        actual_ghsa_vulns = []
        actual_not_matching = {}

        for vuln_id, vuln in result["vulns"].items():
            vuln = vuln.to_dict()
            if vuln_id.startswith("CVE-"):
                if "ghsa" in vuln["match_sources"]:
                    # check that ghsa vulns for the software are reported
                    self.assertIn(expected_vulns[vuln_id], vuln["aliases"])
                    for alias in vuln["aliases"]:
                        if alias.startswith("GHSA-"):
                            actual_ghsa_vulns.append(alias)
                else:
                    # check that cve<->ghsa matchings work, even if the software is not vulnerable via GHSA
                    for alias in vuln["aliases"]:
                        if alias.startswith("GHSA-"):
                            actual_not_matching[vuln_id] = alias
            elif vuln_id.startswith("GHSA-"):
                # check that GHSA attributes match
                actual_ghsa_vulns.append(vuln_id)
                self.assertEqual(vuln["published"], expected_vulns[vuln_id]["published"])
                self.assertEqual(vuln["cvss_ver"], expected_vulns[vuln_id]["cvss_ver"])
                self.assertEqual(vuln["cvss"], expected_vulns[vuln_id]["cvss"])
                self.assertEqual(vuln["cvss_vec"], expected_vulns[vuln_id]["cvss_vec"])
                self.assertEqual(vuln["aliases"], expected_vulns[vuln_id]["aliases"])
                if "exploits" in expected_vulns[vuln_id]:
                    self.assertEqual(
                        sorted(vuln["exploits"]), sorted(expected_vulns[vuln_id]["exploits"])
                    )
        self.assertEqual(sorted(actual_ghsa_vulns), sorted(expected_ghsa_vulns))
        self.assertEqual(actual_not_matching, expected_not_matching)

    def test_search_keycloak_23_0_7(self):
        self.maxDiff = None
        query = "cpe:2.3:a:redhat:keycloak:23.0.7:*:*:*:*:*:*:*"
        result = search_vulns(query=query, is_product_id_query=False)
        expected_vulns = {
            "GHSA-cq42-vhv7-xr7p": {
                "published": "2024-06-12 19:42:21",
                "cvss_ver": "3.1",
                "cvss": "3.7",
                "cvss_vec": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L",
                "aliases": {
                    "CVE-2024-1722": "https://nvd.nist.gov/vuln/detail/CVE-2024-1722",
                    "GHSA-cq42-vhv7-xr7p": "https://github.com/advisories/GHSA-cq42-vhv7-xr7p",
                },
            },
            "GHSA-4vc8-pg5c-vg4x": {
                "published": "2024-06-12 19:41:05",
                "cvss_ver": "3.1",
                "cvss": "3.7",
                "cvss_vec": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L",
                "aliases": {
                    "CVE-2021-3754": "https://nvd.nist.gov/vuln/detail/CVE-2021-3754",
                    "GHSA-4vc8-pg5c-vg4x": "https://github.com/advisories/GHSA-4vc8-pg5c-vg4x",
                },
            },
            "CVE-2024-7260": "GHSA-g4gc-rh26-m3p5",
            "CVE-2024-4629": "GHSA-gc7q-jgjv-vjr2",
            "CVE-2024-7341": "GHSA-5rxp-2rhr-qwqv",
            "GHSA-w97f-w3hq-36g2": {
                "published": "2024-09-10 18:30:44",
                "cvss_ver": "3.1",
                "cvss": "6.5",
                "cvss_vec": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
                "aliases": {
                    "CVE-2023-6841": "https://nvd.nist.gov/vuln/detail/CVE-2023-6841",
                    "GHSA-w97f-w3hq-36g2": "https://github.com/advisories/GHSA-w97f-w3hq-36g2",
                },
            },
            "GHSA-w8gr-xwp4-r9f7": {
                "published": "2024-10-14 20:55:22",
                "cvss_ver": "3.1",
                "cvss": "6.1",
                "cvss_vec": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                "aliases": {
                    "CVE-2024-8883": "https://nvd.nist.gov/vuln/detail/CVE-2024-8883",
                    "GHSA-w8gr-xwp4-r9f7": "https://github.com/advisories/GHSA-w8gr-xwp4-r9f7",
                },
            },
            "GHSA-93ww-43rr-79v3": {
                "published": "2024-11-25 19:40:46",
                "cvss_ver": "3.1",
                "cvss": "7.1",
                "cvss_vec": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
                "aliases": {
                    "CVE-2024-10039": "https://nvd.nist.gov/vuln/detail/CVE-2024-10039",
                    "GHSA-93ww-43rr-79v3": "https://github.com/advisories/GHSA-93ww-43rr-79v3",
                },
            },
            "CVE-2024-10492": "GHSA-5545-r4hg-rj4m",
            "CVE-2025-3501": "GHSA-hw58-3793-42gg",
            "CVE-2024-1132": "GHSA-72vp-xfrc-42xm",
            "CVE-2023-0657": "GHSA-7fpj-9hr8-28vh",
            "CVE-2024-4540": "GHSA-69fp-7c8p-crjr",
            "CVE-2023-3597": "GHSA-4f53-xh3v-g8x4",
            "CVE-2023-6717": "GHSA-8rmm-gm28-pj8q",
            "CVE-2024-10270": "GHSA-wq8x-cg39-8mrr",
            "CVE-2024-2419": "GHSA-mrv8-pqfj-7gp5",
            "CVE-2024-1249": "GHSA-m6q9-p373-g5q8",
            "CVE-2024-5967": "GHSA-c25h-c27q-5qpv",
            "CVE-2025-1391": "GHSA-gvgg-2r3r-53x7",
            "CVE-2024-10451": "GHSA-v7gv-xpgf-6395",
            "CVE-2024-8698": "GHSA-xgfv-xpx8-qhcr",
            "CVE-2023-6544": "GHSA-46c8-635v-68r2",
            "CVE-2024-11736": "GHSA-f4v7-3mww-9gc2",
            "CVE-2024-11734": "GHSA-w3g8-r9gw-qrh8",
            "CVE-2023-6787": "GHSA-c9h6-v78w-52wj",
            "CVE-2024-9666": "GHSA-jgwc-jh89-rpgq",
            "CVE-2024-7318": "GHSA-xmmm-jw76-q7vg",
            "CVE-2024-3656": "GHSA-2cww-fgmg-4jqc",
            "CVE-2025-0604": "GHSA-2p82-5wwr-43cw",
            "CVE-2025-2559": "GHSA-2935-2wfm-hhpv",
            "GHSA-q4xq-445g-g6ch": {
                "published": "2025-02-18 18:33:21",
                "cvss_ver": "3.1",
                "cvss": "3.8",
                "cvss_vec": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:N",
                "aliases": {
                    "CVE-2024-4028": "https://nvd.nist.gov/vuln/detail/CVE-2024-4028",
                    "GHSA-q4xq-445g-g6ch": "https://github.com/advisories/GHSA-q4xq-445g-g6ch",
                },
            },
            "GHSA-5jfq-x6xp-7rw2": {
                "published": "2025-04-30 17:26:13",
                "cvss_ver": "3.1",
                "cvss": "5.4",
                "cvss_vec": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
                "cisa_known_exploited": False,
                "aliases": {
                    "CVE-2025-3910": "https://nvd.nist.gov/vuln/detail/CVE-2025-3910",
                    "GHSA-5jfq-x6xp-7rw2": "https://github.com/advisories/GHSA-5jfq-x6xp-7rw2",
                },
            },
            "GHSA-xhpr-465j-7p9q": {
                "published": "2025-07-30 13:16:47",
                "cvss_ver": "3.1",
                "cvss": "5.4",
                "cvss_vec": "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:H/I:L/A:N",
                "cisa_known_exploited": False,
                "aliases": {
                    "CVE-2025-7365": "https://nvd.nist.gov/vuln/detail/CVE-2025-7365",
                    "GHSA-xhpr-465j-7p9q": "https://github.com/advisories/GHSA-xhpr-465j-7p9q",
                },
            },
            "CVE-2025-9162": "GHSA-8hxp-qmph-w5gq",
            "CVE-2025-10044": "GHSA-27gc-wj6x-9w55",
            "CVE-2025-12110": "GHSA-895x-rfqp-jh5c",
            "CVE-2025-12390": "GHSA-rg35-5v25-mqvp",
            "GHSA-m4j5-5x4r-2xp9": {
                "published": "2025-09-17 20:24:07",
                "cvss_ver": "3.1",
                "cvss": "5.3",
                "cvss_vec": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
                "cisa_known_exploited": False,
                "aliases": {
                    "CVE-2025-8419": "https://nvd.nist.gov/vuln/detail/CVE-2025-8419",
                    "GHSA-m4j5-5x4r-2xp9": "https://github.com/advisories/GHSA-m4j5-5x4r-2xp9",
                },
            },
            "CVE-2025-11419": "GHSA-q8hq-4h99-fj7x",
            "CVE-2025-10939": "GHSA-vjr8-56p3-fmqq",
            "CVE-2025-11429": "GHSA-64w3-5q9m-68xf",
            "CVE-2025-11538": "GHSA-j4vq-q93m-4683",
            "CVE-2025-13467": "GHSA-4hx9-48xh-5mxr",
            "GHSA-6q37-7866-h27j": {
                "published": "2025-12-10 09:30:24",
                "cvss_ver": "3.1",
                "cvss": "2.7",
                "cvss_vec": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:N/A:N",
                "aliases": {
                    "CVE-2025-14082": "https://nvd.nist.gov/vuln/detail/CVE-2025-14082",
                    "GHSA-6q37-7866-h27j": "https://github.com/advisories/GHSA-6q37-7866-h27j",
                },
            },
        }
        expected_ghsa_vulns = [
            expected_vulns[vuln_id] if vuln_id.startswith("CVE") else vuln_id
            for vuln_id in expected_vulns
        ]
        expected_not_matching = {
            "CVE-2023-0105": "GHSA-c7xw-p58w-h6fj",
            "CVE-2022-4137": "GHSA-9hhc-pj4w-w5rv",
            "CVE-2022-0225": "GHSA-fqc7-5xxc-ph7r",
            "CVE-2020-10734": "GHSA-rvjg-gxwx-j5gf",
            "CVE-2023-1664": "GHSA-5cc8-pgp5-7mpm",
            "CVE-2023-48795": "GHSA-45x7-px36-x8w8",
            "CVE-2017-12160": "GHSA-qc72-gfvw-76h7",
            "CVE-2023-2422": "GHSA-3qh5-qqj2-c78f",
            "CVE-2022-1438": "GHSA-w354-2f3c-qvg9",
            "CVE-2023-0091": "GHSA-v436-q368-hvgg",
            "CVE-2023-6927": "GHSA-3p75-q5cc-qmj7",
            "CVE-2017-12159": "GHSA-7fmw-85qm-h22p",
            "CVE-2017-12158": "GHSA-v38p-mqq3-m6v5",
            "CVE-2020-14359": "GHSA-jh6m-3pqw-242h",
            "CVE-2024-7885": "GHSA-9623-mqmm-5rcf",
            "CVE-2025-4057": "GHSA-q5q7-8x6x-hcg2",
            "CVE-2025-7784": "GHSA-83j7-mhw9-388w",
            "CVE-2025-7195": "GHSA-856v-8qm2-9wjv",
        }

        actual_ghsa_vulns = []
        actual_not_matching = {}
        for vuln_id, vuln in result["vulns"].items():
            vuln = vuln.to_dict()
            if vuln_id.startswith("CVE-"):
                if "ghsa" in vuln["match_sources"]:
                    # check that ghsa vulns for the software are reported
                    self.assertIn(expected_vulns[vuln_id], vuln["aliases"])
                    for alias in vuln["aliases"]:
                        if alias.startswith("GHSA-"):
                            actual_ghsa_vulns.append(alias)
                else:
                    # check that cve<->ghsa matchings work, even if the software is not vulnerable via GHSA
                    for alias in vuln["aliases"]:
                        if alias.startswith("GHSA-"):
                            actual_not_matching[vuln_id] = alias
            elif vuln_id.startswith("GHSA-"):
                # check that GHSA attributes match
                actual_ghsa_vulns.append(vuln_id)
                self.assertEqual(vuln["published"], expected_vulns[vuln_id]["published"])
                self.assertEqual(vuln["cvss_ver"], expected_vulns[vuln_id]["cvss_ver"])
                self.assertEqual(vuln["cvss"], expected_vulns[vuln_id]["cvss"])
                self.assertEqual(vuln["cvss_vec"], expected_vulns[vuln_id]["cvss_vec"])
                self.assertEqual(vuln["aliases"], expected_vulns[vuln_id]["aliases"])
                if "exploits" in expected_vulns[vuln_id]:
                    self.assertEqual(
                        sorted(vuln["exploits"]), sorted(expected_vulns[vuln_id]["exploits"])
                    )
        self.assertEqual(sorted(actual_ghsa_vulns), sorted(expected_ghsa_vulns))
        self.assertEqual(sorted(actual_not_matching), sorted(expected_not_matching))

    def test_search_wagtail_2_7_4(self):
        self.maxDiff = None
        query = "cpe:2.3:a:torchbox:wagtail:2.7.4:*:*:*:*:*:*:*"
        result = search_vulns(query=query, is_product_id_query=False)
        expected_vulns = {
            "CVE-2023-28836": "GHSA-5286-f2rf-35c2",
            "CVE-2021-32681": "GHSA-xfrw-hxr5-ghqf",
            "CVE-2021-29434": "GHSA-wq5h-f9p5-q7fx",
            "CVE-2023-45809": "GHSA-fc75-58r8-rm3h",
            "CVE-2023-28837": "GHSA-33pv-vcgh-jfg9",
            "CVE-2024-39317": "GHSA-jmp3-39vp-fwg8",
        }
        expected_ghsa_vulns = [
            expected_vulns[vuln_id] if vuln_id.startswith("CVE") else vuln_id
            for vuln_id in expected_vulns
        ]
        expected_not_matching = {}
        actual_ghsa_vulns = []
        actual_not_matching = {}

        for vuln_id, vuln in result["vulns"].items():
            vuln = vuln.to_dict()
            if vuln_id.startswith("CVE-"):
                if "ghsa" in vuln["match_sources"]:
                    # check that ghsa vulns for the software are reported
                    self.assertIn(expected_vulns[vuln_id], vuln["aliases"])
                    for alias in vuln["aliases"]:
                        if alias.startswith("GHSA-"):
                            actual_ghsa_vulns.append(alias)
                else:
                    # check that cve<->ghsa matchings work, even if the software is not vulnerable via GHSA
                    for alias in vuln["aliases"]:
                        if alias.startswith("GHSA-"):
                            actual_not_matching[vuln_id] = alias
            elif vuln_id.startswith("GHSA-"):
                # check that GHSA attributes match
                actual_ghsa_vulns.append(vuln_id)
                self.assertEqual(vuln["published"], expected_vulns[vuln_id]["published"])
                self.assertEqual(vuln["cvss_ver"], expected_vulns[vuln_id]["cvss_ver"])
                self.assertEqual(vuln["cvss"], expected_vulns[vuln_id]["cvss"])
                self.assertEqual(vuln["cvss_vec"], expected_vulns[vuln_id]["cvss_vec"])
                self.assertEqual(vuln["aliases"], expected_vulns[vuln_id]["aliases"])
                if "exploits" in expected_vulns[vuln_id]:
                    self.assertEqual(
                        sorted(vuln["exploits"]), sorted(expected_vulns[vuln_id]["exploits"])
                    )
        self.assertEqual(sorted(actual_ghsa_vulns), sorted(expected_ghsa_vulns))
        self.assertEqual(actual_not_matching, expected_not_matching)


if __name__ == "__main__":
    unittest.main()

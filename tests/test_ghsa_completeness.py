#!/usr/bin/env python3

import os
import unittest
import sys

SEARCH_VULNS_PATH = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
sys.path.insert(1, SEARCH_VULNS_PATH)
import search_vulns

class TestSearches(unittest.TestCase):

    def test_search_handlebars_js_300(self):
        self.maxDiff = None
        query = 'cpe:2.3:a:handlebarsjs:handlebars:3.0.0:*:*:*:*:node.js:*:*'
        result = search_vulns.search_vulns(query=query, is_good_cpe=False)
        expected_vulns = {'CVE-2021-23369': 'GHSA-f2jv-r9rf-7988', 'CVE-2019-20920': 'GHSA-3cqr-58rm-57f8', 'CVE-2021-23383': 'GHSA-765h-qjxv-5f44', 'CVE-2019-19919': 'GHSA-w457-6q6x-cgp9', 'CVE-2015-8861': 'GHSA-9prh-257w-9277', 'GHSA-g9r4-xpmj-mj65': {'published': '2020-09-04 15:06:32', 'cvss_ver': '', 'cvss': '-1.0', 'cvss_vec': '', 'aliases': []}, 'GHSA-q42p-pg8m-cqh6': {'published': '2019-06-05 14:07:48', 'cvss_ver': '3.1', 'cvss': '7.3', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L', 'aliases': []}, 'GHSA-2cf5-4w76-r9qv': {'published': '2020-09-04 14:57:38', 'cvss_ver': '3.1', 'cvss': '7.3', 'cvss_vec': 'CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:C/C:L/I:H/A:L', 'aliases': []}, 'GHSA-q2c6-c6pm-g3gh': {'published': '2020-09-04 15:07:38', 'cvss_ver': '', 'cvss': '-1.0', 'cvss_vec': '', 'aliases': []}}
        expected_ghsa_vulns = [expected_vulns[vuln_id] if vuln_id.startswith('CVE') else vuln_id for vuln_id in expected_vulns]
        expected_not_matching = {}
        actual_ghsa_vulns = []
        actual_not_matching = {}

        for vuln_id, vuln in result[query]['vulns'].items():
            if vuln_id.startswith('CVE-'):
                if 'ghsa' in vuln['sources']:
                    # check that ghsa vulns for the software are reported
                    self.assertIn(expected_vulns[vuln_id], vuln['aliases'])
                    for alias in vuln['aliases']:
                        if alias.startswith('GHSA-'):
                            actual_ghsa_vulns.append(alias)
                else:
                    # check that cve<->ghsa matchings work, even if the software is not vulnerable via GHSA
                    for alias in vuln['aliases']:
                        if alias.startswith('GHSA-'):
                            actual_not_matching[vuln_id] = alias
            elif vuln_id.startswith('GHSA-'):
                # check that GHSA attributes match
                actual_ghsa_vulns.append(vuln_id)
                self.assertEqual(vuln['published'], expected_vulns[vuln_id]['published'])
                self.assertEqual(vuln['cvss_ver'], expected_vulns[vuln_id]['cvss_ver'])
                self.assertEqual(vuln['cvss'], expected_vulns[vuln_id]['cvss'])
                self.assertEqual(vuln['cvss_vec'], expected_vulns[vuln_id]['cvss_vec'])
                self.assertEqual(vuln['aliases'], expected_vulns[vuln_id]['aliases'])
                if 'exploits' in expected_vulns[vuln_id]:
                    self.assertEqual(vuln['exploits'], expected_vulns[vuln_id]['exploits'])
        self.assertEqual(sorted(actual_ghsa_vulns), sorted(expected_ghsa_vulns))
        self.assertEqual(actual_not_matching, expected_not_matching)

    def test_search_rosariosis_7_0_0(self):
        self.maxDiff = None
        query = 'cpe:2.3:a:rosariosis:rosariosis:7.0.0:*:*:*:*:*:*:*'
        result = search_vulns.search_vulns(query=query, is_good_cpe=False, include_single_version_vulns=True)
        expected_vulns = {'CVE-2021-44427': 'GHSA-wf5p-f5xr-c4jj', 'CVE-2022-2067': 'GHSA-3pqv-6pm3-g46j', 'CVE-2022-2714': 'GHSA-vh4m-mw8w-g4w8', 'CVE-2022-3072': 'GHSA-2mh7-qxcw-q39g', 'CVE-2023-2665': 'GHSA-36cm-h8gv-mg97', 'CVE-2022-1997': 'GHSA-wjh9-344g-vc49', 'CVE-2021-44567': 'GHSA-82rr-mq4r-p4r3', 'CVE-2022-2036': 'GHSA-4hpr-hh77-6q9p', 'CVE-2021-44565': 'GHSA-44cg-qcpr-fwjh', 'CVE-2023-0994': 'GHSA-prjg-28jg-m3p5', 'CVE-2023-2202': 'GHSA-g66v-3v62-g375', 'GHSA-f8hp-grmr-pp7j': {'published': '2023-05-02 18:30:20', 'cvss_ver': '3.1', 'cvss': '5.4', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N', 'aliases': ['CVE-2023-29918'], 'sources': ['ghsa'], 'exploits': ['https://www.exploit-db.com/exploits/51622']}, 'GHSA-287r-574x-f4h4': {'published': '2022-02-02 00:01:46', 'cvss_ver': '', 'cvss': '-1.0', 'cvss_vec': '', 'aliases': ['CVE-2021-45416'], 'sources': ['ghsa']}, 'CVE-2024-3138': 'GHSA-r32g-w9cv-9fgc'}
        expected_ghsa_vulns = [expected_vulns[vuln_id] if vuln_id.startswith('CVE') else vuln_id for vuln_id in expected_vulns]
        expected_not_matching = {}
        actual_ghsa_vulns = []
        actual_not_matching = {}

        for vuln_id, vuln in result[query]['vulns'].items():
            if vuln_id.startswith('CVE-'):
                if 'ghsa' in vuln['sources']:
                    # check that ghsa vulns for the software are reported
                    self.assertIn(expected_vulns[vuln_id], vuln['aliases'])
                    for alias in vuln['aliases']:
                        if alias.startswith('GHSA-'):
                            actual_ghsa_vulns.append(alias)
                else:
                    # check that cve<->ghsa matchings work, even if the software is not vulnerable via GHSA
                    for alias in vuln['aliases']:
                        if alias.startswith('GHSA-'):
                            actual_not_matching[vuln_id] = alias
            elif vuln_id.startswith('GHSA-'):
                # check that GHSA attributes match
                actual_ghsa_vulns.append(vuln_id)
                self.assertEqual(vuln['published'], expected_vulns[vuln_id]['published'])
                self.assertEqual(vuln['cvss_ver'], expected_vulns[vuln_id]['cvss_ver'])
                self.assertEqual(vuln['cvss'], expected_vulns[vuln_id]['cvss'])
                self.assertEqual(vuln['cvss_vec'], expected_vulns[vuln_id]['cvss_vec'])
                self.assertEqual(vuln['aliases'], expected_vulns[vuln_id]['aliases'])
                if 'exploits' in expected_vulns[vuln_id]:
                    self.assertEqual(vuln['exploits'], expected_vulns[vuln_id]['exploits'])
        self.assertEqual(sorted(actual_ghsa_vulns), sorted(expected_ghsa_vulns))
        self.assertEqual(actual_not_matching, expected_not_matching)

    def test_search_vmware_spring_framework_5_3_26(self):
        self.maxDiff = None
        query = 'cpe:2.3:a:vmware:spring_framework:5.3.26:*:*:*:*:*:*:*'
        result = search_vulns.search_vulns(query=query, is_good_cpe=False)
        expected_vulns = {'CVE-2023-20863': 'GHSA-wxqc-pxw9-g2p8', 'CVE-2016-1000027': 'GHSA-4wrc-f8pq-fpqp', 'CVE-2024-22262': 'GHSA-2wrp-6fg6-hmc5', 'CVE-2024-22243': 'GHSA-ccgv-vj62-xf9h', 'CVE-2024-22259': 'GHSA-hgjh-9rj2-g67j', 'GHSA-9cmq-m9j5-mvww': {'published': '2024-08-20 09:30:28', 'cvss_ver': '3.1', 'cvss': '4.3', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:L', 'aliases': ['CVE-2024-38808']}, 'CVE-2024-38809': 'GHSA-2rmj-mq67-h97g', 'GHSA-cx7f-g6mp-7hqm': {'published': '2024-09-13 06:30:42', 'cvss_ver': '3.1', 'cvss': '7.5', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N', 'aliases': ['CVE-2024-38816']}, 'CVE-2024-38820': 'GHSA-4gc7-5j7h-4qph', 'CVE-2024-53677': 'GHSA-43mq-6xmg-29vm', 'CVE-2024-38828': 'GHSA-w3c8-7r8f-9jp8', 'CVE-2024-38819': 'GHSA-g5vr-rgqm-vf78'}
        expected_ghsa_vulns = [expected_vulns[vuln_id] if vuln_id.startswith('CVE') else vuln_id for vuln_id in expected_vulns]
        expected_not_matching = {}
        actual_ghsa_vulns = []
        actual_not_matching = {}

        for vuln_id, vuln in result[query]['vulns'].items():
            if vuln_id.startswith('CVE-'):
                if 'ghsa' in vuln['sources']:
                    # check that ghsa vulns for the software are reported
                    self.assertIn(expected_vulns[vuln_id], vuln['aliases'])
                    for alias in vuln['aliases']:
                        if alias.startswith('GHSA-'):
                            actual_ghsa_vulns.append(alias)
                else:
                    # check that cve<->ghsa matchings work, even if the software is not vulnerable via GHSA
                    for alias in vuln['aliases']:
                        if alias.startswith('GHSA-'):
                            actual_not_matching[vuln_id] = alias
            elif vuln_id.startswith('GHSA-'):
                # check that GHSA attributes match
                actual_ghsa_vulns.append(vuln_id)
                self.assertEqual(vuln['published'], expected_vulns[vuln_id]['published'])
                self.assertEqual(vuln['cvss_ver'], expected_vulns[vuln_id]['cvss_ver'])
                self.assertEqual(vuln['cvss'], expected_vulns[vuln_id]['cvss'])
                self.assertEqual(vuln['cvss_vec'], expected_vulns[vuln_id]['cvss_vec'])
                self.assertEqual(vuln['aliases'], expected_vulns[vuln_id]['aliases'])
                if 'exploits' in expected_vulns[vuln_id]:
                    self.assertEqual(vuln['exploits'], expected_vulns[vuln_id]['exploits'])
        self.assertEqual(sorted(actual_ghsa_vulns), sorted(expected_ghsa_vulns))
        self.assertEqual(actual_not_matching, expected_not_matching)

    def test_search_jquery_2_1_3(self):
        self.maxDiff = None
        query = 'cpe:2.3:a:jquery:jquery:2.1.3:*:*:*:*:*:*:*'
        result = search_vulns.search_vulns(query=query, is_good_cpe=False)
        expected_vulns = {'CVE-2020-11022': 'GHSA-gxr4-xjj5-5px2', 'CVE-2020-11023': 'GHSA-jpcq-cgw6-v4j6', 'CVE-2019-11358': 'GHSA-6c3j-c64m-qhgq', 'CVE-2015-9251': 'GHSA-rmxg-73gg-4p98'}
        expected_ghsa_vulns = [expected_vulns[vuln_id] if vuln_id.startswith('CVE') else vuln_id for vuln_id in expected_vulns]
        expected_not_matching = {}
        actual_ghsa_vulns = []
        actual_not_matching = {}

        for vuln_id, vuln in result[query]['vulns'].items():
            if vuln_id.startswith('CVE-'):
                if 'ghsa' in vuln['sources']:
                    # check that ghsa vulns for the software are reported
                    self.assertIn(expected_vulns[vuln_id], vuln['aliases'])
                    for alias in vuln['aliases']:
                        if alias.startswith('GHSA-'):
                            actual_ghsa_vulns.append(alias)
                else:
                    # check that cve<->ghsa matchings work, even if the software is not vulnerable via GHSA
                    for alias in vuln['aliases']:
                        if alias.startswith('GHSA-'):
                            actual_not_matching[vuln_id] = alias
            elif vuln_id.startswith('GHSA-'):
                # check that GHSA attributes match
                actual_ghsa_vulns.append(vuln_id)
                self.assertEqual(vuln['published'], expected_vulns[vuln_id]['published'])
                self.assertEqual(vuln['cvss_ver'], expected_vulns[vuln_id]['cvss_ver'])
                self.assertEqual(vuln['cvss'], expected_vulns[vuln_id]['cvss'])
                self.assertEqual(vuln['cvss_vec'], expected_vulns[vuln_id]['cvss_vec'])
                self.assertEqual(vuln['aliases'], expected_vulns[vuln_id]['aliases'])
                if 'exploits' in expected_vulns[vuln_id]:
                    self.assertEqual(vuln['exploits'], expected_vulns[vuln_id]['exploits'])
        self.assertEqual(sorted(actual_ghsa_vulns), sorted(expected_ghsa_vulns))
        self.assertEqual(actual_not_matching, expected_not_matching)

    def test_search_electron_20_0_0(self):
        self.maxDiff = None
        query = 'cpe:2.3:a:electronjs:electron:20.0.0:*:*:*:*:*:*:*'
        result = search_vulns.search_vulns(query=query, is_good_cpe=False)
        expected_vulns = {'CVE-2023-44402': 'GHSA-7m48-wc93-9g85', 'CVE-2023-29198': 'GHSA-p7v2-p9m8-qqg7', 'CVE-2023-39956': 'GHSA-7x97-j373-85x5', 'GHSA-qqvq-6xgj-jw8g': {'published': '2023-09-28 18:30:45', 'cvss_ver': '3.1', 'cvss': '8.8', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H', 'aliases': ['CVE-2023-5217']}}
        expected_ghsa_vulns = [expected_vulns[vuln_id] if vuln_id.startswith('CVE') else vuln_id for vuln_id in expected_vulns]
        expected_not_matching = {'CVE-2022-36077': 'GHSA-p2jh-44qj-pf2v'}
        actual_ghsa_vulns = []
        actual_not_matching = {}

        for vuln_id, vuln in result[query]['vulns'].items():
            if vuln_id.startswith('CVE-'):
                if 'ghsa' in vuln['sources']:
                    # check that ghsa vulns for the software are reported
                    self.assertIn(expected_vulns[vuln_id], vuln['aliases'])
                    for alias in vuln['aliases']:
                        if alias.startswith('GHSA-'):
                            actual_ghsa_vulns.append(alias)
                else:
                    # check that cve<->ghsa matchings work, even if the software is not vulnerable via GHSA
                    for alias in vuln['aliases']:
                        if alias.startswith('GHSA-'):
                            actual_not_matching[vuln_id] = alias
            elif vuln_id.startswith('GHSA-'):
                # check that GHSA attributes match
                actual_ghsa_vulns.append(vuln_id)
                self.assertEqual(vuln['published'], expected_vulns[vuln_id]['published'])
                self.assertEqual(vuln['cvss_ver'], expected_vulns[vuln_id]['cvss_ver'])
                self.assertEqual(vuln['cvss'], expected_vulns[vuln_id]['cvss'])
                self.assertEqual(vuln['cvss_vec'], expected_vulns[vuln_id]['cvss_vec'])
                self.assertEqual(vuln['aliases'], expected_vulns[vuln_id]['aliases'])
                if 'exploits' in expected_vulns[vuln_id]:
                    self.assertEqual(vuln['exploits'], expected_vulns[vuln_id]['exploits'])
        self.assertEqual(sorted(actual_ghsa_vulns), sorted(expected_ghsa_vulns))
        self.assertEqual(actual_not_matching, expected_not_matching)

    def test_search_typo3_7_4_22(self):
        self.maxDiff = None
        query = 'cpe:2.3:a:typo3:typo3:7.4.22:*:*:*:*:*:*:*'
        result = search_vulns.search_vulns(query=query, is_good_cpe=False)
        expected_vulns = {'CVE-2022-31046': 'GHSA-8gmv-9hwg-w89g', 'CVE-2022-31047': 'GHSA-fh99-4pgr-8j99', 'CVE-2021-32768': 'GHSA-c5c9-8c6m-727v', 'CVE-2021-21339': 'GHSA-qx3w-4864-94ch', 'CVE-2021-21338': 'GHSA-4jhw-2p6j-5wmp', 'CVE-2022-36107': 'GHSA-9c6w-55cp-5w25', 'CVE-2022-23501': 'GHSA-jfp7-79g7-89rf', 'CVE-2022-36105': 'GHSA-m392-235j-9r7r', 'CVE-2018-6905': 'GHSA-3w22-wrwx-2r75', 'CVE-2021-32767': 'GHSA-34fr-fhqr-7235', 'CVE-2021-21370': 'GHSA-x7hc-x7fm-f7qh', 'GHSA-f777-f784-36gm': {'published': '2024-06-07 19:52:43', 'cvss_ver': '3.1', 'cvss': '8.1', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N', 'aliases': []}, 'GHSA-7q33-hxwj-7p8v': {'published': '2024-06-07 19:44:49', 'cvss_ver': '3.1', 'cvss': '5.4', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N', 'aliases': []}, 'GHSA-66c2-7g4p-wx4p': {'published': '2024-05-30 15:13:09', 'cvss_ver': '3.1', 'cvss': '5.3', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N', 'aliases': []}, 'GHSA-5cxf-xx9j-54jc': {'published': '2024-06-03 14:29:56', 'cvss_ver': '', 'cvss': '-1.0', 'cvss_vec': '', 'aliases': []}, 'GHSA-g4c9-qfvw-fmr4': {'published': '2024-05-30 14:57:50', 'cvss_ver': '3.1', 'cvss': '6.1', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N', 'aliases': []}, 'GHSA-56f9-5563-m2h7': {'published': '2022-05-17 03:59:51', 'cvss_ver': '3.0', 'cvss': '5.4', 'cvss_vec': 'CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N', 'aliases': ['CVE-2015-8755']}, 'GHSA-29m4-mx89-3mjg': {'published': '2024-05-30 15:33:17', 'cvss_ver': '3.1', 'cvss': '5.3', 'cvss_vec': 'CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H', 'aliases': []}, 'GHSA-jxg5-35fj-ccwf': {'published': '2022-05-17 03:02:43', 'cvss_ver': '3.0', 'cvss': '8.1', 'cvss_vec': 'CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H', 'aliases': ['CVE-2016-5091']}, 'GHSA-f3wf-q4fj-3gxf': {'published': '2024-06-07 19:56:24', 'cvss_ver': '3.1', 'cvss': '6.5', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H', 'aliases': []}, 'GHSA-ppvg-hw62-6ph9': {'published': '2024-05-30 15:11:42', 'cvss_ver': '3.1', 'cvss': '7.5', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N', 'aliases': []}, 'GHSA-6fc6-cj2j-h22x': {'published': '2024-06-03 17:00:44', 'cvss_ver': '', 'cvss': '-1.0', 'cvss_vec': '', 'aliases': []}, 'GHSA-6f9m-v7mp-7jjq': {'published': '2024-06-05 16:52:44', 'cvss_ver': '', 'cvss': '-1.0', 'cvss_vec': '', 'aliases': []}, 'GHSA-8c25-vj2w-p72j': {'published': '2024-05-30 14:59:25', 'cvss_ver': '3.1', 'cvss': '6.1', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N', 'aliases': []}, 'GHSA-6487-3qvg-8px9': {'published': '2024-06-07 19:55:04', 'cvss_ver': '3.1', 'cvss': '5.3', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N', 'aliases': []}, 'GHSA-hjx5-v9xg-7h25': {'published': '2024-05-30 15:36:27', 'cvss_ver': '3.1', 'cvss': '7.5', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H', 'aliases': []}, 'GHSA-x4rj-f7m6-42c3': {'published': '2024-05-30 13:49:16', 'cvss_ver': '3.1', 'cvss': '7.5', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N', 'aliases': []}, 'GHSA-gqqf-g5r7-84vf': {'published': '2022-09-15 03:26:51', 'cvss_ver': '3.1', 'cvss': '6.1', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N', 'aliases': []}, 'GHSA-8m6j-p5jv-v69w': {'published': '2024-06-07 19:43:19', 'cvss_ver': '3.1', 'cvss': '5.4', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N', 'aliases': []}, 'GHSA-ppgf-8745-8pgx': {'published': '2024-06-05 16:41:48', 'cvss_ver': '', 'cvss': '-1.0', 'cvss_vec': '', 'aliases': []}, 'GHSA-g585-crjf-vhwq': {'published': '2024-06-07 18:30:35', 'cvss_ver': '3.1', 'cvss': '7.5', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H', 'aliases': []}, 'GHSA-75mx-chcf-2q32': {'published': '2024-05-30 21:25:26', 'cvss_ver': '3.1', 'cvss': '6.1', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N', 'aliases': []}, 'GHSA-2rcw-9hrm-8q7q': {'published': '2024-06-07 19:47:52', 'cvss_ver': '3.1', 'cvss': '5.4', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N', 'aliases': []}, 'GHSA-cc97-g92w-jm65': {'published': '2024-05-30 13:52:08', 'cvss_ver': '3.1', 'cvss': '9.8', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 'aliases': []}, 'GHSA-j5v7-9xr5-m7gx': {'published': '2022-05-17 03:59:52', 'cvss_ver': '3.0', 'cvss': '5.4', 'cvss_vec': 'CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N', 'aliases': ['CVE-2015-8759']}}
        expected_ghsa_vulns = [expected_vulns[vuln_id] if vuln_id.startswith('CVE') else vuln_id for vuln_id in expected_vulns]
        expected_not_matching = {'CVE-2019-19848': 'GHSA-77p4-wfr8-977w', 'CVE-2019-19849': 'GHSA-rcgc-4xfc-564v', 'CVE-2024-22188': 'GHSA-5w2h-59j3-8x5w', 'CVE-2024-34537': 'GHSA-ffcv-v6pw-qhrp'}
        actual_ghsa_vulns = []
        actual_not_matching = {}

        for vuln_id, vuln in result[query]['vulns'].items():
            if vuln_id.startswith('CVE-'):
                if 'ghsa' in vuln['sources']:
                    # check that ghsa vulns for the software are reported
                    self.assertIn(expected_vulns[vuln_id], vuln['aliases'])
                    for alias in vuln['aliases']:
                        if alias.startswith('GHSA-'):
                            actual_ghsa_vulns.append(alias)
                else:
                    # check that cve<->ghsa matchings work, even if the software is not vulnerable via GHSA
                    for alias in vuln['aliases']:
                        if alias.startswith('GHSA-'):
                            actual_not_matching[vuln_id] = alias
            elif vuln_id.startswith('GHSA-'):
                # check that GHSA attributes match
                actual_ghsa_vulns.append(vuln_id)
                self.assertEqual(vuln['published'], expected_vulns[vuln_id]['published'])
                self.assertEqual(vuln['cvss_ver'], expected_vulns[vuln_id]['cvss_ver'])
                self.assertEqual(vuln['cvss'], expected_vulns[vuln_id]['cvss'])
                self.assertEqual(vuln['cvss_vec'], expected_vulns[vuln_id]['cvss_vec'])
                self.assertEqual(vuln['aliases'], expected_vulns[vuln_id]['aliases'])
                if 'exploits' in expected_vulns[vuln_id]:
                    self.assertEqual(vuln['exploits'], expected_vulns[vuln_id]['exploits'])
        self.assertEqual(sorted(actual_ghsa_vulns), sorted(expected_ghsa_vulns))
        self.assertEqual(actual_not_matching, expected_not_matching)

    def test_search_keycloak_23_0_7(self):
        self.maxDiff = None
        query = 'cpe:2.3:a:redhat:keycloak:23.0.7:*:*:*:*:*:*:*'
        result = search_vulns.search_vulns(query=query, is_good_cpe=False)
        expected_vulns = {'GHSA-cq42-vhv7-xr7p': {'published': '2024-06-12 19:42:21', 'cvss_ver': '3.1', 'cvss': '3.7', 'cvss_vec': 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L', 'aliases': ['CVE-2024-1722']}, 'GHSA-4vc8-pg5c-vg4x': {'published': '2024-06-12 19:41:05', 'cvss_ver': '3.1', 'cvss': '3.7', 'cvss_vec': 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L', 'aliases': ['CVE-2021-3754']}, 'CVE-2024-7260': 'GHSA-g4gc-rh26-m3p5', 'CVE-2024-4629': 'GHSA-gc7q-jgjv-vjr2', 'CVE-2024-7341': 'GHSA-5rxp-2rhr-qwqv', 'GHSA-w97f-w3hq-36g2': {'published': '2024-09-10 18:30:44', 'cvss_ver': '3.1', 'cvss': '6.5', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H', 'aliases': ['CVE-2023-6841']}, 'GHSA-w8gr-xwp4-r9f7': {'published': '2024-10-14 20:55:22', 'cvss_ver': '3.1', 'cvss': '6.1', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N', 'aliases': ['CVE-2024-8883']}, 'GHSA-xmmm-jw76-q7vg': {'published': '2024-10-14 20:56:43', 'cvss_ver': '3.1', 'cvss': '4.8', 'cvss_vec': 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N', 'aliases': ['CVE-2024-7318']}, 'GHSA-93ww-43rr-79v3': {'published': '2024-11-25 19:40:46', 'cvss_ver': '3.1', 'cvss': '7.1', 'cvss_vec': 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N', 'aliases': ['CVE-2024-10039']}, 'CVE-2024-10492': 'GHSA-5545-r4hg-rj4m', 'CVE-2025-3501': 'GHSA-hw58-3793-42gg', 'CVE-2024-1132': 'GHSA-72vp-xfrc-42xm', 'CVE-2023-0657': 'GHSA-7fpj-9hr8-28vh', 'CVE-2024-4540': 'GHSA-69fp-7c8p-crjr', 'CVE-2023-3597': 'GHSA-4f53-xh3v-g8x4', 'CVE-2023-6717': 'GHSA-8rmm-gm28-pj8q', 'CVE-2024-10270': 'GHSA-wq8x-cg39-8mrr', 'CVE-2024-2419': 'GHSA-mrv8-pqfj-7gp5', 'CVE-2024-1249': 'GHSA-m6q9-p373-g5q8', 'CVE-2024-5967': 'GHSA-c25h-c27q-5qpv', 'CVE-2025-1391': 'GHSA-gvgg-2r3r-53x7', 'CVE-2024-10451': 'GHSA-v7gv-xpgf-6395', 'CVE-2024-8698': 'GHSA-xgfv-xpx8-qhcr', 'CVE-2023-6544': 'GHSA-46c8-635v-68r2', 'CVE-2024-11736': 'GHSA-f4v7-3mww-9gc2', 'CVE-2024-11734': 'GHSA-w3g8-r9gw-qrh8', 'CVE-2023-6787': 'GHSA-c9h6-v78w-52wj', 'CVE-2024-9666': 'GHSA-jgwc-jh89-rpgq', 'CVE-2024-3656': 'GHSA-2cww-fgmg-4jqc', 'CVE-2025-0604': 'GHSA-2p82-5wwr-43cw', 'CVE-2025-3910': 'GHSA-5jfq-x6xp-7rw2', 'GHSA-q4xq-445g-g6ch': {'published': '2025-02-18 18:33:21', 'cvss_ver': '3.1', 'cvss': '3.8', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:N', 'aliases': ['CVE-2024-4028']}, 'GHSA-2935-2wfm-hhpv': {'published': '2025-03-25 09:32:07', 'cvss_ver': '3.1', 'cvss': '4.9', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H', 'aliases': ['CVE-2025-2559']}}
        expected_ghsa_vulns = [expected_vulns[vuln_id] if vuln_id.startswith('CVE') else vuln_id for vuln_id in expected_vulns]
        expected_not_matching = {'CVE-2023-0105': 'GHSA-c7xw-p58w-h6fj', 'CVE-2022-4137': 'GHSA-9hhc-pj4w-w5rv', 'CVE-2022-0225': 'GHSA-fqc7-5xxc-ph7r', 'CVE-2020-10734': 'GHSA-rvjg-gxwx-j5gf', 'CVE-2023-1664': 'GHSA-5cc8-pgp5-7mpm', 'CVE-2023-48795': 'GHSA-45x7-px36-x8w8', 'CVE-2017-12160': 'GHSA-qc72-gfvw-76h7', 'CVE-2023-2422': 'GHSA-3qh5-qqj2-c78f', 'CVE-2022-1438': 'GHSA-w354-2f3c-qvg9', 'CVE-2023-0091': 'GHSA-v436-q368-hvgg', 'CVE-2023-6927': 'GHSA-3p75-q5cc-qmj7', 'CVE-2017-12159': 'GHSA-7fmw-85qm-h22p', 'CVE-2017-12158': 'GHSA-v38p-mqq3-m6v5'}
        actual_ghsa_vulns = []
        actual_not_matching = {}

        for vuln_id, vuln in result[query]['vulns'].items():
            if vuln_id.startswith('CVE-'):
                if 'ghsa' in vuln['sources']:
                    # check that ghsa vulns for the software are reported
                    self.assertIn(expected_vulns[vuln_id], vuln['aliases'])
                    for alias in vuln['aliases']:
                        if alias.startswith('GHSA-'):
                            actual_ghsa_vulns.append(alias)
                else:
                    # check that cve<->ghsa matchings work, even if the software is not vulnerable via GHSA
                    for alias in vuln['aliases']:
                        if alias.startswith('GHSA-'):
                            actual_not_matching[vuln_id] = alias
            elif vuln_id.startswith('GHSA-'):
                # check that GHSA attributes match
                actual_ghsa_vulns.append(vuln_id)
                self.assertEqual(vuln['published'], expected_vulns[vuln_id]['published'])
                self.assertEqual(vuln['cvss_ver'], expected_vulns[vuln_id]['cvss_ver'])
                self.assertEqual(vuln['cvss'], expected_vulns[vuln_id]['cvss'])
                self.assertEqual(vuln['cvss_vec'], expected_vulns[vuln_id]['cvss_vec'])
                self.assertEqual(vuln['aliases'], expected_vulns[vuln_id]['aliases'])
                if 'exploits' in expected_vulns[vuln_id]:
                    self.assertEqual(vuln['exploits'], expected_vulns[vuln_id]['exploits'])
        self.assertEqual(sorted(actual_ghsa_vulns), sorted(expected_ghsa_vulns))
        self.assertEqual(sorted(actual_not_matching), sorted(expected_not_matching))

    def test_search_wagtail_2_7_4(self):
        self.maxDiff = None
        query = 'cpe:2.3:a:torchbox:wagtail:2.7.4:*:*:*:*:*:*:*'
        result = search_vulns.search_vulns(query=query, is_good_cpe=False)
        expected_vulns = {'CVE-2023-28836': 'GHSA-5286-f2rf-35c2', 'CVE-2021-32681': 'GHSA-xfrw-hxr5-ghqf', 'CVE-2021-29434': 'GHSA-wq5h-f9p5-q7fx', 'CVE-2023-45809': 'GHSA-fc75-58r8-rm3h', 'CVE-2023-28837': 'GHSA-33pv-vcgh-jfg9', 'CVE-2024-39317': 'GHSA-jmp3-39vp-fwg8'}
        expected_ghsa_vulns = [expected_vulns[vuln_id] if vuln_id.startswith('CVE') else vuln_id for vuln_id in expected_vulns]
        expected_not_matching = {}
        actual_ghsa_vulns = []
        actual_not_matching = {}

        for vuln_id, vuln in result[query]['vulns'].items():
            if vuln_id.startswith('CVE-'):
                if 'ghsa' in vuln['sources']:
                    # check that ghsa vulns for the software are reported
                    self.assertIn(expected_vulns[vuln_id], vuln['aliases'])
                    for alias in vuln['aliases']:
                        if alias.startswith('GHSA-'):
                            actual_ghsa_vulns.append(alias)
                else:
                    # check that cve<->ghsa matchings work, even if the software is not vulnerable via GHSA
                    for alias in vuln['aliases']:
                        if alias.startswith('GHSA-'):
                            actual_not_matching[vuln_id] = alias
            elif vuln_id.startswith('GHSA-'):
                # check that GHSA attributes match
                actual_ghsa_vulns.append(vuln_id)
                self.assertEqual(vuln['published'], expected_vulns[vuln_id]['published'])
                self.assertEqual(vuln['cvss_ver'], expected_vulns[vuln_id]['cvss_ver'])
                self.assertEqual(vuln['cvss'], expected_vulns[vuln_id]['cvss'])
                self.assertEqual(vuln['cvss_vec'], expected_vulns[vuln_id]['cvss_vec'])
                self.assertEqual(vuln['aliases'], expected_vulns[vuln_id]['aliases'])
                if 'exploits' in expected_vulns[vuln_id]:
                    self.assertEqual(vuln['exploits'], expected_vulns[vuln_id]['exploits'])
        self.assertEqual(sorted(actual_ghsa_vulns), sorted(expected_ghsa_vulns))
        self.assertEqual(actual_not_matching, expected_not_matching)


if __name__ == '__main__':
    unittest.main()

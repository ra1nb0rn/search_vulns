#!/usr/bin/env python3

import unittest
import sys

sys.path.insert(1, '../search_vulns/')
import search_vulns

class TestSearches(unittest.TestCase):

    def test_search_wp_572(self):
        self.maxDiff = None
        result = search_vulns.search_vulns(query='cpe:2.3:a:wordpress:wordpress:5.7.2:*:*:*:*:*:*:*', add_other_exploit_refs=True, is_good_cpe=True)
        expected_cves = ['CVE-2021-44223', 'CVE-2022-21663', 'CVE-2022-21664', 'CVE-2012-6527', 'CVE-2022-43497', 'CVE-2007-2627', 'CVE-2012-4271', 'CVE-2022-3590', 'CVE-2011-5216', 'CVE-2023-22622', 'CVE-2013-7240', 'CVE-2022-21661', 'CVE-2021-39201', 'CVE-2022-21662', 'CVE-2023-2745', 'CVE-2021-39200', 'CVE-2022-43504', 'CVE-2022-43500']
        self.assertEqual(set(expected_cves), set(list(result.keys())))

    def test_search_apache_2425(self):
        self.maxDiff = None
        result = search_vulns.search_vulns(query='cpe:2.3:a:apache:http_server:2.4.25:*:*:*:*:*:*:*', add_other_exploit_refs=True, is_good_cpe=True)
        expected_cves = ['CVE-2017-15710', 'CVE-2017-3169', 'CVE-2017-7659', 'CVE-2017-7668', 'CVE-2017-9798', 'CVE-2018-1312', 'CVE-2018-17189', 'CVE-2020-9490', 'CVE-2021-26691', 'CVE-2017-3167', 'CVE-2022-28615', 'CVE-2023-25690', 'CVE-1999-0289', 'CVE-2021-33193', 'CVE-2019-9517', 'CVE-2022-30556', 'CVE-2019-0217', 'CVE-2018-1303', 'CVE-2018-11763', 'CVE-2022-37436', 'CVE-2022-22719', 'CVE-2006-20001', 'CVE-2021-26690', 'CVE-2022-36760', 'CVE-2022-26377', 'CVE-2017-9788', 'CVE-2020-13938', 'CVE-2019-17567', 'CVE-2022-31813', 'CVE-2021-40438', 'CVE-2019-0211', 'CVE-2021-34798', 'CVE-2019-10092', 'CVE-1999-1237', 'CVE-1999-0236', 'CVE-2019-0220', 'CVE-2018-1301', 'CVE-2020-11993', 'CVE-1999-1412', 'CVE-2020-1927', 'CVE-2017-7679', 'CVE-2021-39275', 'CVE-2022-28330', 'CVE-2019-10098', 'CVE-2022-28614', 'CVE-2019-10081', 'CVE-2020-1934', 'CVE-2007-0450', 'CVE-2018-17199', 'CVE-2021-44790', 'CVE-1999-0678', 'CVE-2022-29404', 'CVE-2021-44224', 'CVE-2019-0196', 'CVE-2022-22720', 'CVE-2017-15715', 'CVE-2022-23943', 'CVE-2020-35452', 'CVE-2018-1283', 'CVE-2019-10082', 'CVE-2022-22721', 'CVE-2018-1302', 'CVE-2007-0086', 'CVE-2018-1333']
        self.assertEqual(set(expected_cves), set(list(result.keys())))

    def test_search_proftpd_133c(self):
        self.maxDiff = None
        result = search_vulns.search_vulns(query='cpe:2.3:a:proftpd:proftpd:1.3.3:c:*:*:*:*:*:*', add_other_exploit_refs=True, is_good_cpe=True)
        expected_cves = ['CVE-2011-1137', 'CVE-2011-4130', 'CVE-2012-6095', 'CVE-2019-19271', 'CVE-2019-19272', 'CVE-2019-19269', 'CVE-2019-12815', 'CVE-2021-46854', 'CVE-2019-19270', 'CVE-2020-9272', 'CVE-2019-18217', 'CVE-2010-4652']
        self.assertEqual(set(expected_cves), set(list(result.keys())))

    def test_search_thingsboard_341(self):
        self.maxDiff = None
        result = search_vulns.search_vulns(query='cpe:2.3:a:thingsboard:thingsboard:3.4.1:*:*:*:*:*:*:*', add_other_exploit_refs=True, is_good_cpe=True)
        expected_cves = ['CVE-2022-40004', 'CVE-2022-45608', 'CVE-2022-48341', 'CVE-2023-26462']
        self.assertEqual(set(expected_cves), set(list(result.keys())))

    def test_search_redis_323(self):
        self.maxDiff = None
        result = search_vulns.search_vulns(query='cpe:2.3:a:redis:redis:3.2.3:*:*:*:*:*:*:*', add_other_exploit_refs=True, is_good_cpe=True)
        expected_cves = ['CVE-2021-32626', 'CVE-2022-3647', 'CVE-2022-24735', 'CVE-2023-28856', 'CVE-2022-0543', 'CVE-2021-32672', 'CVE-2022-24736', 'CVE-2022-3734', 'CVE-2022-24834', 'CVE-2022-36021', 'CVE-2023-25155', 'CVE-2021-31294']
        self.assertEqual(set(expected_cves), set(list(result.keys())))

    def test_search_piwik_045(self):
        self.maxDiff = None
        result = search_vulns.search_vulns(query='cpe:2.3:a:piwik:piwik:0.4.5:*:*:*:*:*:*:*', add_other_exploit_refs=True)
        expected_cves = ['CVE-2015-7815','CVE-2015-7816','CVE-2011-0398','CVE-2013-0193','CVE-2013-0194','CVE-2013-0195','CVE-2011-0400','CVE-2011-0401','CVE-2013-2633','CVE-2010-1453','CVE-2011-0004','CVE-2011-0399','CVE-2012-4541','CVE-2013-1844']
        self.assertEqual(set(expected_cves), set(list(result.keys())))

    def test_search_vmware_spring_framework_5326(self):
        self.maxDiff = None
        result = search_vulns.search_vulns(query='cpe:2.3:a:vmware:spring_framework:5.3.26:*:*:*:*:*:*:*', add_other_exploit_refs=True, is_good_cpe=True)
        expected_cves = ['CVE-2016-1000027', 'CVE-2023-20863']
        self.assertEqual(set(expected_cves), set(list(result.keys())))

    def test_search_zulip_server_48(self):
        self.maxDiff = None
        result = search_vulns.search_vulns(query='cpe:2.3:a:zulip:zulip:4.8:*:*:*:*:*:*:*', add_other_exploit_refs=True, is_good_cpe=True)
        expected_cves = ['CVE-2022-35962', 'CVE-2022-36048', 'CVE-2023-28623', 'CVE-2021-43799', 'CVE-2023-32677', 'CVE-2022-31017', 'CVE-2022-24751', 'CVE-2021-3967', 'CVE-2021-3866', 'CVE-2022-31168']
        self.assertEqual(set(expected_cves), set(list(result.keys())))

    def test_search_electron_1317(self):
        self.maxDiff = None
        result = search_vulns.search_vulns(query='cpe:2.3:a:electronjs:electron:13.1.7:*:*:*:*:*:*:*', add_other_exploit_refs=True, is_good_cpe=True)
        expected_cves = ['CVE-2022-36077', 'CVE-2022-29247', 'CVE-2022-21718', 'CVE-2022-29257', 'CVE-2021-39184']
        self.assertEqual(set(expected_cves), set(list(result.keys())))


if __name__ == '__main__':
    unittest.main()

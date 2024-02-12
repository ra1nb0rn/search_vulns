#!/usr/bin/env python3

import os
import unittest
import sys

SEARCH_VULNS_PATH = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
sys.path.insert(1, SEARCH_VULNS_PATH)
from search_vulns_modules.search_vulns import search_vulns

class TestSearches(unittest.TestCase):

    def test_search_tigervnc_1111_rhel_85(self):
        self.maxDiff = None
        result,_ = search_vulns(query='cpe:2.3:a:tigervnc:tigervnc:1.11.1:*:*:*:*:*:*:rhel_8.5', add_other_exploit_refs=True, is_good_cpe=True)
        expected_cves = ['CVE-2023-5380','CVE-2022-46344','CVE-2022-46343','CVE-2022-46342','CVE-2022-46341','CVE-2022-46340','CVE-2022-4283','CVE-2014-8241']
        self.assertEqual(set(expected_cves), set(list(result.keys())))

    def test_search_rsyslog_819111_rhel_85(self):
        self.maxDiff = None
        result,_ = search_vulns(query='cpe:2.3:a:rsyslog:rsyslog:8.1911.1:*:*:*:*:*:*:rhel_8.5', add_other_exploit_refs=True, is_good_cpe=True)
        expected_cves = ['CVE-2022-32189', 'CVE-2015-3243']
        self.assertEqual(set(expected_cves), set(list(result.keys())))

    def test_search_gnutls_36_rhel_9(self):
        self.maxDiff = None
        result,_ = search_vulns(query='cpe:2.3:a:gnu:gnutls:3.6:*:*:*:*:*:*:rhel_9', add_other_exploit_refs=True, is_good_cpe=True)
        expected_cves = ['CVE-2024-0567', 'CVE-2024-0553', 'CVE-2023-5981', 'CVE-2023-0361', 'CVE-2022-2509', 'CVE-2021-20305', 'CVE-2020-24659', 'CVE-2020-13777', 'CVE-2020-11501', 'CVE-2019-3836', 'CVE-2019-3829', 'CVE-2016-8610', 'CVE-2015-6251', 'CVE-2015-3308', 'CVE-2015-2808', 'CVE-2015-0294', 'CVE-2014-3566', 'CVE-2012-4929', 'CVE-2011-3389']
        self.assertEqual(set(expected_cves), set(list(result.keys())))

    def test_search_squid_cache_squid_555_rhel_92(self):
        self.maxDiff = None
        result,_ = search_vulns(query='cpe:2.3:a:squid-cache:squid:5.5-5:*:*:*:*:*:*:rhel_9.2', add_other_exploit_refs=True, is_good_cpe=True)
        expected_cves = ['CVE-2024-23638', 'CVE-2023-50269', 'CVE-2023-49288', 'CVE-2022-41317', 'CVE-2019-12522', 'CVE-2016-10003', 'CVE-2015-5400', 'CVE-2014-9749', 'CVE-2014-6270', 'CVE-2010-2951']
        self.assertEqual(set(expected_cves), set(list(result.keys())))

    def test_search_openssl_111k_rhel_8(self):
        self.maxDiff = None
        result,_ = search_vulns(query='OpenSSL 1.1.1k RHEL 8', add_other_exploit_refs=True, is_good_cpe=True)
        expected_cves = ['CVE-2024-0727', 'CVE-2023-5678', 'CVE-2023-3817', 'CVE-2023-2650', 'CVE-2023-0466', 'CVE-2023-0465', 'CVE-2023-0464', 'CVE-2022-40735', 'CVE-2019-1563', 'CVE-2019-1551', 'CVE-2019-1547', 'CVE-2016-2183', 'CVE-2015-4000', 'CVE-2015-2808', 'CVE-2014-3566', 'CVE-2011-1473'] 
        self.assertEqual(set(expected_cves), set(list(result.keys())))


if __name__ == '__main__':
    unittest.main()
#!/usr/bin/env python3

import os
import unittest
import sys

SEARCH_VULNS_PATH = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
sys.path.insert(1, SEARCH_VULNS_PATH)
import search_vulns

class TestSearches(unittest.TestCase):

    def test_search_libcurl_788_ubuntu_2210(self):
        self.maxDiff = None
        query = 'libcurl 7.88 ubuntu kinetic'
        result,_ = search_vulns.search_vulns(query, add_other_exploit_refs=True, is_good_cpe=True)
        expected_cves = ['CVE-2023-38545', 'CVE-2023-38546']
        self.assertEqual(set(expected_cves), set(list(result[query]['vulns'].keys())))

    def test_search_vim_81_ubuntu_1404(self):
        self.maxDiff = None
        query = 'cpe:2.3:a:vim:vim:8.1:*:*:*:*:ubuntu_14.04:*:*'
        result,_ = search_vulns.search_vulns(query, add_other_exploit_refs=True, is_good_cpe=True)
        expected_cves = ['CVE-2022-0318', 'CVE-2022-1733', 'CVE-2022-1942', 'CVE-2022-3037', 'CVE-2022-1629', 'CVE-2022-1898', 'CVE-2022-1796', 'CVE-2022-1851', 'CVE-2022-2125', 'CVE-2022-2124', 'CVE-2022-1619', 'CVE-2021-4069', 'CVE-2022-3235', 'CVE-2022-0361', 'CVE-2022-1616', 'CVE-2022-2126', 'CVE-2022-2042', 'CVE-2021-3984', 'CVE-2021-3974', 'CVE-2022-1968', 'CVE-2022-2175', 'CVE-2021-3973', 'CVE-2019-12735', 'CVE-2022-1735', 'CVE-2022-3134', 'CVE-2022-3297', 'CVE-2022-1720', 'CVE-2022-1621', 'CVE-2022-2522', 'CVE-2022-3296', 'CVE-2022-0261', 'CVE-2022-2849', 'CVE-2022-1785', 'CVE-2022-2183', 'CVE-2022-2000', 'CVE-2022-2129', 'CVE-2021-4019', 'CVE-2022-2946', 'CVE-2022-4141', 'CVE-2022-2845', 'CVE-2022-3705', 'CVE-2022-1620', 'CVE-2021-4166', 'CVE-2022-1674', 'CVE-2022-1725', 'CVE-2022-2598', 'CVE-2022-1771', 'CVE-2022-2208', 'CVE-2023-1264', 'CVE-2017-1000382']
        self.assertEqual(set(expected_cves), set(list(result[query]['vulns'].keys())))
    
    def test_search_chrome_117_ubuntu_2304(self):
        self.maxDiff = None
        query = 'cpe:2.3:a:google:chrome:117:*:*:*:*:ubuntu_23.04:*:*'
        result,_ = search_vulns.search_vulns(query, add_other_exploit_refs=True, is_good_cpe=True)
        expected_cves = ['CVE-2013-6647', 'CVE-2009-1598', 'CVE-2013-6662', 'CVE-2016-7152', 'CVE-2016-7153', 'CVE-2018-10229', 'CVE-2011-3389', 'CVE-2010-1731', 'CVE-2015-4000', 'CVE-2012-4929', 'CVE-2012-4930', 'CVE-2008-5915']
        self.assertEqual(set(expected_cves), set(list(result[query]['vulns'].keys())))

    def test_search_thunderbird_1153_ubuntu_2204(self):
        self.maxDiff = None
        query = 'cpe:2.3:a:mozilla:thunderbird:115.3:*:*:*:*:ubuntu_22.04:*:*'
        result,_ = search_vulns.search_vulns(query, add_other_exploit_refs=True, is_good_cpe=True)
        expected_cves = ['CVE-2023-5176', 'CVE-2023-5730', 'CVE-2023-4057', 'CVE-2009-3982', 'CVE-2009-3980', 'CVE-2009-3981', 'CVE-2009-1840', 'CVE-2023-3600', 'CVE-2023-6208', 'CVE-2023-5217', 'CVE-2023-6212', 'CVE-2023-4585', 'CVE-2023-6207', 'CVE-2023-5728', 'CVE-2023-4583', 'CVE-2023-5724', 'CVE-2009-3984', 'CVE-2023-5171', 'CVE-2023-4580', 'CVE-2023-6204', 'CVE-2023-4578', 'CVE-2023-6209', 'CVE-2023-5732', 'CVE-2023-5727', 'CVE-2023-5169', 'CVE-2023-6205', 'CVE-2023-4577', 'CVE-2017-17688', 'CVE-2023-6206', 'CVE-2009-4630', 'CVE-2023-5721', 'CVE-2023-5725', 'CVE-2023-5726', 'CVE-2022-40674', 'CVE-2022-23990', 'CVE-2022-25315', 'CVE-2022-37609', 'CVE-2022-25314', 'CVE-2022-25313', 'CVE-2022-43680', 'CVE-2022-39393', 'CVE-2022-31146', 'CVE-2022-25236', 'CVE-2023-1999', 'CVE-2022-24791', 'CVE-2022-23639', 'CVE-2022-25235', 'CVE-2022-39394', 'CVE-2022-3857', 'CVE-2022-39392', 'CVE-2022-31169', 'CVE-2022-23852', 'CVE-2023-6864','CVE-2023-6857','CVE-2023-6858','CVE-2023-50761','CVE-2023-6873','CVE-2023-6856','CVE-2023-6859','CVE-2023-6861','CVE-2023-50762','CVE-2023-6860','CVE-2023-6862', 'CVE-2023-6863']
        self.assertEqual(set(expected_cves), set(list(result[query]['vulns'].keys())))

    def test_search_chrome_1170593862_ubuntu_general(self):
        self.maxDiff = None
        query = 'ubuntu google chrome 117.0.5938.62'
        result,_ = search_vulns.search_vulns(query, add_other_exploit_refs=False, is_good_cpe=True)
        expected_cves = ['CVE-2013-6647', 'CVE-2009-1598', 'CVE-2013-6662', 'CVE-2016-7153', 'CVE-2016-7152', 'CVE-2018-10229', 'CVE-2011-3389', 'CVE-2010-1731', 'CVE-2015-4000', 'CVE-2012-4929', 'CVE-2012-4930', 'CVE-2008-5915']
        self.assertEqual(set(expected_cves), set(list(result[query]['vulns'].keys())))

    def test_search_ubuntu_linux_2304(self):
        self.maxDiff = None
        query = 'cpe:2.3:o:canonical:ubuntu_linux:23.04:*:*:*:*:*:*:*'
        result,_ = search_vulns.search_vulns(query, add_other_exploit_refs=False, is_good_cpe=True)
        expected_cves = ['CVE-2023-1523', 'CVE-2023-2640', 'CVE-2023-32629', 'CVE-2023-3297', 'CVE-2023-5536', 'CVE-2023-1786']
        self.assertEqual(set(expected_cves), set(list(result[query]['vulns'].keys())))


if __name__ == '__main__':
    unittest.main()
#!/usr/bin/env python3

import os
import unittest
import sys

SEARCH_VULNS_PATH = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
sys.path.insert(1, SEARCH_VULNS_PATH)
from search_vulns_modules.search_vulns_functions import search_vulns

class TestSearches(unittest.TestCase):

    def test_search_libcurl_788_ubuntu_2210(self):
        self.maxDiff = None
        query = 'haxx libcurl 7.88 ubuntu kinetic'
        result,_ = search_vulns(query, add_other_exploit_refs=True)
        expected_cves = ['CVE-2024-32928', 'CVE-2024-7264', 'CVE-2023-46219', 'CVE-2023-46218', 'CVE-2023-38545', 'CVE-2023-38546', 'CVE-2023-38039']
        self.assertEqual(set(expected_cves), set(list(result[query]['vulns'].keys())))

    def test_search_vim_81_ubuntu_1404(self):
        self.maxDiff = None
        query = 'cpe:2.3:a:vim:vim:8.1:*:*:*:*:*:*:ubuntu_14.04_esm'
        result,_ = search_vulns(query, add_other_exploit_refs=True, is_good_cpe=True)
        expected_cves = ['CVE-2024-43790', 'CVE-2024-43374', 'CVE-2024-41957','CVE-2024-41965','CVE-2023-1264', 'CVE-2022-4141', 'CVE-2022-3705', 'CVE-2022-3297', 'CVE-2022-3296', 'CVE-2022-3235', 'CVE-2022-3134', 'CVE-2022-3037', 'CVE-2022-2946', 'CVE-2022-2849', 'CVE-2022-2845', 'CVE-2022-2598', 'CVE-2022-2522', 'CVE-2022-2208', 'CVE-2022-1720', 'CVE-2022-0361', 'CVE-2022-0318', 'CVE-2022-0261', 'CVE-2021-4166', 'CVE-2017-1000382']
        self.assertEqual(set(expected_cves), set(list(result[query]['vulns'].keys())))
    
    def test_search_chrome_117_ubuntu_2304(self):
        self.maxDiff = None
        query = 'cpe:2.3:a:google:chrome:117:*:*:*:*:*:*:ubuntu_23.04'
        result,_ = search_vulns(query, add_other_exploit_refs=True, is_good_cpe=True)
        expected_cves = ['CVE-2009-1598', 'CVE-2016-7152', 'CVE-2016-7153', 'CVE-2018-10229', 'CVE-2011-3389', 'CVE-2015-4000', 'CVE-2008-5915', 'CVE-2010-1731', 'CVE-2024-3171', 'CVE-2024-3176', 'CVE-2024-3168', 'CVE-2024-3175', 'CVE-2024-3174', 'CVE-2024-3173', 'CVE-2024-3169', 'CVE-2024-3172', 'CVE-2024-2884', 'CVE-2024-3170', 'CVE-2024-5500']

        self.assertEqual(set(expected_cves), set(list(result[query]['vulns'].keys())))

    def test_search_thunderbird_1153_ubuntu_2204(self):
        self.maxDiff = None
        query = 'cpe:2.3:a:mozilla:thunderbird:115.3:*:*:*:*:*:*:ubuntu_22.04'
        result,_ = search_vulns(query, add_other_exploit_refs=True, is_good_cpe=True)
        expected_cves = ['CVE-2021-4231', 'CVE-2022-29167', 'CVE-2016-4472', 'CVE-2023-4577', 'CVE-2023-5732', 'CVE-2022-39393', 'CVE-2011-0051', 'CVE-2022-40674', 'CVE-2024-1936', 'CVE-2023-6208', 'CVE-2024-0746', 'CVE-2024-2614', 'CVE-2024-1546', 'CVE-2022-31169', 'CVE-2024-1549', 'CVE-2023-6207', 'CVE-2022-31146', 'CVE-2024-1550', 'CVE-2009-3984', 'CVE-2023-6864', 'CVE-2024-2607', 'CVE-2023-5730', 'CVE-2023-4585', 'CVE-2015-7210', 'CVE-2009-3980', 'CVE-2016-5827', 'CVE-2011-2998', 'CVE-2023-6858', 'CVE-2019-20446', 'CVE-2023-6860', 'CVE-2024-0755', 'CVE-2023-31670', 'CVE-2023-5176', 'CVE-2024-0743', 'CVE-2023-5725', 'CVE-2024-0751', 'CVE-2023-6206', 'CVE-2014-6272', 'CVE-2022-23990', 'CVE-2023-5217', 'CVE-2022-3857', 'CVE-2022-25314', 'CVE-2017-17688', 'CVE-2024-2609', 'CVE-2024-1551', 'CVE-2024-2611', 'CVE-2009-1840', 'CVE-2023-6212', 'CVE-2022-25315', 'CVE-2024-1552', 'CVE-2022-43680', 'CVE-2024-0753', 'CVE-2022-39392', 'CVE-2022-23639', 'CVE-2023-6204', 'CVE-2024-0747', 'CVE-2022-23852', 'CVE-2022-24791', 'CVE-2023-6209', 'CVE-2023-6863', 'CVE-2016-5826', 'CVE-2023-5388', 'CVE-2024-1553', 'CVE-2023-5171', 'CVE-2024-1547', 'CVE-2022-25236', 'CVE-2023-50761', 'CVE-2023-6857', 'CVE-2024-0749', 'CVE-2022-0235', 'CVE-2024-0750', 'CVE-2009-4630', 'CVE-2024-2616', 'CVE-2009-3981', 'CVE-2020-0470', 'CVE-2024-2608', 'CVE-2022-37609', 'CVE-2024-2612', 'CVE-2022-25313', 'CVE-2023-4583', 'CVE-2023-4578', 'CVE-2017-0381', 'CVE-2023-6862', 'CVE-2023-6861', 'CVE-2023-3600', 'CVE-2023-6856', 'CVE-2023-5724', 'CVE-2023-5169', 'CVE-2023-4057', 'CVE-2024-2610', 'CVE-2023-5727', 'CVE-2023-5728', 'CVE-2015-6525', 'CVE-2023-50762', 'CVE-2023-5721', 'CVE-2022-39394', 'CVE-2023-5726', 'CVE-2022-25235', 'CVE-2023-4580', 'CVE-2024-0742', 'CVE-2024-1548', 'CVE-2016-5825', 'CVE-2009-3982', 'CVE-2023-6205', 'CVE-2023-1999', 'CVE-2023-6859', 'CVE-2016-5823', 'CVE-2024-7523', 'CVE-2024-6604', 'CVE-2024-4367', 'CVE-2024-7531', 'CVE-2024-3859', 'CVE-2024-5693', 'CVE-2024-7520', 'CVE-2024-6603', 'CVE-2024-4767', 'CVE-2024-42459', 'CVE-2024-4777', 'CVE-2024-7527', 'CVE-2024-4769', 'CVE-2024-5688', 'CVE-2024-4768', 'CVE-2024-7522', 'CVE-2024-4770', 'CVE-2024-3864', 'CVE-2024-5690', 'CVE-2024-7518', 'CVE-2024-3302', 'CVE-2024-29041', 'CVE-2024-3857', 'CVE-2024-3861', 'CVE-2024-5702', 'CVE-2024-7526', 'CVE-2024-7529', 'CVE-2024-7521', 'CVE-2024-5700', 'CVE-2024-5171', 'CVE-2024-3854', 'CVE-2024-7525', 'CVE-2024-6602', 'CVE-2024-5696', 'CVE-2024-7524', 'CVE-2024-7528', 'CVE-2024-5197', 'CVE-2024-3852', 'CVE-2024-7530', 'CVE-2024-7519', 'CVE-2024-6601', 'CVE-2024-5691']
        self.assertEqual(set(expected_cves), set(list(result[query]['vulns'].keys())))

    def test_search_thunderbird_1153_ubuntu_2204_ignore_general_distro(self):
        self.maxDiff = None
        query = 'cpe:2.3:a:mozilla:thunderbird:115.3:*:*:*:*:*:*:ubuntu_22.04'
        result,_ = search_vulns(query, add_other_exploit_refs=True, is_good_cpe=True, ignore_general_distribution_vulns=True)
        expected_cves = ['CVE-2023-4577', 'CVE-2023-5732', 'CVE-2022-39393', 'CVE-2022-40674', 'CVE-2024-1936', 'CVE-2023-6208', 'CVE-2024-0746', 'CVE-2024-2614', 'CVE-2024-1546', 'CVE-2022-31169', 'CVE-2024-1549', 'CVE-2023-6207', 'CVE-2022-31146', 'CVE-2024-1550', 'CVE-2009-3984', 'CVE-2023-6864', 'CVE-2024-2607', 'CVE-2023-5730', 'CVE-2023-4585', 'CVE-2009-3980', 'CVE-2023-6858', 'CVE-2023-6860', 'CVE-2024-0755', 'CVE-2023-5176', 'CVE-2024-0743', 'CVE-2023-5725', 'CVE-2024-0751', 'CVE-2023-6206', 'CVE-2022-23990', 'CVE-2023-5217', 'CVE-2022-3857', 'CVE-2022-25314', 'CVE-2017-17688', 'CVE-2024-2609', 'CVE-2024-1551', 'CVE-2024-2611', 'CVE-2009-1840', 'CVE-2023-6212', 'CVE-2022-25315', 'CVE-2024-1552', 'CVE-2022-43680', 'CVE-2024-0753', 'CVE-2022-39392', 'CVE-2022-23639', 'CVE-2023-6204', 'CVE-2024-0747', 'CVE-2022-23852', 'CVE-2022-24791', 'CVE-2023-6209', 'CVE-2023-6863', 'CVE-2023-5388', 'CVE-2024-1553', 'CVE-2023-5171', 'CVE-2024-1547', 'CVE-2022-25236', 'CVE-2023-50761', 'CVE-2023-6857', 'CVE-2024-0749', 'CVE-2024-0750', 'CVE-2009-4630', 'CVE-2024-2616', 'CVE-2009-3981', 'CVE-2024-2608', 'CVE-2022-37609', 'CVE-2024-2612', 'CVE-2022-25313', 'CVE-2023-4583', 'CVE-2023-4578', 'CVE-2023-6862', 'CVE-2023-6861', 'CVE-2023-3600', 'CVE-2023-6856', 'CVE-2023-5724', 'CVE-2023-5169', 'CVE-2023-4057', 'CVE-2024-2610', 'CVE-2023-5727', 'CVE-2023-5728', 'CVE-2023-50762', 'CVE-2023-5721', 'CVE-2022-39394', 'CVE-2023-5726', 'CVE-2022-25235', 'CVE-2023-4580', 'CVE-2024-0742', 'CVE-2024-1548', 'CVE-2009-3982', 'CVE-2023-6205', 'CVE-2023-1999', 'CVE-2023-6859', 'CVE-2024-7523', 'CVE-2024-6604', 'CVE-2024-4367', 'CVE-2024-7531', 'CVE-2024-3859', 'CVE-2024-5693', 'CVE-2024-7520', 'CVE-2024-6603', 'CVE-2024-4767', 'CVE-2024-4777', 'CVE-2024-7527', 'CVE-2024-4769', 'CVE-2024-5688', 'CVE-2024-4768', 'CVE-2024-7522', 'CVE-2024-4770', 'CVE-2024-3864', 'CVE-2024-5690', 'CVE-2024-7518', 'CVE-2024-3302', 'CVE-2024-3857', 'CVE-2024-3861', 'CVE-2024-5702', 'CVE-2024-7526', 'CVE-2024-7529', 'CVE-2024-7521', 'CVE-2024-5700', 'CVE-2024-3854', 'CVE-2024-7525', 'CVE-2024-6602', 'CVE-2024-5696', 'CVE-2024-7524', 'CVE-2024-7528', 'CVE-2024-3852', 'CVE-2024-7530', 'CVE-2024-7519', 'CVE-2024-6601', 'CVE-2024-5691']
        self.assertEqual(set(expected_cves), set(list(result[query]['vulns'].keys())))

    def test_search_thunderbird_1153_ubuntu_2204_ignore_general_cpe(self):
        self.maxDiff = None
        query = 'cpe:2.3:a:mozilla:thunderbird:115.3:*:*:*:*:*:*:ubuntu_22.04'
        result,_ = search_vulns(query, add_other_exploit_refs=True, is_good_cpe=True, ignore_general_cpe_vulns=True)
        expected_cves = ['CVE-2021-4231', 'CVE-2022-29167', 'CVE-2016-4472', 'CVE-2023-4577', 'CVE-2023-5732', 'CVE-2022-39393', 'CVE-2011-0051', 'CVE-2022-40674', 'CVE-2024-1936', 'CVE-2023-6208', 'CVE-2024-0746', 'CVE-2024-2614', 'CVE-2024-1546', 'CVE-2022-31169', 'CVE-2024-1549', 'CVE-2023-6207', 'CVE-2022-31146', 'CVE-2024-1550', 'CVE-2023-6864', 'CVE-2024-2607', 'CVE-2023-5730', 'CVE-2023-4585', 'CVE-2015-7210', 'CVE-2016-5827', 'CVE-2011-2998', 'CVE-2023-6858', 'CVE-2019-20446', 'CVE-2023-6860', 'CVE-2024-0755', 'CVE-2023-31670', 'CVE-2023-5176', 'CVE-2024-0743', 'CVE-2023-5725', 'CVE-2024-0751', 'CVE-2023-6206', 'CVE-2014-6272', 'CVE-2022-23990', 'CVE-2023-5217', 'CVE-2022-3857', 'CVE-2022-25314', 'CVE-2024-2609', 'CVE-2024-1551', 'CVE-2024-2611', 'CVE-2023-6212', 'CVE-2022-25315', 'CVE-2024-1552', 'CVE-2022-43680', 'CVE-2024-0753', 'CVE-2022-39392', 'CVE-2022-23639', 'CVE-2023-6204', 'CVE-2024-0747', 'CVE-2022-23852', 'CVE-2022-24791', 'CVE-2023-6209', 'CVE-2023-6863', 'CVE-2016-5826', 'CVE-2023-5388', 'CVE-2024-1553', 'CVE-2023-5171', 'CVE-2024-1547', 'CVE-2022-25236', 'CVE-2023-50761', 'CVE-2023-6857', 'CVE-2024-0749', 'CVE-2022-0235', 'CVE-2024-0750', 'CVE-2024-2616', 'CVE-2020-0470', 'CVE-2024-2608', 'CVE-2022-37609', 'CVE-2024-2612', 'CVE-2022-25313', 'CVE-2023-4583', 'CVE-2023-4578', 'CVE-2017-0381', 'CVE-2023-6862', 'CVE-2023-6861', 'CVE-2023-3600', 'CVE-2023-6856', 'CVE-2023-5724', 'CVE-2023-5169', 'CVE-2023-4057', 'CVE-2024-2610', 'CVE-2023-5727', 'CVE-2023-5728', 'CVE-2015-6525', 'CVE-2023-50762', 'CVE-2023-5721', 'CVE-2022-39394', 'CVE-2023-5726', 'CVE-2022-25235', 'CVE-2023-4580', 'CVE-2024-0742', 'CVE-2024-1548', 'CVE-2016-5825', 'CVE-2023-6205', 'CVE-2023-1999', 'CVE-2023-6859', 'CVE-2016-5823', 'CVE-2024-7523', 'CVE-2024-6604', 'CVE-2024-4367', 'CVE-2024-7531', 'CVE-2024-3859', 'CVE-2024-5693', 'CVE-2024-7520', 'CVE-2024-6603', 'CVE-2024-4767', 'CVE-2024-42459', 'CVE-2024-4777', 'CVE-2024-7527', 'CVE-2024-4769', 'CVE-2024-5688', 'CVE-2024-4768', 'CVE-2024-7522', 'CVE-2024-4770', 'CVE-2024-3864', 'CVE-2024-5690', 'CVE-2024-7518', 'CVE-2024-3302', 'CVE-2024-29041', 'CVE-2024-3857', 'CVE-2024-3861', 'CVE-2024-5702', 'CVE-2024-7526', 'CVE-2024-7529', 'CVE-2024-7521', 'CVE-2024-5700', 'CVE-2024-5171', 'CVE-2024-3854', 'CVE-2024-7525', 'CVE-2024-6602', 'CVE-2024-5696', 'CVE-2024-7524', 'CVE-2024-7528', 'CVE-2024-5197', 'CVE-2024-3852', 'CVE-2024-7530', 'CVE-2024-7519', 'CVE-2024-6601', 'CVE-2024-5691']
        self.assertEqual(set(expected_cves), set(list(result[query]['vulns'].keys())))

    def test_search_chrome_1170593862_ubuntu_general(self):
        self.maxDiff = None
        query = 'cpe:2.3:a:google:chrome:117.0.5938.62:*:*:*:*:*:*:ubuntu'
        result,_ = search_vulns(query, add_other_exploit_refs=False, is_good_cpe=True)
        expected_cves = ['CVE-2009-1598', 'CVE-2016-7153', 'CVE-2016-7152', 'CVE-2018-10229', 'CVE-2011-3389', 'CVE-2015-4000', 'CVE-2008-5915', 'CVE-2010-1731', 'CVE-2024-3171', 'CVE-2024-3168', 'CVE-2024-3175', 'CVE-2024-3174', 'CVE-2024-3173', 'CVE-2024-3169', 'CVE-2024-3172', 'CVE-2024-2884', 'CVE-2024-3170', 'CVE-2024-5500']
        self.assertEqual(set(expected_cves), set(list(result[query]['vulns'].keys())))

    def test_search_ubuntu_linux_2304(self):
        self.maxDiff = None
        query = 'cpe:2.3:o:canonical:ubuntu_linux:23.04:*:*:*:*:*:*:*'
        result,_ = search_vulns(query, add_other_exploit_refs=False, is_good_cpe=True)
        expected_cves = ['CVE-2024-6387', 'CVE-2023-5536', 'CVE-2023-3297', 'CVE-2023-32629', 'CVE-2023-2640', 'CVE-2023-1786', 'CVE-2023-1523']
        self.assertEqual(set(expected_cves), set(list(result[query]['vulns'].keys())))


if __name__ == '__main__':
    unittest.main()
#!/usr/bin/env python3

import os
import unittest
import sys

SEARCH_VULNS_PATH = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
sys.path.insert(1, SEARCH_VULNS_PATH)
from search_vulns_modules.search_vulns_functions import search_vulns

class TestSearches(unittest.TestCase):

    def test_search_libcurl_7501_debian_sid(self):
        self.maxDiff = None
        query = 'cpe:2.3:a:haxx:libcurl:7.50.1:*:*:*:*:*:*:debian_sid'
        result,_ = search_vulns(query, add_other_exploit_refs=True, is_good_cpe=True)
        expected_cves = ['CVE-2024-32928', 'CVE-2024-7264', 'CVE-2023-38546','CVE-2023-27538','CVE-2023-27536','CVE-2023-27535','CVE-2021-22924','CVE-2021-22876','CVE-2020-8286','CVE-2020-8285','CVE-2020-8231','CVE-2019-5436','CVE-2019-3823','CVE-2019-3822','CVE-2018-16890','CVE-2018-14618','CVE-2018-1000005','CVE-2017-8817','CVE-2017-8816','CVE-2017-1000257','CVE-2016-8622','CVE-2016-7167','CVE-2016-7141', 'CVE-2017-1000254', 'CVE-2017-1000100']
        self.assertEqual(set(expected_cves), set(list(result[query]['vulns'].keys())))

    def test_search_libssh2_general_debian_10(self):
        self.maxDiff = None
        query = 'cpe:2.3:a:libssh2:libssh2:-:*:*:*:*:*:*:debian_10'
        result,_ = search_vulns(query, add_other_exploit_refs=True, is_good_cpe=True)
        expected_cves = ['CVE-2020-1730', 'CVE-2020-22218', 'CVE-2019-3863', 'CVE-2019-3862', 'CVE-2019-3861', 'CVE-2019-3860', 'CVE-2019-3859', 'CVE-2019-3858', 'CVE-2019-3857', 'CVE-2019-3856', 'CVE-2019-3855', 'CVE-2019-17498', 'CVE-2019-13115', 'CVE-2016-0787', 'CVE-2015-1782']
        self.assertEqual(set(expected_cves), set(list(result[query]['vulns'].keys())))

    def test_search_glibc2383_debian_14(self):
        self.maxDiff = None
        query = 'cpe:2.3:a:gnu:glibc:2.38-3:*:*:*:*:*:*:debian_14'
        result,_ = search_vulns(query, add_other_exploit_refs=True, is_good_cpe=True)
        expected_cves = ['CVE-2019-9192', 'CVE-2019-1010025', 'CVE-2019-1010024', 'CVE-2019-1010023', 'CVE-2019-1010022', 'CVE-2018-20796', 'CVE-2016-20013', 'CVE-2010-4756']
        self.assertEqual(set(expected_cves), set(list(result[query]['vulns'].keys())))

    def test_search_gpac_24_debian_general(self):
        self.maxDiff = None
        query = 'cpe:2.3:a:gpac:gpac:2.4:*:*:*:*:*:*:debian'
        result,_ = search_vulns(query, add_other_exploit_refs=True, is_good_cpe=True)
        expected_cves = ['CVE-2024-28319', 'CVE-2024-28318', 'CVE-2023-46427', 'CVE-2023-46426', 'CVE-2024-24267', 'CVE-2024-24266', 'CVE-2024-24265', 'CVE-2024-22749', 'CVE-2024-24267', 'CVE-2024-24266', 'CVE-2024-24265', 'CVE-2023-5998','CVE-2023-5595','CVE-2023-5586','CVE-2023-5520','CVE-2023-5377','CVE-2023-48958','CVE-2023-48090','CVE-2023-48039','CVE-2023-48014','CVE-2023-48013','CVE-2023-48011','CVE-2023-4778','CVE-2023-4758','CVE-2023-4756','CVE-2023-4755','CVE-2023-4754','CVE-2023-47465','CVE-2023-47384','CVE-2023-4722','CVE-2023-4721','CVE-2023-4720','CVE-2023-46932','CVE-2023-46931','CVE-2023-46930','CVE-2023-46928','CVE-2023-46927','CVE-2023-46871','CVE-2023-4683','CVE-2023-4682','CVE-2023-4681','CVE-2023-4678','CVE-2023-46001','CVE-2023-42298','CVE-2023-41000','CVE-2023-37767','CVE-2023-37766','CVE-2023-37765','CVE-2023-37174','CVE-2023-3523','CVE-2023-3013','CVE-2023-0841','CVE-2023-0358','CVE-2022-47654','CVE-2022-47093','CVE-2022-46490','CVE-2022-46489','CVE-2022-43254','CVE-2022-43045','CVE-2022-43044','CVE-2022-43043','CVE-2022-43042','CVE-2022-30976','CVE-2022-29340','CVE-2022-29339','CVE-2022-2549','CVE-2022-24576','CVE-2022-24575','CVE-2022-2453','CVE-2022-1172','CVE-2021-45288','CVE-2021-44927','CVE-2021-44926','CVE-2021-44925','CVE-2021-44924','CVE-2021-44923','CVE-2021-44922','CVE-2021-44921','CVE-2021-44920','CVE-2021-44919','CVE-2021-44918','CVE-2021-40942','CVE-2021-40607','CVE-2021-40573','CVE-2021-36584','CVE-2021-33362','CVE-2021-32440','CVE-2021-32439','CVE-2021-32438','CVE-2021-32437','CVE-2021-32139','CVE-2021-32138','CVE-2021-32137','CVE-2021-32136','CVE-2021-32135','CVE-2021-32134','CVE-2021-32132', 'CVE-2024-0321', 'CVE-2024-0322', 'CVE-2021-46237', 'CVE-2021-46236', 'CVE-2021-46311', 'CVE-2021-45258', 'CVE-2021-45259', 'CVE-2021-46234', 'CVE-2023-39562', 'CVE-2021-46240', 'CVE-2021-46313', 'CVE-2021-46238', 'CVE-2021-45260', 'CVE-2021-45266', 'CVE-2021-46239', 'CVE-2024-6061', 'CVE-2024-6062', 'CVE-2024-6064', 'CVE-2024-6063', 'CVE-2023-3291', 'CVE-2023-2838', 'CVE-2023-2840', 'CVE-2023-2837', 'CVE-2023-3012', 'CVE-2023-2839']
        self.assertEqual(set(expected_cves), set(list(result[query]['vulns'].keys())))


if __name__ == '__main__':
    unittest.main()
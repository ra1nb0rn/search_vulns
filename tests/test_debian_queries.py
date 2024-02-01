#!/usr/bin/env python3

import os
import unittest
import sys

SEARCH_VULNS_PATH = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
sys.path.insert(1, SEARCH_VULNS_PATH)
import search_vulns

class TestSearches(unittest.TestCase):

    def test_search_libcurl_7501_debian_sid(self):
        self.maxDiff = None
        query = 'Debian sid LibCurl 7.50.1'
        result,_ = search_vulns.search_vulns(query, add_other_exploit_refs=True, is_good_cpe=True)
        expected_cves = ['CVE-2023-38546','CVE-2023-27538','CVE-2023-27536','CVE-2023-27535','CVE-2021-22924','CVE-2021-22876','CVE-2020-8286','CVE-2020-8285','CVE-2020-8231','CVE-2019-5436','CVE-2019-3823','CVE-2019-3822','CVE-2018-16890','CVE-2018-14618','CVE-2018-1000005','CVE-2017-8817','CVE-2017-8816','CVE-2017-1000257','CVE-2016-8622','CVE-2016-7167','CVE-2016-7141','CVE-2016-5421','CVE-2016-5420','CVE-2016-5419', 'CVE-2017-1000254', 'CVE-2017-1000100']
        self.assertEqual(set(expected_cves), set(list(result[query]['vulns'].keys())))

    def test_search_libssh_general_debian_10(self):
        self.maxDiff = None
        query = 'Libssh Debian 10'
        result,_ = search_vulns.search_vulns(query, add_other_exploit_refs=True, is_good_cpe=True)
        expected_cves = ['CVE-2023-6918','CVE-2020-1730','CVE-2020-16135','CVE-2019-14889','CVE-2018-10933','CVE-2016-0739','CVE-2015-3146','CVE-2014-8132','CVE-2014-0017','CVE-2013-0176','CVE-2012-6063','CVE-2012-4562','CVE-2012-4561','CVE-2012-4560','CVE-2012-4559', 'CVE-2023-48795', 'CVE-2023-6004']
        self.assertEqual(set(expected_cves), set(list(result[query]['vulns'].keys())))
    
    def test_search_glibc2383_debian_14(self):
        self.maxDiff = None
        query = 'cpe:2.3:a:gnu:glibc:2.38-3:*:*:*:*:*:*:debian_14'
        result,_ = search_vulns.search_vulns(query, add_other_exploit_refs=True, is_good_cpe=True)
        expected_cves = ['CVE-2019-9192','CVE-2019-1010025','CVE-2019-1010024','CVE-2019-1010023','CVE-2019-1010022','CVE-2018-20796','CVE-2010-4756']
        self.assertEqual(set(expected_cves), set(list(result[query]['vulns'].keys())))

    def test_search_gpac_24_debian_general(self):
        self.maxDiff = None
        query = 'cpe:2.3:a:gpac:gpac:2.4:*:*:*:*:*:*:debian'
        result,_ = search_vulns.search_vulns(query, add_other_exploit_refs=True, is_good_cpe=True)
        expected_cves = ['CVE-2023-5998','CVE-2023-5595','CVE-2023-5586','CVE-2023-5520','CVE-2023-5377','CVE-2023-48958','CVE-2023-48090','CVE-2023-48039','CVE-2023-48014','CVE-2023-48013','CVE-2023-48011','CVE-2023-4778','CVE-2023-4758','CVE-2023-4756','CVE-2023-4755','CVE-2023-4754','CVE-2023-47465','CVE-2023-47384','CVE-2023-4722','CVE-2023-4721','CVE-2023-4720','CVE-2023-46932','CVE-2023-46931','CVE-2023-46930','CVE-2023-46928','CVE-2023-46927','CVE-2023-46871','CVE-2023-4683','CVE-2023-4682','CVE-2023-4681','CVE-2023-4678','CVE-2023-46001','CVE-2023-42298','CVE-2023-41000','CVE-2023-37767','CVE-2023-37766','CVE-2023-37765','CVE-2023-37174','CVE-2023-3523','CVE-2023-3013','CVE-2023-0841','CVE-2023-0358','CVE-2022-47654','CVE-2022-47093','CVE-2022-46490','CVE-2022-46489','CVE-2022-43254','CVE-2022-43045','CVE-2022-43044','CVE-2022-43043','CVE-2022-43042','CVE-2022-30976','CVE-2022-29340','CVE-2022-29339','CVE-2022-2549','CVE-2022-24576','CVE-2022-24575','CVE-2022-2453','CVE-2022-1172','CVE-2021-45288','CVE-2021-44927','CVE-2021-44926','CVE-2021-44925','CVE-2021-44924','CVE-2021-44923','CVE-2021-44922','CVE-2021-44921','CVE-2021-44920','CVE-2021-44919','CVE-2021-44918','CVE-2021-40942','CVE-2021-40607','CVE-2021-40573','CVE-2021-36584','CVE-2021-33362','CVE-2021-32440','CVE-2021-32439','CVE-2021-32438','CVE-2021-32437','CVE-2021-32139','CVE-2021-32138','CVE-2021-32137','CVE-2021-32136','CVE-2021-32135','CVE-2021-32134','CVE-2021-32132', 'CVE-2024-0321', 'CVE-2024-0322']
        self.assertEqual(set(expected_cves), set(list(result[query]['vulns'].keys())))

    # this test aims to check whether with_cpes are handled correctly
    def test_search_thunderbird_1154_debian_general(self):
        self.maxDiff = None
        result,_ = search_vulns.search_vulns(query='cpe:2.3:a:mozilla:thunderbird:115.4:*:*:*:*:*:*:debian', add_other_exploit_refs=True, is_good_cpe=True)
        expected_cves = ['CVE-2024-0755','CVE-2024-0754','CVE-2024-0753','CVE-2024-0751','CVE-2024-0750','CVE-2024-0749','CVE-2024-0748','CVE-2024-0747','CVE-2024-0746','CVE-2024-0745','CVE-2024-0744','CVE-2024-0743','CVE-2024-0742','CVE-2024-0741','CVE-2023-6873','CVE-2023-6872','CVE-2023-6871','CVE-2023-6870','CVE-2023-6869','CVE-2023-6868','CVE-2023-6867','CVE-2023-6866','CVE-2023-6865','CVE-2023-6864','CVE-2023-6863','CVE-2023-6862','CVE-2023-6861','CVE-2023-6860','CVE-2023-6859','CVE-2023-6858','CVE-2023-6857','CVE-2023-6856','CVE-2023-6213','CVE-2023-6212','CVE-2023-6211','CVE-2023-6210','CVE-2023-6209','CVE-2023-6208','CVE-2023-6207','CVE-2023-6206','CVE-2023-6205','CVE-2023-6204','CVE-2023-6135','CVE-2023-5732','CVE-2023-5731','CVE-2023-5730','CVE-2023-5729','CVE-2023-5728','CVE-2023-5725','CVE-2023-5724','CVE-2023-5723','CVE-2023-5722','CVE-2023-5721','CVE-2023-5175','CVE-2023-5173','CVE-2023-5172','CVE-2023-5170','CVE-2023-50762','CVE-2023-50761','CVE-2023-4579','CVE-2023-44488','CVE-2023-31670','CVE-2022-46884','CVE-2022-43680','CVE-2022-39394','CVE-2022-39393','CVE-2022-39392','CVE-2022-3857','CVE-2022-37609','CVE-2022-31169','CVE-2022-31146','CVE-2022-25315','CVE-2022-25314','CVE-2022-25313','CVE-2022-25236','CVE-2022-25235','CVE-2022-24791','CVE-2022-23990','CVE-2022-23852','CVE-2022-23639','CVE-2022-0235','CVE-2020-0470','CVE-2019-20446','CVE-2017-17689','CVE-2017-17688','CVE-2017-0381','CVE-2016-5827','CVE-2016-5826','CVE-2016-5825','CVE-2016-5823','CVE-2016-4472','CVE-2015-7210','CVE-2015-6525','CVE-2014-6272','CVE-2011-3656','CVE-2011-2998','CVE-2011-0051','CVE-2009-4630','CVE-2009-3984','CVE-2009-3983','CVE-2009-3982','CVE-2009-3981','CVE-2009-3980','CVE-2009-1840','CVE-2009-1309','CVE-2009-1308','CVE-2009-1307','CVE-2009-1306']
        self.assertEqual(set(expected_cves), set(list(result.keys())))


if __name__ == '__main__':
    unittest.main()
#!/usr/bin/env python3

import os
import unittest
import sys

SEARCH_VULNS_PATH = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
sys.path.insert(1, SEARCH_VULNS_PATH)
import search_vulns

class TestSearches(unittest.TestCase):

    def test_search_wp_572(self):
        self.maxDiff = None
        query = 'cpe:2.3:a:wordpress:wordpress:5.7.2:*:*:*:*:*:*:*'
        result = search_vulns.search_vulns(query=query, add_other_exploit_refs=True, is_good_cpe=True)
        expected_cves = ['CVE-2021-44223', 'CVE-2022-21663', 'CVE-2022-21664', 'CVE-2012-6527', 'CVE-2022-43497', 'CVE-2007-2627', 'CVE-2012-4271', 'CVE-2022-3590', 'CVE-2011-5216', 'CVE-2023-22622', 'CVE-2013-7240', 'CVE-2022-21661', 'CVE-2021-39201', 'CVE-2022-21662', 'CVE-2023-2745', 'CVE-2021-39200', 'CVE-2022-43504', 'CVE-2022-43500', 'CVE-2023-5561', 'CVE-2023-39999', 'CVE-2024-31210', 'CVE-2024-32111', 'CVE-2023-5692', 'CVE-2024-31211', 'CVE-2022-4973']
        result_cves = [vuln_id for vuln_id in result[query]['vulns'].keys() if vuln_id.startswith('CVE-')]
        self.assertEqual(set(expected_cves), set(result_cves))

    def test_search_apache_2425(self):
        self.maxDiff = None
        query = 'cpe:2.3:a:apache:http_server:2.4.25:*:*:*:*:*:*:*'
        result = search_vulns.search_vulns(query=query, add_other_exploit_refs=True, is_good_cpe=True)
        expected_cves = ['CVE-2017-15710', 'CVE-2017-3169', 'CVE-2017-7659', 'CVE-2017-7668', 'CVE-2017-9798', 'CVE-2018-1312', 'CVE-2018-17189', 'CVE-2020-9490', 'CVE-2021-26691', 'CVE-2017-3167', 'CVE-2022-28615', 'CVE-2023-25690', 'CVE-1999-0289', 'CVE-2021-33193', 'CVE-2019-9517', 'CVE-2022-30556', 'CVE-2019-0217', 'CVE-2018-1303', 'CVE-2018-11763', 'CVE-2022-37436', 'CVE-2022-22719', 'CVE-2006-20001', 'CVE-2021-26690', 'CVE-2022-36760', 'CVE-2022-26377', 'CVE-2017-9788', 'CVE-2020-13938', 'CVE-2019-17567', 'CVE-2022-31813', 'CVE-2021-40438', 'CVE-2019-0211', 'CVE-2021-34798', 'CVE-2019-10092', 'CVE-1999-1237', 'CVE-2019-0220', 'CVE-2018-1301', 'CVE-2020-11993', 'CVE-1999-1412', 'CVE-2020-1927', 'CVE-2017-7679', 'CVE-2021-39275', 'CVE-2022-28330', 'CVE-2019-10098', 'CVE-2022-28614', 'CVE-2019-10081', 'CVE-2020-1934', 'CVE-2007-0450', 'CVE-2018-17199', 'CVE-2021-44790', 'CVE-1999-0678', 'CVE-2022-29404', 'CVE-2021-44224', 'CVE-2019-0196', 'CVE-2022-22720', 'CVE-2017-15715', 'CVE-2022-23943', 'CVE-2020-35452', 'CVE-2018-1283', 'CVE-2019-10082', 'CVE-2022-22721', 'CVE-2018-1302', 'CVE-2007-0086', 'CVE-2018-1333', 'CVE-2023-31122', 'CVE-2023-45802', 'CVE-2024-27316', 'CVE-2024-40898', 'CVE-2024-38477', 'CVE-2024-38474', 'CVE-2024-38476', 'CVE-2024-24795', 'CVE-2024-38473', 'CVE-2024-38475', 'CVE-2024-39573', 'CVE-2024-38472', 'CVE-2023-38709']
        result_cves = [vuln_id for vuln_id in result[query]['vulns'].keys() if vuln_id.startswith('CVE-')]
        self.assertEqual(set(expected_cves), set(result_cves))

    def test_search_proftpd_133c(self):
        self.maxDiff = None
        query = 'cpe:2.3:a:proftpd:proftpd:1.3.3:c:*:*:*:*:*:*'
        result = search_vulns.search_vulns(query=query, add_other_exploit_refs=True, is_good_cpe=True)
        expected_cves = ['CVE-2011-1137', 'CVE-2011-4130', 'CVE-2012-6095', 'CVE-2019-19271', 'CVE-2019-19272', 'CVE-2019-19269', 'CVE-2019-12815', 'CVE-2021-46854', 'CVE-2019-19270', 'CVE-2020-9272', 'CVE-2019-18217', 'CVE-2010-4652', 'CVE-2023-51713', 'CVE-2023-48795', 'CVE-2024-48651']
        result_cves = [vuln_id for vuln_id in result[query]['vulns'].keys() if vuln_id.startswith('CVE-')]
        self.assertEqual(set(expected_cves), set(result_cves))

    def test_search_thingsboard_340(self):
        self.maxDiff = None
        query = 'cpe:2.3:a:thingsboard:thingsboard:3.4.0:*:*:*:*:*:*:*'
        result = search_vulns.search_vulns(query=query, add_other_exploit_refs=True, is_good_cpe=True, include_single_version_vulns=True)
        expected_cves = ['CVE-2022-40004', 'CVE-2022-45608', 'CVE-2022-48341', 'CVE-2023-26462', 'CVE-2023-45303', 'CVE-2024-9358', 'CVE-2024-3270']
        result_cves = [vuln_id for vuln_id in result[query]['vulns'].keys() if vuln_id.startswith('CVE-')]
        self.assertEqual(set(expected_cves), set(result_cves))

    def test_search_redis_323(self):
        self.maxDiff = None
        query = 'cpe:2.3:a:redis:redis:3.2.3:*:*:*:*:*:*:*'
        result = search_vulns.search_vulns(query=query, add_other_exploit_refs=True, is_good_cpe=True)
        expected_cves = ['CVE-2021-32626', 'CVE-2022-3647', 'CVE-2022-24735', 'CVE-2023-28856', 'CVE-2022-0543', 'CVE-2021-32672', 'CVE-2022-24736', 'CVE-2022-3734', 'CVE-2022-24834', 'CVE-2022-36021', 'CVE-2023-25155', 'CVE-2021-31294', 'CVE-2023-45145', 'CVE-2024-31449', 'CVE-2024-31228', 'CVE-2024-46981', 'CVE-2025-21605']
        result_cves = [vuln_id for vuln_id in result[query]['vulns'].keys() if vuln_id.startswith('CVE-')]
        self.assertEqual(set(expected_cves), set(result_cves))

    def test_search_piwik_045(self):
        self.maxDiff = None
        query = 'cpe:2.3:a:piwik:piwik:0.4.5:*:*:*:*:*:*:*'
        result = search_vulns.search_vulns(query=query, add_other_exploit_refs=True)
        expected_cves = ['CVE-2015-7815','CVE-2015-7816','CVE-2011-0398','CVE-2013-0193','CVE-2013-0194','CVE-2013-0195','CVE-2011-0400','CVE-2011-0401','CVE-2013-2633','CVE-2010-1453','CVE-2011-0004','CVE-2011-0399','CVE-2012-4541','CVE-2013-1844', 'CVE-2023-6923']
        result_cves = [vuln_id for vuln_id in result[query]['vulns'].keys() if vuln_id.startswith('CVE-')]
        self.assertEqual(set(expected_cves), set(result_cves))

    def test_search_vmware_spring_framework_5326(self):
        self.maxDiff = None
        query = 'cpe:2.3:a:vmware:spring_framework:5.3.26:*:*:*:*:*:*:*'
        result = search_vulns.search_vulns(query=query, add_other_exploit_refs=True, is_good_cpe=True)
        expected_cves = ['CVE-2016-1000027', 'CVE-2023-20863', 'CVE-2024-22243', 'CVE-2024-22259', 'CVE-2024-22262', 'CVE-2024-38809', 'CVE-2024-38820', 'CVE-2024-38828', 'CVE-2024-38819']
        result_cves = [vuln_id for vuln_id in result[query]['vulns'].keys() if vuln_id.startswith('CVE-')]
        self.assertEqual(set(expected_cves), set(result_cves))

    def test_search_zulip_48(self):
        self.maxDiff = None
        query = 'cpe:2.3:a:zulip:zulip:4.8:*:*:*:*:*:*:*'
        result = search_vulns.search_vulns(query=query, add_other_exploit_refs=True, is_good_cpe=True)
        expected_cves = ['CVE-2022-35962', 'CVE-2022-36048', 'CVE-2023-28623', 'CVE-2021-43799', 'CVE-2023-32677', 'CVE-2022-31017', 'CVE-2022-24751', 'CVE-2021-3967', 'CVE-2021-3866', 'CVE-2022-31168']
        result_cves = [vuln_id for vuln_id in result[query]['vulns'].keys() if vuln_id.startswith('CVE-')]
        self.assertEqual(set(expected_cves), set(result_cves))

    def test_search_zulip_server_general(self):
        self.maxDiff = None
        query = 'cpe:2.3:a:zulip:zulip_server:*:*:*:*:*:*:*:*'
        result = search_vulns.search_vulns(query=query, add_other_exploit_refs=True, is_good_cpe=True)
        expected_cves = ['CVE-2022-41914', 'CVE-2023-33186', 'CVE-2020-12759', 'CVE-2021-30479', 'CVE-2020-9444', 'CVE-2019-16216', 'CVE-2021-30487', 'CVE-2019-19775', 'CVE-2020-14194', 'CVE-2017-0896', 'CVE-2020-14215', 'CVE-2018-9990', 'CVE-2023-22735', 'CVE-2020-10935', 'CVE-2022-31134', 'CVE-2019-18933', 'CVE-2018-9987', 'CVE-2018-9986', 'CVE-2020-9445', 'CVE-2017-0910', 'CVE-2017-0881', 'CVE-2019-16215', 'CVE-2022-23656', 'CVE-2022-21706', 'CVE-2021-30478', 'CVE-2023-32678', 'CVE-2020-15070', 'CVE-2018-9999', 'CVE-2021-30477', 'CVE-2023-47642', 'CVE-2024-21630', 'CVE-2024-27286', 'CVE-2024-36612', 'CVE-2024-56136', 'CVE-2025-30368', 'CVE-2025-25195', 'CVE-2025-27149', 'CVE-2025-30369', 'CVE-2025-31478']
        result_cves = [vuln_id for vuln_id in result[query]['vulns'].keys() if vuln_id.startswith('CVE-')]
        self.assertEqual(set(expected_cves), set(result_cves))

    def test_search_electron_1317(self):
        self.maxDiff = None
        query = 'cpe:2.3:a:electronjs:electron:13.1.7:*:*:*:*:*:*:*'
        result = search_vulns.search_vulns(query=query, add_other_exploit_refs=True, is_good_cpe=True)
        expected_cves = ['CVE-2023-39956', 'CVE-2022-29247', 'CVE-2023-29198', 'CVE-2021-39184', 'CVE-2022-21718', 'CVE-2022-29257', 'CVE-2022-36077', 'CVE-2023-44402']
        result_cves = [vuln_id for vuln_id in result[query]['vulns'].keys() if vuln_id.startswith('CVE-')]
        self.assertEqual(set(expected_cves), set(result_cves))

    def test_search_hitachi_replication_manager_86500(self):
        self.maxDiff = None
        query = 'cpe:2.3:a:hitachi:replication_manager:8.6.5-00:*:*:*:*:*:*:*'
        result = search_vulns.search_vulns(query=query, add_other_exploit_refs=True, is_good_cpe=True)
        expected_cves = ['CVE-2022-4146', 'CVE-2020-36695', 'CVE-2019-17360']
        result_cves = [vuln_id for vuln_id in result[query]['vulns'].keys() if vuln_id.startswith('CVE-')]
        self.assertEqual(set(expected_cves), set(result_cves))

    def test_search_handlebars_js_300(self):
        self.maxDiff = None
        query = 'cpe:2.3:a:handlebarsjs:handlebars:3.0.0:*:*:*:*:node.js:*:*'
        result = search_vulns.search_vulns(query=query, add_other_exploit_refs=True, is_good_cpe=False)
        expected_cves = ['CVE-2019-19919', 'CVE-2021-23369', 'CVE-2021-23383', 'CVE-2019-20920', 'CVE-2015-8861']
        result_cves = [vuln_id for vuln_id in result[query]['vulns'].keys() if vuln_id.startswith('CVE-')]
        self.assertEqual(set(expected_cves), set(result_cves))

    def test_search_proftpd_135f(self):
        self.maxDiff = None
        query = 'cpe:2.3:a:proftpd:proftpd:1.3.5f:-:*:*:*:*:*:*'
        result = search_vulns.search_vulns(query=query, add_other_exploit_refs=True, is_good_cpe=False)
        expected_cves = ['CVE-2001-0027', 'CVE-2015-3306', 'CVE-2019-18217', 'CVE-2019-19270', 'CVE-2019-19271', 'CVE-2019-19272', 'CVE-2020-9272', 'CVE-2021-46854', 'CVE-2023-51713', 'CVE-2023-48795', 'CVE-2024-48651']
        result_cves = [vuln_id for vuln_id in result[query]['vulns'].keys() if vuln_id.startswith('CVE-')]
        self.assertEqual(set(expected_cves), set(result_cves))

    def test_search_xorg_xorg_server_1100901(self):
        self.maxDiff = None
        query = 'x.org xorg server 1.10.0.901'
        result = search_vulns.search_vulns(query=query, add_other_exploit_refs=True, is_good_cpe=False)
        expected_cves = ['CVE-2024-0409', 'CVE-2024-0408', 'CVE-2023-6816', 'CVE-2023-1393', 'CVE-2020-14362', 'CVE-2020-14361', 'CVE-2020-14347', 'CVE-2020-14346', 'CVE-2018-14665', 'CVE-2017-2624', 'CVE-2017-13723', 'CVE-2017-13721', 'CVE-2017-12187', 'CVE-2017-12186', 'CVE-2017-12185', 'CVE-2017-12184', 'CVE-2017-12183', 'CVE-2017-12182', 'CVE-2017-12181', 'CVE-2017-12180', 'CVE-2017-12179', 'CVE-2017-12178', 'CVE-2017-12177', 'CVE-2017-12176', 'CVE-2017-10972', 'CVE-2017-10971', 'CVE-2015-3418', 'CVE-2015-0255', 'CVE-2014-8102', 'CVE-2014-8101', 'CVE-2014-8100', 'CVE-2014-8099', 'CVE-2014-8098', 'CVE-2014-8097', 'CVE-2014-8096', 'CVE-2014-8095', 'CVE-2014-8094', 'CVE-2014-8093', 'CVE-2014-8092', 'CVE-2014-8091', 'CVE-2013-1940', 'CVE-2012-0064', 'CVE-2011-0465', 'CVE-2006-6103', 'CVE-2006-6101', 'CVE-2006-0197', 'CVE-2002-1510', 'CVE-1999-0241', 'CVE-1999-0126', 'CVE-1999-0965']
        result_cves = [vuln_id for vuln_id in result[query]['vulns'].keys() if vuln_id.startswith('CVE-')]
        self.assertEqual(set(expected_cves), set(result_cves))

    def test_search_trendmicro_dsa_20_0_u1558(self):
        self.maxDiff = None
        query = 'cpe:2.3:a:trendmicro:deep_security_agent:20.0:u1559:*:*:*:*:*:*'
        result = search_vulns.search_vulns(query=query, add_other_exploit_refs=True, is_good_cpe=True)
        expected_cves = ['CVE-2023-52337', 'CVE-2022-23120', 'CVE-2022-23119', 'CVE-2023-52338', 'CVE-2022-40707', 'CVE-2022-40709', 'CVE-2022-40710', 'CVE-2022-40708']
        result_cves = [vuln_id for vuln_id in result[query]['vulns'].keys() if vuln_id.startswith('CVE-')]
        self.assertEqual(set(expected_cves), set(result_cves))

    def test_search_vmware_esxi_802(self):
        self.maxDiff = None
        query = 'cpe:2.3:o:vmware:esxi:8.0:update_2:*:*:*:*:*:*'
        result = search_vulns.search_vulns(query=query, add_other_exploit_refs=True, is_good_cpe=True)
        expected_cves = ['CVE-2024-22253', 'CVE-2024-22273', 'CVE-2024-22254', 'CVE-2024-22252', 'CVE-2024-22255', 'CVE-2022-31705', 'CVE-2024-37085', 'CVE-2025-22225', 'CVE-2025-22224', 'CVE-2025-22226']
        result_cves = [vuln_id for vuln_id in result[query]['vulns'].keys() if vuln_id.startswith('CVE-')]
        self.assertEqual(set(expected_cves), set(result_cves))

    def test_search_openstack_glance(self):
        self.maxDiff = None
        query = 'cpe:2.3:a:openstack:glance:*:*:*:*:*:*:*:*'
        result = search_vulns.search_vulns(query=query, add_other_exploit_refs=True, is_good_cpe=False)
        expected_cves = ['CVE-2022-47951', 'CVE-2013-1840', 'CVE-2015-8234', 'CVE-2015-3289', 'CVE-2015-5163', 'CVE-2015-5162', 'CVE-2013-4428', 'CVE-2016-8611', 'CVE-2017-7200', 'CVE-2022-4134', 'CVE-2015-5251', 'CVE-2014-0162', 'CVE-2014-5356', 'CVE-2016-0757', 'CVE-2015-5286', 'CVE-2014-9623', 'CVE-2015-1195', 'CVE-2014-1948', 'CVE-2012-5482', 'CVE-2013-0212', 'CVE-2013-4354', 'CVE-2015-1881', 'CVE-2014-9493', 'CVE-2014-9684', 'CVE-2012-4573', 'CVE-2024-32498']
        result_cves = [vuln_id for vuln_id in result[query]['vulns'].keys() if vuln_id.startswith('CVE-')]
        self.assertEqual(set(expected_cves), set(result_cves))

    def test_search_simplednsplus(self):
        self.maxDiff = None
        query = 'simpledns simple dns plus'
        result = search_vulns.search_vulns(query=query, add_other_exploit_refs=True)
        expected_cves = ['CVE-2008-3208']
        result_cves = [vuln_id for vuln_id in result[query]['vulns'].keys() if vuln_id.startswith('CVE-')]
        self.assertEqual(set(expected_cves), set(result_cves))

    def test_search_portainer_2_19_0(self):
        self.maxDiff = None
        query = 'cpe:2.3:a:portainer:portainer:2.19.0:*:*:*:*:*:*:*'
        result = search_vulns.search_vulns(query=query, add_other_exploit_refs=True, is_good_cpe=True)
        expected_cves = ['CVE-2021-41874', 'CVE-2024-33661', 'CVE-2024-33662']
        result_cves = [vuln_id for vuln_id in result[query]['vulns'].keys() if vuln_id.startswith('CVE-')]
        self.assertEqual(set(expected_cves), set(result_cves))

if __name__ == '__main__':
    unittest.main()

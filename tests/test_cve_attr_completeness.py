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
        result = search_vulns.search_vulns(query='cpe:2.3:a:wordpress:wordpress:5.7.2:*:*:*:*:*:*:*', add_other_exploit_refs=True, is_good_cpe=True)
        expected_attrs = {'CVE-2021-44223': {'published': '2021-11-25 15:15:09', 'cvss_ver': '3.1', 'cvss': '9.8', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'}, 'CVE-2013-7240': {'published': '2014-01-03 18:54:09', 'cvss_ver': '2.0', 'cvss': '5.0', 'cvss_vec': 'AV:N/AC:L/Au:N/C:P/I:N/A:N'}, 'CVE-2022-43500': {'published': '2022-12-05 04:15:10', 'cvss_ver': '3.1', 'cvss': '6.1', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N'}, 'CVE-2023-2745': {'published': '2023-05-17 09:15:10', 'cvss_ver': '3.1', 'cvss': '5.4', 'cvss_vec': 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:L/I:L/A:N'}, 'CVE-2011-5216': {'published': '2012-10-25 17:55:03', 'cvss_ver': '2.0', 'cvss': '7.5', 'cvss_vec': 'AV:N/AC:L/Au:N/C:P/I:P/A:P'}, 'CVE-2021-39200': {'published': '2021-09-09 22:15:09', 'cvss_ver': '3.1', 'cvss': '5.3', 'cvss_vec': 'CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N'}, 'CVE-2022-21663': {'published': '2022-01-06 23:15:08', 'cvss_ver': '3.1', 'cvss': '7.2', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H'}, 'CVE-2022-21661': {'published': '2022-01-06 23:15:07', 'cvss_ver': '3.1', 'cvss': '7.5', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N'}, 'CVE-2021-39201': {'published': '2021-09-09 22:15:09', 'cvss_ver': '3.1', 'cvss': '5.4', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N'}, 'CVE-2022-21662': {'published': '2022-01-06 23:15:08', 'cvss_ver': '3.1', 'cvss': '5.4', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N'}, 'CVE-2022-3590': {'published': '2022-12-14 09:15:09', 'cvss_ver': '3.1', 'cvss': '5.9', 'cvss_vec': 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N'}, 'CVE-2012-6527': {'published': '2013-01-31 05:44:00', 'cvss_ver': '2.0', 'cvss': '2.6', 'cvss_vec': 'AV:N/AC:H/Au:N/C:N/I:P/A:N'}, 'CVE-2022-43497': {'published': '2022-12-05 04:15:10', 'cvss_ver': '3.1', 'cvss': '6.1', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N'}, 'CVE-2022-21664': {'published': '2022-01-06 23:15:08', 'cvss_ver': '3.1', 'cvss': '8.8', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H'}, 'CVE-2012-4271': {'published': '2012-08-13 22:55:01', 'cvss_ver': '2.0', 'cvss': '4.3', 'cvss_vec': 'AV:N/AC:M/Au:N/C:N/I:P/A:N'}, 'CVE-2022-43504': {'published': '2022-12-05 04:15:10', 'cvss_ver': '3.1', 'cvss': '5.3', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N'}, 'CVE-2007-2627': {'published': '2007-05-11 17:19:00', 'cvss_ver': '2.0', 'cvss': '6.8', 'cvss_vec': 'AV:N/AC:M/Au:N/C:P/I:P/A:P'}, 'CVE-2023-22622': {'published': '2023-01-05 02:15:07', 'cvss_ver': '3.1', 'cvss': '5.3', 'cvss_vec': 'CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H'}, 'CVE-2023-5561': {'published': '2023-10-16 20:15:18', 'cvss_ver': '3.1', 'cvss': '5.3', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N'}, 'CVE-2023-39999': {'published': '2023-10-13 12:15:09', 'cvss_ver': '3.1', 'cvss': '4.3', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N'}}

        for cve, cve_attrs in result.items():
            self.assertIn(cve, expected_attrs)
            self.assertEqual(cve_attrs['published'], expected_attrs[cve]['published'])
            self.assertEqual(cve_attrs['cvss_ver'], expected_attrs[cve]['cvss_ver'])
            self.assertEqual(cve_attrs['cvss'], expected_attrs[cve]['cvss'])
            self.assertEqual(cve_attrs['cvss_vec'], expected_attrs[cve]['cvss_vec'])

    def test_search_apache_2425(self):
        self.maxDiff = None
        result = search_vulns.search_vulns(query='cpe:2.3:a:apache:http_server:2.4.25:*:*:*:*:*:*:*', add_other_exploit_refs=True, is_good_cpe=True)
        expected_attrs = {'CVE-2017-15710': {'published': '2018-03-26 15:29:00', 'cvss_ver': '3.0', 'cvss': '7.5', 'cvss_vec': 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H'}, 'CVE-2017-3169': {'published': '2017-06-20 01:29:00', 'cvss_ver': '3.0', 'cvss': '9.8', 'cvss_vec': 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'}, 'CVE-2017-7659': {'published': '2017-07-26 21:29:00', 'cvss_ver': '3.0', 'cvss': '7.5', 'cvss_vec': 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H'}, 'CVE-2017-7668': {'published': '2017-06-20 01:29:00', 'cvss_ver': '3.1', 'cvss': '7.5', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H'}, 'CVE-2017-9798': {'published': '2017-09-18 15:29:00', 'cvss_ver': '3.1', 'cvss': '7.5', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N'}, 'CVE-2018-1312': {'published': '2018-03-26 15:29:00', 'cvss_ver': '3.1', 'cvss': '9.8', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'}, 'CVE-2018-17189': {'published': '2019-01-30 22:29:00', 'cvss_ver': '3.1', 'cvss': '5.3', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L'}, 'CVE-2023-25690': {'published': '2023-03-07 16:15:09', 'cvss_ver': '3.1', 'cvss': '9.8', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'}, 'CVE-2019-10082': {'published': '2019-09-26 16:15:10', 'cvss_ver': '3.1', 'cvss': '9.1', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H'}, 'CVE-2022-30556': {'published': '2022-06-09 17:15:09', 'cvss_ver': '3.1', 'cvss': '7.5', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N'}, 'CVE-2022-22719': {'published': '2022-03-14 11:15:09', 'cvss_ver': '3.1', 'cvss': '7.5', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H'}, 'CVE-2019-10098': {'published': '2019-09-25 17:15:10', 'cvss_ver': '3.1', 'cvss': '6.1', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N'}, 'CVE-2018-1283': {'published': '2018-03-26 15:29:00', 'cvss_ver': '3.0', 'cvss': '5.3', 'cvss_vec': 'CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:N'}, 'CVE-2022-28615': {'published': '2022-06-09 17:15:09', 'cvss_ver': '3.1', 'cvss': '9.1', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H'}, 'CVE-2019-10092': {'published': '2019-09-26 16:15:10', 'cvss_ver': '3.1', 'cvss': '6.1', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N'}, 'CVE-2021-39275': {'published': '2021-09-16 15:15:07', 'cvss_ver': '3.1', 'cvss': '9.8', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'}, 'CVE-2019-9517': {'published': '2019-08-13 21:15:12', 'cvss_ver': '3.1', 'cvss': '7.5', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H'}, 'CVE-1999-1237': {'published': '1999-06-06 04:00:00', 'cvss_ver': '2.0', 'cvss': '10.0', 'cvss_vec': 'AV:N/AC:L/Au:N/C:C/I:C/A:C'}, 'CVE-2019-10081': {'published': '2019-08-15 22:15:12', 'cvss_ver': '3.0', 'cvss': '7.5', 'cvss_vec': 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H'}, 'CVE-2007-0450': {'published': '2007-03-16 22:19:00', 'cvss_ver': '2.0', 'cvss': '5.0', 'cvss_vec': 'AV:N/AC:L/Au:N/C:P/I:N/A:N'}, 'CVE-2021-34798': {'published': '2021-09-16 15:15:07', 'cvss_ver': '3.1', 'cvss': '7.5', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H'}, 'CVE-1999-0678': {'published': '1999-01-17 05:00:00', 'cvss_ver': '2.0', 'cvss': '5.0', 'cvss_vec': 'AV:N/AC:L/Au:N/C:P/I:N/A:N'}, 'CVE-2019-17567': {'published': '2021-06-10 07:15:07', 'cvss_ver': '3.1', 'cvss': '5.3', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N'}, 'CVE-2006-20001': {'published': '2023-01-17 20:15:11', 'cvss_ver': '3.1', 'cvss': '7.5', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H'}, 'CVE-2021-44224': {'published': '2021-12-20 12:15:07', 'cvss_ver': '3.1', 'cvss': '8.2', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:H'}, 'CVE-1999-0289': {'published': '1999-12-12 05:00:00', 'cvss_ver': '2.0', 'cvss': '5.0', 'cvss_vec': 'AV:N/AC:L/Au:N/C:P/I:N/A:N'}, 'CVE-2021-26690': {'published': '2021-06-10 07:15:07', 'cvss_ver': '3.1', 'cvss': '7.5', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H'}, 'CVE-2017-3167': {'published': '2017-06-20 01:29:00', 'cvss_ver': '3.1', 'cvss': '9.8', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'}, 'CVE-2019-0196': {'published': '2019-06-11 22:29:03', 'cvss_ver': '3.0', 'cvss': '5.3', 'cvss_vec': 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L'}, 'CVE-2020-11993': {'published': '2020-08-07 16:15:11', 'cvss_ver': '3.1', 'cvss': '7.5', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H'}, 'CVE-2019-0220': {'published': '2019-06-11 21:29:00', 'cvss_ver': '3.0', 'cvss': '5.3', 'cvss_vec': 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N'}, 'CVE-2022-37436': {'published': '2023-01-17 20:15:11', 'cvss_ver': '3.1', 'cvss': '5.3', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N'}, 'CVE-2018-1301': {'published': '2018-03-26 15:29:00', 'cvss_ver': '3.0', 'cvss': '5.9', 'cvss_vec': 'CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H'}, 'CVE-2017-9788': {'published': '2017-07-13 16:29:00', 'cvss_ver': '3.0', 'cvss': '9.1', 'cvss_vec': 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H'}, 'CVE-1999-1412': {'published': '1999-06-03 04:00:00', 'cvss_ver': '2.0', 'cvss': '5.0', 'cvss_vec': 'AV:N/AC:L/Au:N/C:N/I:N/A:P'}, 'CVE-1999-0236': {'published': '1997-01-01 05:00:00', 'cvss_ver': '3.1', 'cvss': '7.5', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N'}, 'CVE-2018-1302': {'published': '2018-03-26 15:29:00', 'cvss_ver': '3.0', 'cvss': '5.9', 'cvss_vec': 'CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H'}, 'CVE-2022-31813': {'published': '2022-06-09 17:15:09', 'cvss_ver': '3.1', 'cvss': '9.8', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'}, 'CVE-2020-1927': {'published': '2020-04-02 00:15:13', 'cvss_ver': '3.1', 'cvss': '6.1', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N'}, 'CVE-2020-9490': {'published': '2020-08-07 16:15:12', 'cvss_ver': '3.1', 'cvss': '7.5', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H'}, 'CVE-2022-23943': {'published': '2022-03-14 11:15:09', 'cvss_ver': '3.1', 'cvss': '9.8', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'}, 'CVE-2017-7679': {'published': '2017-06-20 01:29:00', 'cvss_ver': '3.0', 'cvss': '9.8', 'cvss_vec': 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'}, 'CVE-2020-35452': {'published': '2021-06-10 07:15:07', 'cvss_ver': '3.1', 'cvss': '7.3', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L'}, 'CVE-2017-15715': {'published': '2018-03-26 15:29:00', 'cvss_ver': '3.0', 'cvss': '8.1', 'cvss_vec': 'CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H'}, 'CVE-2022-28614': {'published': '2022-06-09 17:15:09', 'cvss_ver': '3.1', 'cvss': '5.3', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N'}, 'CVE-2021-33193': {'published': '2021-08-16 08:15:11', 'cvss_ver': '3.1', 'cvss': '7.5', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N'}, 'CVE-2022-36760': {'published': '2023-01-17 20:15:11', 'cvss_ver': '3.1', 'cvss': '9.0', 'cvss_vec': 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H'}, 'CVE-2022-28330': {'published': '2022-06-09 17:15:09', 'cvss_ver': '3.1', 'cvss': '5.3', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N'}, 'CVE-2021-26691': {'published': '2021-06-10 07:15:07', 'cvss_ver': '3.1', 'cvss': '9.8', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'}, 'CVE-2022-22720': {'published': '2022-03-14 11:15:09', 'cvss_ver': '3.1', 'cvss': '9.8', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'}, 'CVE-2018-11763': {'published': '2018-09-25 21:29:00', 'cvss_ver': '3.0', 'cvss': '5.9', 'cvss_vec': 'CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H'}, 'CVE-2021-40438': {'published': '2021-09-16 15:15:07', 'cvss_ver': '3.1', 'cvss': '9.0', 'cvss_vec': 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H'}, 'CVE-2022-22721': {'published': '2022-03-14 11:15:09', 'cvss_ver': '3.1', 'cvss': '9.1', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H'}, 'CVE-2022-29404': {'published': '2022-06-09 17:15:09', 'cvss_ver': '3.1', 'cvss': '7.5', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H'}, 'CVE-2020-13938': {'published': '2021-06-10 07:15:07', 'cvss_ver': '3.1', 'cvss': '5.5', 'cvss_vec': 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H'}, 'CVE-2021-44790': {'published': '2021-12-20 12:15:07', 'cvss_ver': '3.1', 'cvss': '9.8', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'}, 'CVE-2020-1934': {'published': '2020-04-01 20:15:15', 'cvss_ver': '3.1', 'cvss': '5.3', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N'}, 'CVE-2019-0217': {'published': '2019-04-08 21:29:00', 'cvss_ver': '3.1', 'cvss': '7.5', 'cvss_vec': 'CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H'}, 'CVE-2018-1333': {'published': '2018-06-18 18:29:00', 'cvss_ver': '3.0', 'cvss': '7.5', 'cvss_vec': 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H'}, 'CVE-2018-1303': {'published': '2018-03-26 15:29:00', 'cvss_ver': '3.0', 'cvss': '7.5', 'cvss_vec': 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H'}, 'CVE-2018-17199': {'published': '2019-01-30 22:29:00', 'cvss_ver': '3.0', 'cvss': '7.5', 'cvss_vec': 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N'}, 'CVE-2019-0211': {'published': '2019-04-08 22:29:00', 'cvss_ver': '3.0', 'cvss': '7.8', 'cvss_vec': 'CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H'}, 'CVE-2022-26377': {'published': '2022-06-09 17:15:09', 'cvss_ver': '3.1', 'cvss': '7.5', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N'}, 'CVE-2007-0086': {'published': '2007-01-05 18:28:00', 'cvss_ver': '2.0', 'cvss': '7.8', 'cvss_vec': 'AV:N/AC:L/Au:N/C:N/I:N/A:C'}, 'CVE-2023-31122': {'published': '2023-10-23 07:15:11', 'cvss_ver': '3.1', 'cvss': '7.5', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H'}, 'CVE-2023-45802': {'published': '2023-10-23 07:15:11', 'cvss_ver': '3.1', 'cvss': '5.9', 'cvss_vec': 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H'}}

        for cve, cve_attrs in result.items():
            self.assertIn(cve, expected_attrs)
            self.assertEqual(cve_attrs['published'], expected_attrs[cve]['published'])
            self.assertEqual(cve_attrs['cvss_ver'], expected_attrs[cve]['cvss_ver'])
            self.assertEqual(cve_attrs['cvss'], expected_attrs[cve]['cvss'])
            self.assertEqual(cve_attrs['cvss_vec'], expected_attrs[cve]['cvss_vec'])

    def test_search_proftpd_133c(self):
        self.maxDiff = None
        result = search_vulns.search_vulns(query='cpe:2.3:a:proftpd:proftpd:1.3.3:c:*:*:*:*:*:*', add_other_exploit_refs=True, is_good_cpe=True)
        expected_attrs = {'CVE-2011-1137': {'published': '2011-03-11 17:55:03', 'cvss_ver': '2.0', 'cvss': '5.0', 'cvss_vec': 'AV:N/AC:L/Au:N/C:N/I:N/A:P'}, 'CVE-2011-4130': {'published': '2011-12-06 11:55:06', 'cvss_ver': '2.0', 'cvss': '9.0', 'cvss_vec': 'AV:N/AC:L/Au:S/C:C/I:C/A:C'}, 'CVE-2012-6095': {'published': '2013-01-24 21:55:01', 'cvss_ver': '2.0', 'cvss': '1.2', 'cvss_vec': 'AV:L/AC:H/Au:N/C:N/I:P/A:N'}, 'CVE-2019-19272': {'published': '2019-11-26 04:15:13', 'cvss_ver': '3.1', 'cvss': '7.5', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H'}, 'CVE-2019-18217': {'published': '2019-10-21 04:15:10', 'cvss_ver': '3.1', 'cvss': '7.5', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H'}, 'CVE-2020-9272': {'published': '2020-02-20 16:15:11', 'cvss_ver': '3.1', 'cvss': '7.5', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N'}, 'CVE-2021-46854': {'published': '2022-11-23 07:15:09', 'cvss_ver': '3.1', 'cvss': '7.5', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N'}, 'CVE-2019-19269': {'published': '2019-11-30 23:15:18', 'cvss_ver': '3.1', 'cvss': '4.9', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H'}, 'CVE-2019-19270': {'published': '2019-11-26 04:15:12', 'cvss_ver': '3.1', 'cvss': '7.5', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N'}, 'CVE-2019-12815': {'published': '2019-07-19 23:15:11', 'cvss_ver': '3.1', 'cvss': '9.8', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'}, 'CVE-2010-4652': {'published': '2011-02-02 01:00:04', 'cvss_ver': '2.0', 'cvss': '6.8', 'cvss_vec': 'AV:N/AC:M/Au:N/C:P/I:P/A:P'}, 'CVE-2019-19271': {'published': '2019-11-26 04:15:13', 'cvss_ver': '3.1', 'cvss': '7.5', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N'}}

        for cve, cve_attrs in result.items():
            self.assertIn(cve, expected_attrs)
            self.assertEqual(cve_attrs['published'], expected_attrs[cve]['published'])
            self.assertEqual(cve_attrs['cvss_ver'], expected_attrs[cve]['cvss_ver'])
            self.assertEqual(cve_attrs['cvss'], expected_attrs[cve]['cvss'])
            self.assertEqual(cve_attrs['cvss_vec'], expected_attrs[cve]['cvss_vec'])

    def test_search_thingsboard_341(self):
        self.maxDiff = None
        result = search_vulns.search_vulns(query='cpe:2.3:a:thingsboard:thingsboard:3.4.1:*:*:*:*:*:*:*', add_other_exploit_refs=True, is_good_cpe=True)
        expected_attrs = {'CVE-2022-40004': {'published': '2022-12-15 23:15:10', 'cvss_ver': '3.1', 'cvss': '9.6', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H'}, 'CVE-2022-45608': {'published': '2023-03-01 16:15:09', 'cvss_ver': '3.1', 'cvss': '8.8', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H'}, 'CVE-2022-48341': {'published': '2023-02-23 06:15:10', 'cvss_ver': '3.1', 'cvss': '8.8', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H'}, 'CVE-2023-26462': {'published': '2023-02-23 06:15:10', 'cvss_ver': '3.1', 'cvss': '8.1', 'cvss_vec': 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H'}, 'CVE-2023-45303': {'published': '2023-10-06 19:15:13', 'cvss_ver': '3.1', 'cvss': '8.8', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H'}}

        for cve, cve_attrs in result.items():
            self.assertIn(cve, expected_attrs)
            self.assertEqual(cve_attrs['published'], expected_attrs[cve]['published'])
            self.assertEqual(cve_attrs['cvss_ver'], expected_attrs[cve]['cvss_ver'])
            self.assertEqual(cve_attrs['cvss'], expected_attrs[cve]['cvss'])
            self.assertEqual(cve_attrs['cvss_vec'], expected_attrs[cve]['cvss_vec'])

    def test_search_redis_323(self):
        self.maxDiff = None
        result = search_vulns.search_vulns(query='cpe:2.3:a:redis:redis:3.2.3:*:*:*:*:*:*:*', add_other_exploit_refs=True, is_good_cpe=True)
        expected_attrs = {'CVE-2022-3647': {'published': '2022-10-21 18:15:10', 'cvss_ver': '3.1', 'cvss': '3.3', 'cvss_vec': 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L'}, 'CVE-2023-28856': {'published': '2023-04-18 21:15:09', 'cvss_ver': '3.1', 'cvss': '6.5', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H'}, 'CVE-2022-0543': {'published': '2022-02-18 20:15:17', 'cvss_ver': '3.1', 'cvss': '10.0', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H'}, 'CVE-2022-24736': {'published': '2022-04-27 20:15:09', 'cvss_ver': '3.1', 'cvss': '5.5', 'cvss_vec': 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H'}, 'CVE-2021-32626': {'published': '2021-10-04 18:15:08', 'cvss_ver': '3.1', 'cvss': '8.8', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H'}, 'CVE-2022-36021': {'published': '2023-03-01 16:15:09', 'cvss_ver': '3.1', 'cvss': '5.5', 'cvss_vec': 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H'}, 'CVE-2021-32672': {'published': '2021-10-04 18:15:08', 'cvss_ver': '3.1', 'cvss': '4.3', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N'}, 'CVE-2022-24834': {'published': '2023-07-13 15:15:08', 'cvss_ver': '3.1', 'cvss': '8.8', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H'}, 'CVE-2023-25155': {'published': '2023-03-02 04:15:10', 'cvss_ver': '3.1', 'cvss': '6.5', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H'}, 'CVE-2022-3734': {'published': '2022-10-28 08:15:14', 'cvss_ver': '3.1', 'cvss': '9.8', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'}, 'CVE-2021-31294': {'published': '2023-07-15 23:15:09', 'cvss_ver': '3.1', 'cvss': '5.9', 'cvss_vec': 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H'}, 'CVE-2022-24735': {'published': '2022-04-27 20:15:09', 'cvss_ver': '3.1', 'cvss': '7.8', 'cvss_vec': 'CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H'}, 'CVE-2023-45145': {'published': '2023-10-18 21:15:09', 'cvss_ver': '3.1', 'cvss': '3.6', 'cvss_vec': 'CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:N'}}

        for cve, cve_attrs in result.items():
            self.assertIn(cve, expected_attrs)
            self.assertEqual(cve_attrs['published'], expected_attrs[cve]['published'])
            self.assertEqual(cve_attrs['cvss_ver'], expected_attrs[cve]['cvss_ver'])
            self.assertEqual(cve_attrs['cvss'], expected_attrs[cve]['cvss'])
            self.assertEqual(cve_attrs['cvss_vec'], expected_attrs[cve]['cvss_vec'])

    def test_search_piwik_045(self):
        self.maxDiff = None
        result = search_vulns.search_vulns(query='cpe:2.3:a:piwik:piwik:0.4.5:*:*:*:*:*:*:*', add_other_exploit_refs=True)
        expected_attrs = {'CVE-2010-1453': {'published': '2010-05-07 18:24:15', 'cvss_ver': '2.0', 'cvss': '4.3', 'cvss_vec': 'AV:N/AC:M/Au:N/C:N/I:P/A:N'}, 'CVE-2011-0004': {'published': '2011-01-10 20:00:17', 'cvss_ver': '2.0', 'cvss': '4.3', 'cvss_vec': 'AV:N/AC:M/Au:N/C:N/I:P/A:N'}, 'CVE-2011-0398': {'published': '2011-01-10 20:00:17', 'cvss_ver': '2.0', 'cvss': '6.4', 'cvss_vec': 'AV:N/AC:L/Au:N/C:P/I:P/A:N'}, 'CVE-2011-0399': {'published': '2011-01-10 20:00:17', 'cvss_ver': '2.0', 'cvss': '4.3', 'cvss_vec': 'AV:N/AC:M/Au:N/C:N/I:P/A:N'}, 'CVE-2011-0400': {'published': '2011-01-10 20:00:17', 'cvss_ver': '2.0', 'cvss': '5.0', 'cvss_vec': 'AV:N/AC:L/Au:N/C:P/I:N/A:N'}, 'CVE-2011-0401': {'published': '2011-01-10 20:00:17', 'cvss_ver': '2.0', 'cvss': '5.0', 'cvss_vec': 'AV:N/AC:L/Au:N/C:N/I:N/A:P'}, 'CVE-2013-2633': {'published': '2013-03-21 21:55:01', 'cvss_ver': '2.0', 'cvss': '5.0', 'cvss_vec': 'AV:N/AC:L/Au:N/C:P/I:N/A:N'}, 'CVE-2012-4541': {'published': '2012-11-19 12:10:52', 'cvss_ver': '2.0', 'cvss': '4.3', 'cvss_vec': 'AV:N/AC:M/Au:N/C:N/I:P/A:N'}, 'CVE-2015-7815': {'published': '2015-11-16 19:59:04', 'cvss_ver': '2.0', 'cvss': '7.5', 'cvss_vec': 'AV:N/AC:L/Au:N/C:P/I:P/A:P'}, 'CVE-2013-1844': {'published': '2013-03-21 21:55:00', 'cvss_ver': '2.0', 'cvss': '4.3', 'cvss_vec': 'AV:N/AC:M/Au:N/C:N/I:P/A:N'}, 'CVE-2013-0194': {'published': '2019-11-20 15:15:11', 'cvss_ver': '3.1', 'cvss': '6.1', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N'}, 'CVE-2013-0195': {'published': '2019-11-20 15:15:11', 'cvss_ver': '3.1', 'cvss': '6.1', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N'}, 'CVE-2015-7816': {'published': '2015-11-16 19:59:05', 'cvss_ver': '2.0', 'cvss': '7.5', 'cvss_vec': 'AV:N/AC:L/Au:N/C:P/I:P/A:P'}, 'CVE-2013-0193': {'published': '2019-11-20 15:15:11', 'cvss_ver': '3.1', 'cvss': '6.1', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N'}}

        for cve, cve_attrs in result.items():
            self.assertIn(cve, expected_attrs)
            self.assertEqual(cve_attrs['published'], expected_attrs[cve]['published'])
            self.assertEqual(cve_attrs['cvss_ver'], expected_attrs[cve]['cvss_ver'])
            self.assertEqual(cve_attrs['cvss'], expected_attrs[cve]['cvss'])
            self.assertEqual(cve_attrs['cvss_vec'], expected_attrs[cve]['cvss_vec'])

    def test_search_vmware_spring_framework_5326(self):
        self.maxDiff = None
        result = search_vulns.search_vulns(query='cpe:2.3:a:vmware:spring_framework:5.3.26:*:*:*:*:*:*:*', add_other_exploit_refs=True, is_good_cpe=True)
        expected_attrs = {'CVE-2016-1000027': {'published': '2020-01-02 23:15:11', 'cvss_ver': '3.1', 'cvss': '9.8', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'}, 'CVE-2023-20863': {'published': '2023-04-13 20:15:07', 'cvss_ver': '3.1', 'cvss': '6.5', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H'}}

        for cve, cve_attrs in result.items():
            self.assertIn(cve, expected_attrs)
            self.assertEqual(cve_attrs['published'], expected_attrs[cve]['published'])
            self.assertEqual(cve_attrs['cvss_ver'], expected_attrs[cve]['cvss_ver'])
            self.assertEqual(cve_attrs['cvss'], expected_attrs[cve]['cvss'])
            self.assertEqual(cve_attrs['cvss_vec'], expected_attrs[cve]['cvss_vec'])

    def test_search_zulip_48(self):
        self.maxDiff = None
        result = search_vulns.search_vulns(query='cpe:2.3:a:zulip:zulip:4.8:*:*:*:*:*:*:*', add_other_exploit_refs=True, is_good_cpe=True)
        expected_attrs = {'CVE-2021-3967': {'published': '2022-02-26 23:15:08', 'cvss_ver': '3.1', 'cvss': '8.8', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H'}, 'CVE-2022-36048': {'published': '2022-08-31 20:15:08', 'cvss_ver': '3.1', 'cvss': '4.3', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N'}, 'CVE-2021-43799': {'published': '2022-01-25 21:15:07', 'cvss_ver': '3.1', 'cvss': '9.8', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'}, 'CVE-2023-32677': {'published': '2023-05-19 21:15:08', 'cvss_ver': '3.1', 'cvss': '3.1', 'cvss_vec': 'CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N'}, 'CVE-2022-31017': {'published': '2022-06-25 09:15:09', 'cvss_ver': '3.1', 'cvss': '2.6', 'cvss_vec': 'CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N'}, 'CVE-2022-35962': {'published': '2022-08-29 15:15:10', 'cvss_ver': '3.1', 'cvss': '5.7', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:N/A:N'}, 'CVE-2022-31168': {'published': '2022-07-22 13:15:08', 'cvss_ver': '3.1', 'cvss': '8.8', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H'}, 'CVE-2022-24751': {'published': '2022-03-16 14:15:08', 'cvss_ver': '3.1', 'cvss': '7.4', 'cvss_vec': 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N'}, 'CVE-2021-3866': {'published': '2022-01-20 11:15:07', 'cvss_ver': '3.1', 'cvss': '5.4', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N'}, 'CVE-2023-28623': {'published': '2023-05-19 22:15:09', 'cvss_ver': '3.1', 'cvss': '3.7', 'cvss_vec': 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N'}}

        for cve, cve_attrs in result.items():
            self.assertIn(cve, expected_attrs)
            self.assertEqual(cve_attrs['published'], expected_attrs[cve]['published'])
            self.assertEqual(cve_attrs['cvss_ver'], expected_attrs[cve]['cvss_ver'])
            self.assertEqual(cve_attrs['cvss'], expected_attrs[cve]['cvss'])
            self.assertEqual(cve_attrs['cvss_vec'], expected_attrs[cve]['cvss_vec'])

    def test_search_zulip_server_general(self):
        self.maxDiff = None
        result = search_vulns.search_vulns(query='cpe:2.3:a:zulip:zulip_server:*:*:*:*:*:*:*:*', add_other_exploit_refs=True, is_good_cpe=True)
        expected_attrs = {'CVE-2017-0881': {'published': '2017-03-28 02:59:01', 'cvss_ver': '3.0', 'cvss': '4.3', 'cvss_vec': 'CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N'}, 'CVE-2017-0910': {'published': '2017-11-27 16:29:00', 'cvss_ver': '3.0', 'cvss': '8.8', 'cvss_vec': 'CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H'}, 'CVE-2018-9986': {'published': '2018-04-18 08:29:00', 'cvss_ver': '3.0', 'cvss': '6.1', 'cvss_vec': 'CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N'}, 'CVE-2018-9987': {'published': '2018-04-18 08:29:00', 'cvss_ver': '3.0', 'cvss': '6.1', 'cvss_vec': 'CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N'}, 'CVE-2018-9990': {'published': '2018-04-18 08:29:00', 'cvss_ver': '3.0', 'cvss': '6.1', 'cvss_vec': 'CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N'}, 'CVE-2018-9999': {'published': '2018-04-18 08:29:00', 'cvss_ver': '3.0', 'cvss': '5.4', 'cvss_vec': 'CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N'}, 'CVE-2019-16215': {'published': '2019-09-18 12:15:10', 'cvss_ver': '3.1', 'cvss': '6.5', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H'}, 'CVE-2019-16216': {'published': '2019-09-18 12:15:10', 'cvss_ver': '3.1', 'cvss': '5.4', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N'}, 'CVE-2019-18933': {'published': '2019-11-21 23:15:13', 'cvss_ver': '3.1', 'cvss': '9.8', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'}, 'CVE-2019-19775': {'published': '2019-12-18 04:15:15', 'cvss_ver': '3.1', 'cvss': '6.1', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N'}, 'CVE-2020-10935': {'published': '2020-04-20 20:15:11', 'cvss_ver': '3.1', 'cvss': '5.4', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N'}, 'CVE-2020-12759': {'published': '2020-08-21 05:15:11', 'cvss_ver': '3.1', 'cvss': '6.1', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N'}, 'CVE-2020-14194': {'published': '2020-08-21 05:15:11', 'cvss_ver': '3.1', 'cvss': '5.4', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N'}, 'CVE-2020-14215': {'published': '2020-08-21 05:15:11', 'cvss_ver': '3.1', 'cvss': '7.5', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N'}, 'CVE-2020-15070': {'published': '2020-08-21 05:15:11', 'cvss_ver': '3.1', 'cvss': '8.8', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H'}, 'CVE-2020-9444': {'published': '2020-04-20 20:15:11', 'cvss_ver': '3.1', 'cvss': '6.1', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N'}, 'CVE-2020-9445': {'published': '2020-04-20 20:15:11', 'cvss_ver': '3.1', 'cvss': '6.1', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N'}, 'CVE-2021-30477': {'published': '2021-04-15 00:15:13', 'cvss_ver': '3.1', 'cvss': '4.3', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N'}, 'CVE-2021-30478': {'published': '2021-04-15 00:15:13', 'cvss_ver': '3.1', 'cvss': '4.3', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N'}, 'CVE-2021-30479': {'published': '2021-04-15 00:15:13', 'cvss_ver': '3.1', 'cvss': '5.3', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N'}, 'CVE-2021-30487': {'published': '2021-04-15 00:15:13', 'cvss_ver': '3.1', 'cvss': '2.7', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:L/A:N'}, 'CVE-2022-21706': {'published': '2022-02-26 00:15:08', 'cvss_ver': '3.1', 'cvss': '9.8', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'}, 'CVE-2022-23656': {'published': '2022-03-02 21:15:08', 'cvss_ver': '3.1', 'cvss': '5.4', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N'}, 'CVE-2022-31134': {'published': '2022-07-12 21:15:09', 'cvss_ver': '3.1', 'cvss': '4.9', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N'}, 'CVE-2022-41914': {'published': '2022-11-16 20:15:10', 'cvss_ver': '3.1', 'cvss': '3.7', 'cvss_vec': 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N'}, 'CVE-2023-32678': {'published': '2023-08-25 21:15:08', 'cvss_ver': '3.1', 'cvss': '6.5', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N'}, 'CVE-2017-0896': {'published': '2017-06-02 17:29:00', 'cvss_ver': '3.0', 'cvss': '6.5', 'cvss_vec': 'CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N'}, 'CVE-2023-33186': {'published': '2023-05-30 06:16:36', 'cvss_ver': '3.1', 'cvss': '6.1', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N'}, 'CVE-2023-22735': {'published': '2023-02-07 19:15:09', 'cvss_ver': '3.1', 'cvss': '4.6', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:N'}}

        for cve, cve_attrs in result.items():
            self.assertIn(cve, expected_attrs)
            self.assertEqual(cve_attrs['published'], expected_attrs[cve]['published'])
            self.assertEqual(cve_attrs['cvss_ver'], expected_attrs[cve]['cvss_ver'])
            self.assertEqual(cve_attrs['cvss'], expected_attrs[cve]['cvss'])
            self.assertEqual(cve_attrs['cvss_vec'], expected_attrs[cve]['cvss_vec'])

    def test_search_electron_1317(self):
        self.maxDiff = None
        result = search_vulns.search_vulns(query='cpe:2.3:a:electronjs:electron:13.1.7:*:*:*:*:*:*:*', add_other_exploit_refs=True, is_good_cpe=True)
        expected_attrs = {'CVE-2022-21718': {'published': '2022-03-22 17:15:07', 'cvss_ver': '3.1', 'cvss': '5.0', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:N/A:N'}, 'CVE-2022-29247': {'published': '2022-06-13 21:15:07', 'cvss_ver': '3.1', 'cvss': '9.8', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'}, 'CVE-2022-29257': {'published': '2022-06-13 22:15:08', 'cvss_ver': '3.1', 'cvss': '7.2', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H'}, 'CVE-2021-39184': {'published': '2021-10-12 19:15:07', 'cvss_ver': '3.1', 'cvss': '8.6', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N'}, 'CVE-2022-36077': {'published': '2022-11-08 07:15:09', 'cvss_ver': '3.1', 'cvss': '6.1', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N'}, 'CVE-2023-39956': {'published': '2023-09-06 21:15:13', 'cvss_ver': '3.1', 'cvss': '6.6', 'cvss_vec': 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:L'}, 'CVE-2023-29198': {'published': '2023-09-06 21:15:11', 'cvss_ver': '3.1', 'cvss': '8.5', 'cvss_vec': 'CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H'}}

        for cve, cve_attrs in result.items():
            self.assertIn(cve, expected_attrs)
            self.assertEqual(cve_attrs['published'], expected_attrs[cve]['published'])
            self.assertEqual(cve_attrs['cvss_ver'], expected_attrs[cve]['cvss_ver'])
            self.assertEqual(cve_attrs['cvss'], expected_attrs[cve]['cvss'])
            self.assertEqual(cve_attrs['cvss_vec'], expected_attrs[cve]['cvss_vec'])

    def test_search_hitachi_replication_manager_86500(self):
        self.maxDiff = None
        result = search_vulns.search_vulns(query='cpe:2.3:a:hitachi:replication_manager:8.6.5-00:*:*:*:*:*:*:*', add_other_exploit_refs=True, is_good_cpe=True)
        expected_attrs = {'CVE-2020-36695': {'published': '2023-07-18 03:15:52', 'cvss_ver': '3.1', 'cvss': '7.8', 'cvss_vec': 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H'}, 'CVE-2022-4146': {'published': '2023-07-18 03:15:55', 'cvss_ver': '3.1', 'cvss': '9.8', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'}, 'CVE-2019-17360': {'published': '2019-11-12 18:15:11', 'cvss_ver': '3.1', 'cvss': '7.5', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H'}}

        for cve, cve_attrs in result.items():
            self.assertIn(cve, expected_attrs)
            self.assertEqual(cve_attrs['published'], expected_attrs[cve]['published'])
            self.assertEqual(cve_attrs['cvss_ver'], expected_attrs[cve]['cvss_ver'])
            self.assertEqual(cve_attrs['cvss'], expected_attrs[cve]['cvss'])
            self.assertEqual(cve_attrs['cvss_vec'], expected_attrs[cve]['cvss_vec'])

    def test_search_handlebars_js_300(self):
        self.maxDiff = None
        result = search_vulns.search_vulns(query='cpe:2.3:a:handlebarsjs:handlebars:3.0.0:*:*:*:*:node.js:*:*', add_other_exploit_refs=True, is_good_cpe=False)
        expected_attrs = {'CVE-2021-23369': {'published': '2021-04-12 14:15:14', 'cvss_ver': '3.1', 'cvss': '9.8', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'}, 'CVE-2019-20920': {'published': '2020-09-30 18:15:17', 'cvss_ver': '3.1', 'cvss': '8.1', 'cvss_vec': 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:L/A:L'}, 'CVE-2021-23383': {'published': '2021-05-04 09:15:07', 'cvss_ver': '3.1', 'cvss': '9.8', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'}, 'CVE-2019-19919': {'published': '2019-12-20 23:15:11', 'cvss_ver': '3.1', 'cvss': '9.8', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'}, 'CVE-2015-8861': {'published': '2017-01-23 21:59:00', 'cvss_ver': '3.1', 'cvss': '6.1', 'cvss_vec': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N'}}

        for cve, cve_attrs in result.items():
            self.assertIn(cve, expected_attrs)
            self.assertEqual(cve_attrs['published'], expected_attrs[cve]['published'])
            self.assertEqual(cve_attrs['cvss_ver'], expected_attrs[cve]['cvss_ver'])
            self.assertEqual(cve_attrs['cvss'], expected_attrs[cve]['cvss'])
            self.assertEqual(cve_attrs['cvss_vec'], expected_attrs[cve]['cvss_vec'])


if __name__ == '__main__':
    unittest.main()

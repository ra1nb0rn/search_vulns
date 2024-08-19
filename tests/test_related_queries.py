#!/usr/bin/env python3

import os
import unittest
import sys

SEARCH_VULNS_PATH = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
sys.path.insert(1, SEARCH_VULNS_PATH)
from search_vulns_modules.search_vulns_functions import search_vulns_return_cpe

class TestSearches(unittest.TestCase):

    def test_search_wp_100_42_3(self):
        self.maxDiff = None
        query = 'WordPress 100.42.3'
        result = search_vulns_return_cpe(query)
        expected_related_cpes = [('cpe:2.3:a:wordpress:wordpress:100.42.3:*:*:*:*:*:*:*', -1), ('cpe:2.3:a:wordpress:wordpress:-:*:*:*:*:*:*:*', 0.7889609186783934)]
        for i, (expected_related_cpe, match_score) in enumerate(expected_related_cpes):
            self.assertEqual(expected_related_cpe, result[query]['pot_cpes'][i][0])
            self.assertAlmostEqual(match_score, result[query]['pot_cpes'][i][1])

    def test_apache_airflow_100_42_3(self):
        self.maxDiff = None
        query = 'Airflow 100.42.3'
        result = search_vulns_return_cpe(query)
        expected_related_cpes = [('cpe:2.3:a:apache:airflow:100.42.3:*:*:*:*:*:*:*', -1), ('cpe:2.3:a:apache:airflow:0.1:*:*:*:*:*:*:*', 0.45357155662782184)]
        for i, (expected_related_cpe, match_score) in enumerate(expected_related_cpes):
            self.assertEqual(expected_related_cpe, result[query]['pot_cpes'][i][0])
            self.assertAlmostEqual(match_score, result[query]['pot_cpes'][i][1])

    def test_apache_airflow_no_version(self):
        self.maxDiff = None
        query = 'Airflow'
        result = search_vulns_return_cpe(query)
        expected_related_cpes = [('cpe:2.3:a:apache:airflow:*:*:*:*:*:*:*:*', -1), ('cpe:2.3:a:apache:airflow:0.1:*:*:*:*:*:*:*', 0.574897369298862)]
        for i, (expected_related_cpe, match_score) in enumerate(expected_related_cpes):
            self.assertEqual(expected_related_cpe, result[query]['pot_cpes'][i][0])
            self.assertAlmostEqual(match_score, result[query]['pot_cpes'][i][1])

    def test_jquery_100_42_3(self):
        self.maxDiff = None
        query = 'jQuery 100.42.3'
        result = search_vulns_return_cpe(query)
        expected_related_cpes = [('cpe:2.3:a:jquery:jquery:100.42.3:*:*:*:*:*:*:*', -1), ('cpe:2.3:a:jquery:jquery:-:*:*:*:*:*:*:*', 0.7889609186783934), ('cpe:2.3:a:jqueryui:jquery_ui:100.42.3:*:*:*:*:jquery:*:*', -1), ('cpe:2.3:a:jqueryui:jquery_ui:1.0:*:*:*:*:jquery:*:*', 0.6433270204106121), ('cpe:2.3:a:jqueryui:jquery_ui:1.10.0:-:*:*:*:jquery:*:*', 0.6433270204106121), ('cpe:2.3:a:jqueryui:jquery_ui:100.42.3:beta1:*:*:*:jquery:*:*', -1)]
        for i, (expected_related_cpe, match_score) in enumerate(expected_related_cpes):
            self.assertEqual(expected_related_cpe, result[query]['pot_cpes'][i][0])
            self.assertAlmostEqual(match_score, result[query]['pot_cpes'][i][1])

    def test_search_jfrog_artifactory_4_29_0(self):
        self.maxDiff = None
        query = 'jfrog artifactory 4.29.0'
        result = search_vulns_return_cpe(query)
        expected_related_cpes = [('cpe:2.3:a:jfrog:artifactory:4.29.0:-:*:*:*:-:*:*', -1), ('cpe:2.3:a:jfrog:artifactory:1.3.0:-:*:*:*:-:*:*', 0.7618540942296063), ('cpe:2.3:a:jfrog:artifactory:4.29.0:*:*:*:*:jenkins:*:*', -1), ('cpe:2.3:a:jfrog:artifactory:1.0.1:*:*:*:*:jenkins:*:*', 0.6728911631889697)]
        for i, (expected_related_cpe, match_score) in enumerate(expected_related_cpes):
            self.assertEqual(expected_related_cpe, result[query]['pot_cpes'][i][0])
            self.assertAlmostEqual(match_score, result[query]['pot_cpes'][i][1])

    def test_search_dell_omsa_9_4_0_2(self):
        self.maxDiff = None
        query = 'dell omsa 9.4.0.2'
        result = search_vulns_return_cpe(query)
        expected_related_cpes = [('cpe:2.3:a:dell:openmanage_server_administrator:9.4.0.2:*:*:*:*:*:*:*', -1), ('cpe:2.3:a:dell:openmanage_server_administrator:5.2.0:*:*:*:*:*:*:*', 0.9356286465015572), ('cpe:2.3:a:dell:openmanage_server_administrator:1.00.0000:*:*:*:*:*:*:*', 0.8845604348848455), ('cpe:2.3:a:dell:openmanage_server_administrator_installer:9.4.0.2:*:*:*:*:*:*:*', -1), ('cpe:2.3:a:dell:openmanage_server_administrator_installer:1.0.0:*:*:*:*:*:*:*', 0.8355902246901327), ('cpe:2.3:a:dell:openmanage_server_administrator_lite:9.4.0.2:*:*:*:*:*:*:*', -1), ('cpe:2.3:a:dell:openmanage_server_administrator_lite:5.4.1:*:*:*:*:*:*:*', 0.8355902246901327), ('cpe:2.3:a:dell:openmanage:9.4.0.2:*:*:*:*:*:*:*', -1), ('cpe:2.3:a:dell:openmanage:-:*:*:*:*:*:*:*', 0.826938997039739)]
        for i, (expected_related_cpe, match_score) in enumerate(expected_related_cpes):
            self.assertEqual(expected_related_cpe, result[query]['pot_cpes'][i][0])
            self.assertAlmostEqual(match_score, result[query]['pot_cpes'][i][1])

    def test_search_citrix_adc_13_1_42_47(self):
        self.maxDiff = None
        query = 'citrix adc 13.1-42.47'
        result = search_vulns_return_cpe(query)
        expected_related_cpes = [('cpe:2.3:a:citrix:application_delivery_controller:13.1-42.47:*:*:*:-:*:*:*', -1), ('cpe:2.3:a:citrix:application_delivery_controller:42.47:*:*:*:-:*:*:*', -1), ('cpe:2.3:a:citrix:application_delivery_controller:13.1:*:*:*:-:*:*:*', 0.9443356111798747), ('cpe:2.3:h:citrix:application_delivery_controller:13.1-42.47:*:*:*:*:*:*:*', -1), ('cpe:2.3:h:citrix:application_delivery_controller:13.1:*:*:*:*:*:*:*', -1), ('cpe:2.3:h:citrix:application_delivery_controller:42.47:*:*:*:*:*:*:*', -1), ('cpe:2.3:h:citrix:application_delivery_controller:-:*:*:*:*:*:*:*', 0.9195900759823715), ('cpe:2.3:a:citrix:application_delivery_controller:13.1-21.50:*:*:*:*:*:*:*', 0.8959514540639271), ('cpe:2.3:a:citrix:application_delivery_controller:12.1:*:*:*:-:*:*:*', 0.8588472122359783), ('cpe:2.3:o:citrix:application_delivery_controller_firmware:13.1-42.47:*:*:*:*:*:*:*', -1), ('cpe:2.3:o:citrix:application_delivery_controller_firmware:13.1:*:*:*:*:*:*:*', -1), ('cpe:2.3:o:citrix:application_delivery_controller_firmware:42.47:*:*:*:*:*:*:*', -1), ('cpe:2.3:o:citrix:application_delivery_controller_firmware:10.1:*:*:*:*:*:*:*', 0.8212665153916354)]
        for i, (expected_related_cpe, match_score) in enumerate(expected_related_cpes):
            self.assertEqual(expected_related_cpe, result[query]['pot_cpes'][i][0])
            self.assertAlmostEqual(match_score, result[query]['pot_cpes'][i][1])

    def test_search_citrix_adc_no_version(self):
        self.maxDiff = None
        query = 'citrix adc'
        result = search_vulns_return_cpe(query)
        expected_related_cpes =  [('cpe:2.3:h:citrix:application_delivery_controller:-:*:*:*:*:*:*:*', 0.9640085266327638), ('cpe:2.3:a:citrix:application_delivery_controller:*:*:*:*:*:*:*:*', -1), ('cpe:2.3:a:citrix:application_delivery_controller:12.1:*:*:*:-:*:*:*', 0.9003316339465728), ('cpe:2.3:o:citrix:application_delivery_controller_firmware:*:*:*:*:*:*:*:*', -1), ('cpe:2.3:o:citrix:application_delivery_controller_firmware:10.1:*:*:*:*:*:*:*', 0.8609356974951642), ('cpe:2.3:o:citrix:application_delivery_controller_firmware:10.5:*:*:*:*:*:*:*', 0.8609356974951642), ('cpe:2.3:o:citrix:application_delivery_controller_firmware:10.5e:*:*:*:*:*:*:*', 0.8609356974951642)]
        for i, (expected_related_cpe, match_score) in enumerate(expected_related_cpes):
            self.assertEqual(expected_related_cpe, result[query]['pot_cpes'][i][0])
            self.assertAlmostEqual(match_score, result[query]['pot_cpes'][i][1])


if __name__ == '__main__':
    unittest.main()

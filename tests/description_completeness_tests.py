#!/usr/bin/env python3

import unittest
import subprocess

class TestSearches(unittest.TestCase): 

    def test_search_wp_572(self):
        self.maxDiff = None
        result = subprocess.run(['python', 'search_vulns.py', '-q', 'cpe:2.3:a:wordpress:wordpress:5.7.2:*:*:*:*:*:*:*'], capture_output=True, text=True)
        expected_description = ["SQL injection vulnerability in the administration panel in the DMSGuestbook 1.7.0 plugin for WordPress allows remote authenticated administrators to execute arbitrary SQL commands via unspecified vectors.  NOTE: it is not clear whether this issue crosses privilege boundaries.","https://www.exploit-db.com/exploits/5035", "https://nvd.nist.gov/vuln/detail/CVE-2008-0616", "2008-02-06"]
        for description_elem in expected_description:
            self.assertIn(description_elem, result.stdout)

    def test_search_apache_2425(self):
        self.maxDiff = None
        result = subprocess.run(['python', 'search_vulns.py', '-q', 'cpe:2.3:a:apache:http_server:2.4.25:*:*:*:*:*:*:*'], capture_output=True, text=True)
        expected_description = ["Directory traversal vulnerability in Apache HTTP Server and Tomcat 5.x before 5.5.22 and 6.x before 6.0.10, when using certain proxy modules (mod_proxy, mod_rewrite, mod_jk), allows remote attackers to read arbitrary files via a .. (dot dot) sequence with combinations of (1) \"/\" (slash), (2) \"\\\" (backslash), and (3) URL-encoded backslash (%5C) characters in the URL, which are valid separators in Tomcat but not in Apache.","https://www.exploit-db.com/exploits/29739","https://nvd.nist.gov/vuln/detail/CVE-2007-0450","2007-03-16"]
        for description_elem in expected_description:
            self.assertIn(description_elem, result.stdout)

    def test_search_proftpd_133c(self):
        self.maxDiff = None
        result = subprocess.run(['python', 'search_vulns.py', '-q', 'cpe:2.3:a:proftpd:proftpd:1.3.3:c:*:*:*:*:*:*'], capture_output=True, text=True)
        expected_description = ["Integer overflow in the mod_sftp (aka SFTP) module in ProFTPD 1.3.3d and earlier allows remote attackers to cause a denial of service (memory consumption leading to OOM kill) via a malformed SSH message.","https://www.exploit-db.com/exploits/16129","https://nvd.nist.gov/vuln/detail/CVE-2011-1137", "2011-03-11"]
        for description_elem in expected_description:
            self.assertIn(description_elem, result.stdout)

    def test_search_thingsboard_341(self):
        self.maxDiff = None
        result = subprocess.run(['python', 'search_vulns.py', '-q', 'cpe:2.3:a:thingsboard:thingsboard:3.4.1:*:*:*:*:*:*:*'], capture_output=True, text=True)
        expected_description = ["An issue was discovered in ThingsBoard 3.4.1, allows low privileged attackers (CUSTOMER_USER) to gain escalated privileges (vertically) and become an Administrator (TENANT_ADMIN) or (SYS_ADMIN) on the web application. It is important to note that in order to accomplish this, the attacker must know the corresponding API's parameter (authority : value).","https://nvd.nist.gov/vuln/detail/CVE-2022-45608", "2023-03-01"]
        for description_elem in expected_description:
            self.assertIn(description_elem, result.stdout)

    def test_search_redis_323(self):
        self.maxDiff = None
        result = subprocess.run(['python', 'search_vulns.py', '-q', 'cpe:2.3:a:redis:redis:3.2.3:*:*:*:*:*:*:*'], capture_output=True, text=True)
        expected_description = ["Type confusion in the xgroupCommand function in t_stream.c in redis-server in Redis before 5.0 allows remote attackers to cause denial-of-service via an XGROUP command in which the key is not a stream.", "https://www.exploit-db.com/exploits/44908", "https://nvd.nist.gov/vuln/detail/CVE-2018-12453", "2018-06-16"]
        for description_elem in expected_description:
            self.assertIn(description_elem, result.stdout)

    # def test_search_piwik_045(self):
    #     self.maxDiff = None
    #     result = subprocess.run(['python', 'search_vulns.py', '-q', 'cpe:2.3:a:wordpress:wordpress:5.7.2:*:*:*:*:*:*:*'], capture_output=True, text=True)
    #     expected_cves = ['CVE-2007-1622','CVE-2007-2627','CVE-2007-2757','CVE-2007-4014','CVE-2007-4165','CVE-2007-6677','CVE-2008-0198','CVE-2008-0491','CVE-2008-0615','CVE-2008-0616','CVE-2008-0617','CVE-2008-0618','CVE-2021-39200','CVE-2021-39201','CVE-2021-44223','CVE-2022-21661','CVE-2022-21662','CVE-2022-21663','CVE-2022-21664','CVE-2022-3590','CVE-2022-43497','CVE-2022-43500','CVE-2022-43504','CVE-2023-22622','CVE-2023-2745']
    #     for expected_cve in expected_cves:
    #         self.assertIn(expected_cve, result.stdout)

    def test_search_vmware_spring_framework_5326(self):
        self.maxDiff = None
        result = subprocess.run(['python', 'search_vulns.py', '-q', 'cpe:2.3:a:vmware:spring_framework:5.3.26:*:*:*:*:*:*:*'], capture_output=True, text=True)
        expected_description = ["In spring framework versions prior to 5.2.24 release+ ,5.3.27+ and 6.0.8+ , it is possible for a user to provide a specially crafted SpEL expression that may cause a denial-of-service (DoS) condition.","https://nvd.nist.gov/vuln/detail/CVE-2023-20863", "2023-04-13"]
        for description_elem in expected_description:
            self.assertIn(description_elem, result.stdout)

    def test_search_zulip_server_48(self):
        self.maxDiff = None
        result = subprocess.run(['python', 'search_vulns.py', '-q', 'cpe:2.3:a:zulip:zulip:4.8:*:*:*:*:*:*:*'], capture_output=True, text=True)
        expected_description = ["Zulip is an open-source team collaboration tool. Zulip Server installs RabbitMQ for internal message passing. In versions of Zulip Server prior to 4.9, the initial installation (until first reboot, or restart of RabbitMQ) does not successfully limit the default ports which RabbitMQ opens; this includes port 25672, the RabbitMQ distribution port, which is used as a management port. RabbitMQ's default \"cookie\" which protects this port is generated using a weak PRNG, which limits the entropy of the password to at most 36 bits; in practicality, the seed for the randomizer is biased, resulting in approximately 20 bits of entropy. If other firewalls (at the OS or network level) do not protect port 25672, a remote attacker can brute-force the 20 bits of entropy in the \"cookie\" and leverage it for arbitrary execution of code as the rabbitmq user. They can also read all data which is sent through RabbitMQ, which includes all message traffic sent by users. Version 4.9 contains a patch for this vulnerability. As a workaround, ensure that firewalls prevent access to ports 5672 and 25672 from outside the Zulip server.", "https://nvd.nist.gov/vuln/detail/CVE-2021-43799", "2022-01-25"]
        for description_elem in expected_description:
            self.assertIn(description_elem, result.stdout)

    def test_search_electron_1317(self):
        self.maxDiff = None
        result = subprocess.run(['python', 'search_vulns.py', '-q', 'cpe:2.3:a:electronjs:electron:13.1.7:*:*:*:*:*:*:*'], capture_output=True, text=True)
        expected_description = ["Electron is a framework for writing cross-platform desktop applications using JavaScript, HTML and CSS. A vulnerability in versions prior to 11.5.0, 12.1.0, and 13.3.0 allows a sandboxed renderer to request a \"thumbnail\" image of an arbitrary file on the user's system. The thumbnail can potentially include significant parts of the original file, including textual data in many cases. Versions 15.0.0-alpha.10, 14.0.0, 13.3.0, 12.1.0, and 11.5.0 all contain a fix for the vulnerability. Two workarounds aside from upgrading are available. One may make the vulnerability significantly more difficult for an attacker to exploit by enabling `contextIsolation` in one's app. One may also disable the functionality of the `createThumbnailFromPath` API if one does not need it.","https://nvd.nist.gov/vuln/detail/CVE-2021-39184", "2021-10-12"]
        for description_elem in expected_description:
            self.assertIn(description_elem, result.stdout)
    

if __name__ == '__main__':
    unittest.main()
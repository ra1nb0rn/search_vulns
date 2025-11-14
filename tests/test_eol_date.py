import unittest

from search_vulns.search_vulns import search_vulns


class TestSearches(unittest.TestCase):

    def test_search_wp_general(self):
        self.maxDiff = None
        query = "cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*"
        result = search_vulns(query=query, is_product_id_query=True)
        expected_result = {
            "status": "N/A",
            "latest": "6.8.3",
            "ref": "https://endoflife.date/wordpress",
        }
        self.assertEqual(result["version_status"], expected_result)

    def test_search_wp_572(self):
        self.maxDiff = None
        query = "cpe:2.3:a:wordpress:wordpress:5.7.2:*:*:*:*:*:*:*"
        result = search_vulns(query=query, is_product_id_query=True)
        expected_result = {
            "status": "eol",
            "latest": "6.8.3",
            "ref": "https://endoflife.date/wordpress",
        }
        self.assertEqual(result["version_status"], expected_result)

    def test_search_jquery_general(self):
        self.maxDiff = None
        query = "cpe:2.3:a:jquery:jquery:*:*:*:*:*:*:*:*"
        result = search_vulns(query=query, is_product_id_query=True)
        expected_result = {
            "status": "N/A",
            "latest": "3.7.1",
            "ref": "https://endoflife.date/jquery",
        }
        self.assertEqual(result["version_status"], expected_result)

    def test_search_jquery_213(self):
        self.maxDiff = None
        query = "cpe:2.3:a:jquery:jquery:2.1.3:*:*:*:*:*:*:*"
        result = search_vulns(query=query, is_product_id_query=True)
        expected_result = {
            "status": "eol",
            "latest": "3.7.1",
            "ref": "https://endoflife.date/jquery",
        }
        self.assertEqual(result["version_status"], expected_result)

    def test_search_mongodb_4_4_29(self):
        self.maxDiff = None
        query = "cpe:2.3:a:mongodb:mongodb:4.4.29:*:*:*:*:*:*:*"
        result = search_vulns(query=query, is_product_id_query=True)
        expected_result = {
            "status": "eol",
            "latest": "8.2.2",
            "ref": "https://endoflife.date/mongodb",
        }
        self.assertEqual(result["version_status"], expected_result)

    def test_search_mongodb_6_0_13(self):
        self.maxDiff = None
        query = "cpe:2.3:a:mongodb:mongodb:7.0.13:*:*:*:*:*:*:*"
        result = search_vulns(query=query, is_product_id_query=True)
        expected_result = {
            "status": "outdated",
            "latest": "8.2.2",
            "ref": "https://endoflife.date/mongodb",
        }
        self.assertEqual(result["version_status"], expected_result)


if __name__ == "__main__":
    unittest.main()

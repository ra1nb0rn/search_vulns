#!/usr/bin/env python3

import unittest

from search_vulns.cpe_version import CPEVersion


class TestSearches(unittest.TestCase):

    def test_version_comparison(self):
        # some version comparison tests that should succeed
        self.assertTrue(CPEVersion("15.0.4") != CPEVersion("15.0.0.4"))
        self.assertTrue(CPEVersion("15.0.4.0") == CPEVersion("15.0.4.0.0"))
        self.assertTrue(CPEVersion("15.0.4.0") == CPEVersion("15.0.4.0.0"))
        self.assertTrue(CPEVersion("15.4") > CPEVersion("15.0.4.2"))
        self.assertTrue(CPEVersion("15.0.0.4") < CPEVersion("15.0.4.0"))
        self.assertTrue(CPEVersion("15.0-1") < CPEVersion("15.0.0-2"))
        self.assertTrue(CPEVersion("8.6.5-00") < CPEVersion("8.7.0-00"))
        self.assertTrue(CPEVersion("8.0.0.5-00") > CPEVersion("7.0.0-00"))
        self.assertTrue(CPEVersion("8.0.5.0.0-00") == CPEVersion("8.0.5.0.0.0.0.0-00"))
        self.assertTrue(CPEVersion("8.0.5-00") == CPEVersion("8.0.5.0-00"))
        self.assertTrue(CPEVersion("8.0.5-01") == CPEVersion("8.0.5.0-01"))
        self.assertTrue(CPEVersion("0") == CPEVersion("00"))
        self.assertTrue(CPEVersion("7.0.0") < CPEVersion("8.6.5-00"))
        self.assertFalse(CPEVersion("8.6.5-00") < CPEVersion("8.6.5-00"))
        self.assertTrue(CPEVersion("1.3_rc1") < CPEVersion("1.3.5.0_rc1"))
        self.assertTrue(CPEVersion("1.3-a") < CPEVersion("1.3.0-rc1"))
        self.assertFalse(CPEVersion("1.3.1-4.5") < CPEVersion("1.3.0-4.5.6"))
        self.assertTrue(CPEVersion("20.0") < CPEVersion("20.0.0-3445"))
        self.assertTrue(CPEVersion("1.2.3+01") == CPEVersion("1.2.3+1"))
        self.assertTrue(CPEVersion("1.2.3+a.01") == CPEVersion("1.2.3+a.1"))
        self.assertTrue(CPEVersion("1.2.3+a.000001") == CPEVersion("1.2.3+a.1"))
        self.assertTrue(
            CPEVersion("3.1.4-l.o.n.g.e.r.rc.4") < CPEVersion("3.1.4-l.o.n.g.e.r.rc.5")
        )
        self.assertTrue(CPEVersion("3.1.2147483647") < CPEVersion("3.1.2147483647-1"))
        self.assertTrue(CPEVersion("3.1.2147483647-5") > CPEVersion("3.1.2147483647-1"))
        self.assertFalse(CPEVersion("21.0") < CPEVersion("21.0.0"))
        self.assertFalse(CPEVersion("21") < CPEVersion("21.0.0"))
        self.assertTrue(CPEVersion("3.7.0") > CPEVersion("3.7.0-rc1"))
        self.assertFalse(CPEVersion("3.7.0") < CPEVersion("3.7.0-alpha2"))


if __name__ == "__main__":
    unittest.main()

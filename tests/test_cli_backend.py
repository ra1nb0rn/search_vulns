#!/usr/bin/env python3

import argparse
import json
import os
import sys
import unittest
from io import BytesIO
from unittest.mock import MagicMock, patch

from search_vulns.cli.backend import (
    DEFAULT_API_URL,
    ApiBackend,
    ApiError,
    LocalBackend,
    _parse_api_result,
    select_backend,
)
from search_vulns.models.SearchVulnsResult import SearchVulnsResult


# ------------------------------------------------ fixtures
def _fake_api_json(cpes=None, pot_cpes=None, vulns=None, version_status=None):
    return json.dumps(
        {
            "product_ids": {"cpe": cpes or [], "purl": [], "raw": []},
            "pot_product_ids": {"cpe": pot_cpes or [], "purl": [], "raw": []},
            "vulns": vulns or {},
            "version_status": version_status or {},
        }
    ).encode()


def _mock_urlopen(response_bytes, status=200):
    resp = MagicMock()
    resp.read.return_value = response_bytes
    resp.__enter__ = MagicMock(return_value=resp)
    resp.__exit__ = MagicMock(return_value=False)
    return resp


# ------------------------------------------------ backend selection
class TestBackendSelection(unittest.TestCase):
    def _args(self, **kw):
        defaults = {"api_key": None, "api_url": None, "cpe_search_threshold": None}
        defaults.update(kw)
        return argparse.Namespace(**defaults)

    def test_no_api_flags_selects_local(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("SV_API_KEY", None)
            backend = select_backend(self._args(), {})
        self.assertIsInstance(backend, LocalBackend)

    def test_api_key_flag_selects_api(self):
        backend = select_backend(self._args(api_key="test-key"), {})
        self.assertIsInstance(backend, ApiBackend)

    def test_env_var_selects_api(self):
        with patch.dict(os.environ, {"SV_API_KEY": "env-key"}):
            backend = select_backend(self._args(), {})
        self.assertIsInstance(backend, ApiBackend)

    def test_custom_url_selects_api(self):
        backend = select_backend(
            self._args(api_key="k", api_url="https://custom.example.com/api/"), {}
        )
        self.assertIsInstance(backend, ApiBackend)

    def test_api_key_precedence_over_env(self):
        with patch.dict(os.environ, {"SV_API_KEY": "env-key"}):
            backend = select_backend(self._args(api_key="flag-key"), {})
        self.assertIsInstance(backend, ApiBackend)
        self.assertEqual(backend._api_key, "flag-key")


# ------------------------------------------------ API backend (mocked HTTP)
class TestApiBackend(unittest.TestCase):
    def _backend(self, api_url=None):
        return ApiBackend("test-key", api_url or DEFAULT_API_URL)

    @patch("search_vulns.cli.backend.urlopen")
    def test_suggest_calls_correct_endpoint(self, mock_urlopen):
        mock_urlopen.return_value = _mock_urlopen(_fake_api_json())
        self._backend().suggest("Apache 2.4")
        call_args = mock_urlopen.call_args
        req = call_args[0][0]
        self.assertIn("/product-id-suggestions", req.full_url)
        self.assertIn("query=Apache", req.full_url)

    @patch("search_vulns.cli.backend.urlopen")
    def test_suggest_sends_api_key_header(self, mock_urlopen):
        mock_urlopen.return_value = _mock_urlopen(_fake_api_json())
        self._backend().suggest("test")
        req = mock_urlopen.call_args[0][0]
        self.assertEqual(req.get_header("Api-key"), "test-key")

    @patch("search_vulns.cli.backend.urlopen")
    def test_suggest_parses_response(self, mock_urlopen):
        pot = [["cpe:2.3:a:apache:tomcat:9.0.22:*:*:*:*:*:*:*", 0.95]]
        mock_urlopen.return_value = _mock_urlopen(_fake_api_json(pot_cpes=pot))
        result = self._backend().suggest("Apache Tomcat 9")
        self.assertIsInstance(result, SearchVulnsResult)
        self.assertEqual(len(result.pot_product_ids.cpe), 1)

    @patch("search_vulns.cli.backend.urlopen")
    def test_search_calls_correct_endpoint(self, mock_urlopen):
        mock_urlopen.return_value = _mock_urlopen(_fake_api_json())
        self._backend().search("cpe:2.3:a:apache:tomcat:9.0.22:*:*:*:*:*:*:*")
        req = mock_urlopen.call_args[0][0]
        self.assertIn("/search-vulns", req.full_url)

    @patch("search_vulns.cli.backend.urlopen")
    def test_search_passes_flags(self, mock_urlopen):
        mock_urlopen.return_value = _mock_urlopen(_fake_api_json())
        self._backend().search("test", ignore_general_product_vulns=True)
        req = mock_urlopen.call_args[0][0]
        self.assertIn("ignore-general-product-vulns=true", req.full_url)

    @patch("search_vulns.cli.backend.urlopen")
    def test_http_error_non_fatal(self, mock_urlopen):
        from urllib.error import HTTPError

        mock_urlopen.side_effect = HTTPError(
            "http://x", 500, "fail", {}, BytesIO(b'{"message":"err"}')
        )
        with self.assertRaises(ApiError):
            self._backend()._api_get("/test", {}, fatal=False)

    @patch("builtins.print")
    @patch("search_vulns.cli.backend.urlopen")
    def test_http_error_fatal(self, mock_urlopen, mock_print):
        from urllib.error import HTTPError

        mock_urlopen.side_effect = HTTPError(
            "http://x", 500, "fail", {}, BytesIO(b'{"message":"err"}')
        )
        with self.assertRaises(SystemExit):
            self._backend()._api_get("/test", {}, fatal=True)
        mock_print.assert_called_with("Error: HTTP 500: err", file=sys.stderr)

    @patch("search_vulns.cli.backend.urlopen")
    def test_custom_api_url(self, mock_urlopen):
        mock_urlopen.return_value = _mock_urlopen(_fake_api_json())
        self._backend(api_url="https://custom.example.com/api/").suggest("test")
        req = mock_urlopen.call_args[0][0]
        self.assertTrue(req.full_url.startswith("https://custom.example.com/api/"))


# ------------------------------------------------ API response parsing
class TestParseApiResult(unittest.TestCase):
    def test_parses_product_ids(self):
        data = json.loads(_fake_api_json(cpes=["cpe:2.3:a:v:p:1:*:*:*:*:*:*:*"]))
        result = _parse_api_result(data)
        self.assertEqual(result.product_ids.cpe, ["cpe:2.3:a:v:p:1:*:*:*:*:*:*:*"])

    def test_parses_pot_product_ids(self):
        pot = [["cpe:2.3:a:v:p:1:*:*:*:*:*:*:*", 0.85]]
        data = json.loads(_fake_api_json(pot_cpes=pot))
        result = _parse_api_result(data)
        self.assertEqual(len(result.pot_product_ids.cpe), 1)
        self.assertAlmostEqual(result.pot_product_ids.cpe[0][1], 0.85)

    def test_parses_vulns(self):
        vulns = {
            "CVE-2024-0001": {
                "match_reason": "version_in_range",
                "tracked_by": {"nvd": "https://nvd.nist.gov/vuln/detail/CVE-2024-0001"},
                "matched_by": {"nvd": {"match_reason": "version_in_range", "confidence": 1.0}},
                "description": "Test vuln",
                "severity": {
                    "CVSS": {
                        "type": "CVSS",
                        "score": "7.5",
                        "version": "3.1",
                        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    },
                },
                "cisa_kev": False,
                "exploits": [],
                "cwe_ids": ["CWE-79"],
                "aliases": {"CVE-2024-0001": "https://nvd.nist.gov/vuln/detail/CVE-2024-0001"},
            }
        }
        data = json.loads(_fake_api_json(vulns=vulns))
        result = _parse_api_result(data)
        self.assertIn("CVE-2024-0001", result.vulns)
        v = result.vulns["CVE-2024-0001"]
        self.assertEqual(float(v.get_cvss_score()), 7.5)
        self.assertIn("CWE-79", v.cwe_ids)

    def test_parses_version_status(self):
        vs = {"status": "OUTDATED", "latest": "9.0.98", "reference": "https://example.com"}
        data = json.loads(_fake_api_json(version_status=vs))
        result = _parse_api_result(data)
        self.assertEqual(result.version_status.status.value, "OUTDATED")
        self.assertEqual(result.version_status.latest, "9.0.98")

    def test_empty_response(self):
        data = json.loads(_fake_api_json())
        result = _parse_api_result(data)
        self.assertIsInstance(result, SearchVulnsResult)
        self.assertEqual(len(result.vulns), 0)
        self.assertEqual(len(result.product_ids.cpe), 0)


if __name__ == "__main__":
    unittest.main()

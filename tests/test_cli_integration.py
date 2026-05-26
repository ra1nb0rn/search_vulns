#!/usr/bin/env python3

import json
import os
import sys
import tempfile
import unittest
from datetime import datetime
from io import StringIO
from unittest.mock import MagicMock, patch

from search_vulns.cli.main import _read_query_file, main, parse_args
from search_vulns.models.SearchVulnsResult import (
    PotProductIDsResult,
    ProductIDsResult,
    SearchVulnsResult,
    VersionStatusResult,
)
from search_vulns.models.Severity import SeverityCVSS, SeverityType
from search_vulns.models.Vulnerability import (
    DataSource,
    Match,
    MatchReason,
    Vulnerability,
)

# ------------------------------------------------ fixtures
_DUMMY_CONFIG = {"DATABASE_CONNECTION": "none"}


def _make_vuln(vid="CVE-FAKE", cvss_score="7.5"):
    return Vulnerability(
        id=vid,
        match_reason=MatchReason.VERSION_IN_RANGE,
        tracked_by={DataSource.NVD: f"https://nvd.nist.gov/vuln/detail/{vid}"},
        matched_by={
            DataSource.NVD: Match(match_reason=MatchReason.VERSION_IN_RANGE, confidence=1.0)
        },
        description="Test vulnerability",
        severity={
            SeverityType.CVSS: SeverityCVSS(
                score=cvss_score,
                version="3.1",
                vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            )
        },
        aliases={vid: f"https://nvd.nist.gov/vuln/detail/{vid}"},
        published=datetime(2024, 1, 1),
    )


def _make_search_result(n_vulns=3):
    vulns = {}
    for i in range(n_vulns):
        vid = f"CVE-2024-{i:04d}"
        score = str(round(max(0.1, 10.0 - i * 0.5), 1))
        vulns[vid] = _make_vuln(vid, score)
    return SearchVulnsResult(
        product_ids=ProductIDsResult(cpe=["cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"]),
        pot_product_ids=PotProductIDsResult(),
        vulns=vulns,
        version_status=VersionStatusResult(),
    )


def _mock_backend(search_result=None, is_good=True):
    backend = MagicMock()
    if search_result is None:
        search_result = _make_search_result()
    backend.search.return_value = (is_good, search_result)
    return backend


def _run_main(argv, backend=None):
    if backend is None:
        backend = _mock_backend()
    captured = StringIO()
    with (
        patch("sys.argv", ["search_vulns"] + argv),
        patch("search_vulns.cli.main._load_config", return_value=_DUMMY_CONFIG),
        patch("search_vulns.cli.main.select_backend", return_value=backend),
        patch("sys.stdout", captured),
    ):
        main()
    return captured.getvalue()


# ------------------------------------------------ arg parsing
class TestArgParsing(unittest.TestCase):
    def _parse(self, argv):
        with patch("sys.argv", ["search_vulns"] + argv):
            return parse_args()

    def test_api_key_parsed(self):
        args = self._parse(["--api-key", "abc", "-q", "test"])
        self.assertEqual(args.api_key, "abc")

    def test_api_url_parsed(self):
        args = self._parse(["--api-url", "https://x.com/api/", "--api-key", "k", "-q", "test"])
        self.assertEqual(args.api_url, "https://x.com/api/")

    def test_api_url_default_none(self):
        args = self._parse(["-q", "test"])
        self.assertIsNone(args.api_url)

    def test_query_file_parsed(self):
        args = self._parse(["--query-file", "f.txt"])
        self.assertEqual(args.query_file, "f.txt")

    def test_interactive_flag(self):
        args = self._parse(["-i"])
        self.assertTrue(args.interactive)

    def test_vuln_count_parsed(self):
        args = self._parse(["--vuln-count", "5", "-q", "test"])
        self.assertEqual(args.vuln_count, 5)

    def test_md_cols_parsed(self):
        args = self._parse(["--md-cols", "id,epss,cwe", "-q", "test"])
        self.assertEqual(args.md_cols, "id,epss,cwe")

    def test_format_ansi(self):
        args = self._parse(["-f", "ansi", "-q", "test"])
        self.assertEqual(args.format, "ansi")

    def test_format_md(self):
        args = self._parse(["-f", "md", "-q", "test"])
        self.assertEqual(args.format, "md")

    @patch("sys.stderr", new_callable=StringIO)
    def test_format_rejects_invalid(self, mock_stderr):
        with self.assertRaises(SystemExit):
            self._parse(["-f", "invalid", "-q", "test"])
        self.assertIn("invalid choice: 'invalid'", mock_stderr.getvalue())

    def test_existing_flags_unchanged(self):
        self.assertTrue(self._parse(["-u"]).update)
        self.assertTrue(self._parse(["--full-update"]).full_update)
        self.assertTrue(self._parse(["-V"]).version)


# ------------------------------------------------ query file reading
class TestQueryFileReading(unittest.TestCase):
    def _write_tmp(self, content):
        f = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
        f.write(content)
        f.close()
        return f.name

    def test_reads_lines(self):
        path = self._write_tmp("query1\nquery2\nquery3\n")
        try:
            self.assertEqual(_read_query_file(path), ["query1", "query2", "query3"])
        finally:
            os.unlink(path)

    def test_skips_blank_lines(self):
        path = self._write_tmp("query1\n\nquery2\n\n\n")
        try:
            self.assertEqual(_read_query_file(path), ["query1", "query2"])
        finally:
            os.unlink(path)

    def test_skips_comments(self):
        path = self._write_tmp("# comment\nquery1\n# another\nquery2\n")
        try:
            self.assertEqual(_read_query_file(path), ["query1", "query2"])
        finally:
            os.unlink(path)

    def test_strips_whitespace(self):
        path = self._write_tmp("  query1  \n  query2\n")
        try:
            self.assertEqual(_read_query_file(path), ["query1", "query2"])
        finally:
            os.unlink(path)

    @patch("builtins.print")
    def test_missing_file_exits(self, mock_print):
        with self.assertRaises(SystemExit):
            _read_query_file("/nonexistent/path/file.txt")
        mock_print.assert_called_with(
            "Error: Cannot read query file '/nonexistent/path/file.txt': [Errno 2] No such file or directory: '/nonexistent/path/file.txt'",
            file=sys.stderr,
        )

    def test_empty_file(self):
        path = self._write_tmp("# only comments\n\n")
        try:
            self.assertEqual(_read_query_file(path), [])
        finally:
            os.unlink(path)

    def test_combined_with_cli_queries(self):
        path = self._write_tmp("C\nD\n")
        try:
            with patch(
                "sys.argv", ["search_vulns", "-q", "A", "-q", "B", "--query-file", path]
            ):
                args = parse_args()
            queries = list(args.queries or [])
            queries.extend(_read_query_file(path))
            self.assertEqual(queries, ["A", "B", "C", "D"])
        finally:
            os.unlink(path)


# ------------------------------------------------ vuln count integration
class TestVulnCountIntegration(unittest.TestCase):
    def test_vuln_count_caps_output(self):
        backend = _mock_backend(search_result=_make_search_result(20))
        output = _run_main(["-f", "json", "--vuln-count", "5", "-q", "test"], backend)
        data = json.loads(output)
        self.assertEqual(len(data["test"]["vulns"]), 5)

    def test_vuln_count_preserves_top(self):
        backend = _mock_backend(search_result=_make_search_result(10))
        output = _run_main(["-f", "json", "--vuln-count", "3", "-q", "test"], backend)
        data = json.loads(output)
        vuln_ids = list(data["test"]["vulns"].keys())
        self.assertIn("CVE-2024-0000", vuln_ids)

    def test_no_vuln_count_passes_all(self):
        backend = _mock_backend(search_result=_make_search_result(10))
        output = _run_main(["-f", "json", "-q", "test"], backend)
        data = json.loads(output)
        self.assertEqual(len(data["test"]["vulns"]), 10)


# ------------------------------------------------ output routing
class TestOutputRouting(unittest.TestCase):
    def test_txt_to_stdout(self):
        output = _run_main(["-f", "txt", "-q", "test"])
        self.assertIn("[+] test (", output)
        self.assertIn("CVE-", output)

    def test_txt_to_file(self):
        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f:
            path = f.name
        try:
            _run_main(["-f", "txt", "-o", path, "-q", "test"])
            with open(path) as f:
                content = f.read()
            self.assertIn("[+] test (", content)
            self.assertIn("CVE-", content)
        finally:
            os.unlink(path)

    def test_json_to_stdout(self):
        output = _run_main(["-f", "json", "-q", "test"])
        data = json.loads(output)
        self.assertIn("test", data)
        self.assertIn("vulns", data["test"])

    def test_json_to_file(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name
        try:
            _run_main(["-f", "json", "-o", path, "-q", "test"])
            with open(path) as f:
                data = json.loads(f.read())
            self.assertIn("test", data)
        finally:
            os.unlink(path)

    def test_ansi_to_stdout_has_colors(self):
        output = _run_main(["-f", "ansi", "-q", "test"])
        self.assertIn("\033[", output)

    def test_ansi_to_file_no_colors(self):
        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f:
            path = f.name
        try:
            _run_main(["-f", "ansi", "-o", path, "-q", "test"])
            with open(path) as f:
                content = f.read()
            self.assertNotIn("\033[", content)
            self.assertIn("CVE-", content)
        finally:
            os.unlink(path)

    def test_md_to_stdout(self):
        output = _run_main(["-f", "md", "-q", "test"])
        self.assertTrue(output.strip().startswith("---"))
        self.assertIn("|", output)

    def test_md_to_file(self):
        with tempfile.NamedTemporaryFile(suffix=".md", delete=False) as f:
            path = f.name
        try:
            _run_main(["-f", "md", "-o", path, "-q", "test"])
            with open(path) as f:
                content = f.read()
            self.assertIn("---", content)
            self.assertIn("|", content)
        finally:
            os.unlink(path)

    def test_md_multiple_queries(self):
        output = _run_main(["-f", "md", "-q", "test1", "-q", "test2"])
        self.assertEqual(output.count('cpe: "'), 2)


# ------------------------------------------------ interactive mode
class TestInteractiveMode(unittest.TestCase):
    def test_interactive_dispatches(self):
        with (
            patch("sys.argv", ["search_vulns", "-i"]),
            patch("search_vulns.cli.main._load_config", return_value=_DUMMY_CONFIG),
            patch("search_vulns.cli.main.select_backend", return_value=_mock_backend()),
            patch("search_vulns.cli.main.run_interactive_loop") as mock_loop,
        ):
            main()
        mock_loop.assert_called_once()

    def test_interactive_seed_queries(self):
        with (
            patch("sys.argv", ["search_vulns", "-i", "-q", "Apache"]),
            patch("search_vulns.cli.main._load_config", return_value=_DUMMY_CONFIG),
            patch("search_vulns.cli.main.select_backend", return_value=_mock_backend()),
            patch("search_vulns.cli.main.run_interactive_loop") as mock_loop,
        ):
            main()
        call_kwargs = mock_loop.call_args[1]
        self.assertEqual(call_kwargs["seed_queries"], ["Apache"])

    def test_interactive_default_format_ansi(self):
        with (
            patch("sys.argv", ["search_vulns", "-i"]),
            patch("search_vulns.cli.main._load_config", return_value=_DUMMY_CONFIG),
            patch("search_vulns.cli.main.select_backend", return_value=_mock_backend()),
            patch("search_vulns.cli.main.run_interactive_loop") as mock_loop,
        ):
            main()

        call_kwargs = mock_loop.call_args[1]
        render_fn = call_kwargs["render_result"]

        with (
            patch("search_vulns.cli.main.format_ansi", return_value="ansi") as mock_ansi,
            patch("sys.stdout", StringIO()),
        ):
            render_fn("test", _make_search_result())
        mock_ansi.assert_called_once()

    def test_interactive_explicit_format_md(self):
        with (
            patch("sys.argv", ["search_vulns", "-i", "-f", "md"]),
            patch("search_vulns.cli.main._load_config", return_value=_DUMMY_CONFIG),
            patch("search_vulns.cli.main.select_backend", return_value=_mock_backend()),
            patch("search_vulns.cli.main.run_interactive_loop") as mock_loop,
        ):
            main()

        call_kwargs = mock_loop.call_args[1]
        render_fn = call_kwargs["render_result"]

        with (
            patch("search_vulns.cli.main.format_md", return_value="md") as mock_md,
            patch("sys.stdout", StringIO()),
        ):
            render_fn("test", _make_search_result())
        mock_md.assert_called_once()

    def test_interactive_search_kwargs(self):
        with (
            patch("sys.argv", ["search_vulns", "-i", "--ignore-general-product-vulns"]),
            patch("search_vulns.cli.main._load_config", return_value=_DUMMY_CONFIG),
            patch("search_vulns.cli.main.select_backend", return_value=_mock_backend()),
            patch("search_vulns.cli.main.run_interactive_loop") as mock_loop,
        ):
            main()
        call_kwargs = mock_loop.call_args[1]
        self.assertTrue(call_kwargs["search_kwargs"]["ignore_general_product_vulns"])


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3

import json
import unittest
from datetime import datetime

from search_vulns.cli_formatters import (
    ALLOWED_MD_COLS,
    format_ansi,
    format_json_batch,
    format_md,
    parse_md_cols,
    print_vulns,
    score_bar,
    sort_and_cap_vulns,
    strip_ansi,
)
from search_vulns.models.SearchVulnsResult import (
    PotProductIDsResult,
    ProductIDsResult,
    SearchVulnsResult,
    VersionStatus,
    VersionStatusResult,
)
from search_vulns.models.Severity import SeverityCVSS, SeverityEPSS, SeverityType
from search_vulns.models.Vulnerability import (
    DataSource,
    Match,
    MatchReason,
    Vulnerability,
)


# ------------------------------------------------ fixture helper
def _make_vuln(
    vid="CVE-2024-0001",
    cvss=7.5,
    cvss_ver="3.1",
    epss=0.5,
    desc="Test vulnerability",
    cisa_kev=False,
    exploits=None,
    cwe_ids=None,
    published=None,
):
    severity = {}
    if cvss >= 0:
        severity[SeverityType.CVSS] = SeverityCVSS(
            score=str(cvss),
            version=str(cvss_ver),
            vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        )
    if epss > 0:
        severity[SeverityType.EPSS] = SeverityEPSS(score=str(epss))

    return Vulnerability(
        id=vid,
        match_reason=MatchReason.VERSION_IN_RANGE,
        tracked_by={DataSource.NVD: f"https://nvd.nist.gov/vuln/detail/{vid}"},
        matched_by={
            DataSource.NVD: Match(match_reason=MatchReason.VERSION_IN_RANGE, confidence=1.0)
        },
        description=desc,
        severity=severity,
        cisa_kev=cisa_kev,
        exploits=set(exploits or []),
        cwe_ids=set(cwe_ids or []),
        aliases={vid: f"https://nvd.nist.gov/vuln/detail/{vid}"},
        published=published or datetime(2024, 1, 15, 0, 0, 0),
    )


def _make_result(vulns=None, cpes=None, version_status=None, pot_cpes=None):
    return SearchVulnsResult(
        product_ids=ProductIDsResult(cpe=cpes or []),
        pot_product_ids=PotProductIDsResult(cpe=pot_cpes or []),
        vulns={v.id: v for v in (vulns or [])},
        version_status=version_status or VersionStatusResult(),
    )


# ------------------------------------------------ sort_and_cap_vulns
class TestSortAndCap(unittest.TestCase):
    def _vulns_dict(self, specs):
        return {v.id: v for v in [_make_vuln(vid=s[0], cvss=s[1], epss=s[2]) for s in specs]}

    def test_sort_by_cvss_desc(self):
        vulns = self._vulns_dict(
            [
                ("CVE-A", 9.8, 0.1),
                ("CVE-B", 4.0, 0.1),
                ("CVE-C", 7.5, 0.1),
                ("CVE-D", 0.0, 0.0),
                ("CVE-E", 6.1, 0.1),
            ]
        )
        result = sort_and_cap_vulns(vulns, None)
        ids = list(result.keys())
        self.assertEqual(ids, ["CVE-A", "CVE-C", "CVE-E", "CVE-B", "CVE-D"])

    def test_sort_secondary_epss(self):
        vulns = self._vulns_dict([("CVE-A", 7.5, 0.3), ("CVE-B", 7.5, 0.9)])
        result = sort_and_cap_vulns(vulns, None)
        ids = list(result.keys())
        self.assertEqual(ids[0], "CVE-B")

    def test_sort_tertiary_id(self):
        vulns = self._vulns_dict([("CVE-B", 7.5, 0.5), ("CVE-A", 7.5, 0.5)])
        result = sort_and_cap_vulns(vulns, None)
        ids = list(result.keys())
        self.assertEqual(ids, ["CVE-A", "CVE-B"])

    def test_cap_truncates(self):
        vulns = self._vulns_dict([(f"CVE-{i}", float(i), 0.1) for i in range(10)])
        result = sort_and_cap_vulns(vulns, 3)
        self.assertEqual(len(result), 3)

    def test_cap_none_returns_all(self):
        vulns = self._vulns_dict([(f"CVE-{i}", float(i), 0.1) for i in range(5)])
        result = sort_and_cap_vulns(vulns, None)
        self.assertEqual(len(result), 5)

    def test_cap_zero_returns_empty(self):
        vulns = self._vulns_dict([("CVE-A", 7.5, 0.5)])
        result = sort_and_cap_vulns(vulns, 0)
        self.assertEqual(len(result), 0)

    def test_empty_vulns(self):
        result = sort_and_cap_vulns({}, None)
        self.assertEqual(result, {})


# ------------------------------------------------ format_md
class TestFormatMd(unittest.TestCase):
    def test_default_cols(self):
        result = _make_result([_make_vuln()])
        out = format_md(result, list(ALLOWED_MD_COLS[:3]))
        lines = out.strip().split("\n")
        header_line = [l for l in lines if l.startswith("| Vuln")][0]
        self.assertIn("Vuln ID", header_line)
        self.assertIn("CVSS", header_line)
        self.assertIn("Description", header_line)

    def test_all_cols(self):
        result = _make_result(
            [_make_vuln(cwe_ids=["CWE-79"], exploits=["https://exploit.example"])]
        )
        out = format_md(result, list(ALLOWED_MD_COLS))
        header_line = [l for l in out.split("\n") if l.startswith("| Vuln")][0]
        for col_name in ("Vuln ID", "CVSS", "Description", "EPSS", "CWE", "Exploits"):
            self.assertIn(col_name, header_line)

    def test_frontmatter_from_cpe(self):
        result = _make_result(
            [_make_vuln()],
            cpes=["cpe:2.3:a:apache:tomcat:9.0.22:*:*:*:*:*:*:*"],
        )
        out = format_md(result, ["id"])
        self.assertIn('cpe: "cpe:2.3:a:apache:tomcat:9.0.22', out)
        self.assertIn('product: "Tomcat"', out)
        self.assertIn('version: "9.0.22"', out)

    def test_frontmatter_no_cpe(self):
        result = _make_result([_make_vuln()])
        out = format_md(result, ["id"])
        self.assertIn("---", out)
        self.assertIn('cpe: ""', out)

    def test_pipe_escaping(self):
        result = _make_result([_make_vuln(desc="a | b")])
        out = format_md(result, ["description"])
        data_lines = [
            l
            for l in out.split("\n")
            if l.startswith("|") and "Description" not in l and ":---" not in l
        ]
        self.assertTrue(any("a \\| b" in l for l in data_lines))

    def test_newline_escaping(self):
        result = _make_result([_make_vuln(desc="line1\nline2")])
        out = format_md(result, ["description"])
        data_lines = [
            l
            for l in out.split("\n")
            if l.startswith("|") and "Description" not in l and ":---" not in l
        ]
        self.assertTrue(any("line1 line2" in l for l in data_lines))

    def test_cvss_cell(self):
        result = _make_result([_make_vuln(cvss=8.8, cvss_ver="3.1")])
        out = format_md(result, ["cvss"])
        self.assertIn("8.8 (v3.1)", out)

    def test_cvss_cell_missing(self):
        v = _make_vuln(cvss=-1)
        v.severity = {}
        result = _make_result([v])
        out = format_md(result, ["cvss"])
        data_lines = [
            l
            for l in out.split("\n")
            if l.startswith("|") and "CVSS" not in l and ":---" not in l
        ]
        self.assertTrue(any("| - |" in l for l in data_lines))

    def test_epss_cell(self):
        result = _make_result([_make_vuln(epss=0.84)])
        out = format_md(result, ["epss"])
        self.assertIn("0.84", out)

    def test_epss_cell_zero(self):
        result = _make_result([_make_vuln(epss=0)])
        out = format_md(result, ["epss"])
        data_lines = [
            l
            for l in out.split("\n")
            if l.startswith("|") and "EPSS" not in l and ":---" not in l
        ]
        self.assertTrue(any("| - |" in l for l in data_lines))

    def test_cwe_cell(self):
        result = _make_result([_make_vuln(cwe_ids=["CWE-89", "CWE-79"])])
        out = format_md(result, ["cwe"])
        self.assertIn("CWE-79, CWE-89", out)

    def test_exploits_cell(self):
        result = _make_result([_make_vuln(exploits=["http://a", "http://b", "http://c"])])
        out = format_md(result, ["exploits"])
        self.assertIn("3", out)

    def test_id_cell_with_link(self):
        result = _make_result([_make_vuln(vid="CVE-2024-1234")])
        out = format_md(result, ["id"])
        self.assertIn("[CVE-2024-1234](https://nvd.nist.gov/vuln/detail/CVE-2024-1234)", out)

    def test_empty_vulns_produces_header_only(self):
        result = _make_result([])
        out = format_md(result, ["id", "cvss", "description"])
        lines = [l for l in out.strip().split("\n") if l.startswith("|")]
        self.assertEqual(len(lines), 2)  # header + alignment

    def test_multiple_queries_separated(self):
        r1 = _make_result([_make_vuln(vid="CVE-A")], cpes=["cpe:2.3:a:v:p:1:*:*:*:*:*:*:*"])
        r2 = _make_result([_make_vuln(vid="CVE-B")], cpes=["cpe:2.3:a:v:q:2:*:*:*:*:*:*:*"])
        out1 = format_md(r1, ["id"])
        out2 = format_md(r2, ["id"])
        combined = out1 + "\n\n" + out2
        self.assertIn('cpe: "cpe:2.3:a:v:p:1', combined)
        self.assertIn('cpe: "cpe:2.3:a:v:q:2', combined)
        self.assertEqual(combined.count('cpe: "cpe:2.3:'), 2)


# ------------------------------------------------ parse_md_cols
class TestParseMdCols(unittest.TestCase):
    def test_valid_subset(self):
        self.assertEqual(parse_md_cols("id,epss"), ["id", "epss"])

    def test_default_string(self):
        self.assertEqual(parse_md_cols("id,cvss,description"), ["id", "cvss", "description"])

    def test_invalid_col_rejected(self):
        with self.assertRaises(ValueError):
            parse_md_cols("id,foobar")

    def test_whitespace_tolerant(self):
        self.assertEqual(parse_md_cols(" id , cvss "), ["id", "cvss"])

    def test_duplicate_deduped(self):
        self.assertEqual(parse_md_cols("id,id,cvss"), ["id", "cvss"])


# ------------------------------------------------ format_ansi
class TestFormatAnsi(unittest.TestCase):
    def test_severity_grouping(self):
        vulns = [
            _make_vuln(vid="CVE-CRIT", cvss=9.5),
            _make_vuln(vid="CVE-MED", cvss=5.0),
            _make_vuln(vid="CVE-LOW", cvss=2.0),
        ]
        out = format_ansi("test", _make_result(vulns))
        plain = strip_ansi(out)
        self.assertIn("CRITICAL", plain)
        self.assertIn("MEDIUM", plain)
        self.assertIn("LOW", plain)

    def test_kev_badge(self):
        out = format_ansi("test", _make_result([_make_vuln(cisa_kev=True)]))
        plain = strip_ansi(out)
        self.assertIn("KEV", plain)

    def test_exploit_badge(self):
        out = format_ansi("test", _make_result([_make_vuln(exploits=["http://a", "http://b"])]))
        plain = strip_ansi(out)
        self.assertIn("EXP x2", plain)

    def test_version_status_banner(self):
        vs = VersionStatusResult(status=VersionStatus.OUTDATED, latest="9.0.98")
        out = format_ansi("test", _make_result([], version_status=vs))
        plain = strip_ansi(out)
        self.assertIn("OUTDATED", plain)
        self.assertIn("9.0.98", plain)

    def test_no_vulns_message(self):
        out = format_ansi("test", _make_result([]))
        plain = strip_ansi(out)
        self.assertIn("No vulnerabilities found", plain)

    def test_color_false_strips_ansi(self):
        out = format_ansi("test", _make_result([_make_vuln()]), color=False)
        self.assertNotIn("\033[", out)

    def test_description_truncation(self):
        long_desc = "A" * 200
        out = format_ansi("test", _make_result([_make_vuln(desc=long_desc)]))
        plain = strip_ansi(out)
        self.assertIn("...", plain)
        self.assertNotIn("A" * 200, plain)


# ------------------------------------------------ format_json_batch
class TestFormatJsonBatch(unittest.TestCase):
    def test_valid_json(self):
        results = {"q1": _make_result([_make_vuln()])}
        out = format_json_batch(results)
        parsed = json.loads(out)
        self.assertIsInstance(parsed, dict)

    def test_keys_are_queries(self):
        results = {"query_a": _make_result(), "query_b": _make_result()}
        out = format_json_batch(results)
        parsed = json.loads(out)
        self.assertIn("query_a", parsed)
        self.assertIn("query_b", parsed)

    def test_result_structure(self):
        results = {"q": _make_result([_make_vuln()])}
        out = format_json_batch(results)
        parsed = json.loads(out)
        self.assertIn("product_ids", parsed["q"])
        self.assertIn("vulns", parsed["q"])

    def test_warning_for_bad_result(self):
        results = {"q": "Warning: Could not find matching software for query"}
        out = format_json_batch(results)
        parsed = json.loads(out)
        self.assertIsInstance(parsed["q"], str)


# ------------------------------------------------ print_vulns
class TestPrintVulns(unittest.TestCase):
    def test_to_string_returns_text(self):
        vulns = {v.id: v for v in [_make_vuln(vid="CVE-2024-1111")]}
        out = print_vulns(vulns, to_string=True)
        self.assertIsNotNone(out)
        self.assertIn("CVE-2024-1111", out)  # type: ignore[arg-type]

    def test_to_string_no_ansi(self):
        vulns = {v.id: v for v in [_make_vuln()]}
        out = print_vulns(vulns, to_string=True)
        self.assertIsNotNone(out)
        self.assertNotIn("\033[", out)  # type: ignore[arg-type]

    def test_exploit_display(self):
        vulns = {v.id: v for v in [_make_vuln(exploits=["http://exploit1", "http://exploit2"])]}
        out = print_vulns(vulns, to_string=True)
        self.assertIsNotNone(out)
        self.assertIn("http://exploit1", out)  # type: ignore[arg-type]
        self.assertIn("http://exploit2", out)  # type: ignore[arg-type]

    def test_published_date(self):
        vulns = {v.id: v for v in [_make_vuln(published=datetime(2024, 3, 15))]}
        out = print_vulns(vulns, to_string=True)
        self.assertIsNotNone(out)
        self.assertIn("2024-03-15", out)  # type: ignore[arg-type]

    def test_kev_label(self):
        vulns = {v.id: v for v in [_make_vuln(cisa_kev=True)]}
        out = print_vulns(vulns, to_string=True)
        self.assertIsNotNone(out)
        self.assertIn("Actively exploited", out)  # type: ignore[arg-type]


# ------------------------------------------------ score_bar
class TestScoreBar(unittest.TestCase):
    def test_full_score(self):
        bar = strip_ansi(score_bar(1.0, width=12))
        self.assertEqual(bar.count("█"), 12)
        self.assertEqual(bar.count("░"), 0)

    def test_zero_score(self):
        bar = strip_ansi(score_bar(0.0, width=12))
        self.assertEqual(bar.count("█"), 0)
        self.assertEqual(bar.count("░"), 12)

    def test_mid_score(self):
        bar = strip_ansi(score_bar(0.5, width=12))
        self.assertGreater(bar.count("█"), 0)
        self.assertGreater(bar.count("░"), 0)

    def test_negative_score_uses_abs(self):
        bar_pos = strip_ansi(score_bar(0.8, width=12))
        bar_neg = strip_ansi(score_bar(-0.8, width=12))
        self.assertEqual(bar_pos.count("█"), bar_neg.count("█"))


if __name__ == "__main__":
    unittest.main()

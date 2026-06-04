#!/usr/bin/env python3

import unittest
from datetime import datetime
from unittest.mock import MagicMock, patch

from search_vulns.cli.interactive import (
    _gather_suggestions,
    _pick_from_menu,
    run_interactive_loop,
)
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
def _make_vuln(vid="CVE-FAKE"):
    return Vulnerability(
        id=vid,
        match_reason=MatchReason.VERSION_IN_RANGE,
        tracked_by={DataSource.NVD: f"https://nvd.nist.gov/vuln/detail/{vid}"},
        matched_by={
            DataSource.NVD: Match(match_reason=MatchReason.VERSION_IN_RANGE, confidence=1.0)
        },
        description="Test",
        severity={
            SeverityType.CVSS: SeverityCVSS(
                score="7.5",
                version="3.1",
                vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            )
        },
        aliases={vid: f"https://nvd.nist.gov/vuln/detail/{vid}"},
        published=datetime(2024, 1, 1),
    )


def _make_result(cpes=None, pot_cpes=None, purls=None, pot_purls=None):
    return SearchVulnsResult(
        product_ids=ProductIDsResult(cpe=cpes or [], purl=purls or []),
        pot_product_ids=PotProductIDsResult(
            cpe=pot_cpes or [],
            purl=pot_purls or [],
        ),
        vulns={},
        version_status=VersionStatusResult(),
    )


def _make_search_result():
    v = _make_vuln()
    return SearchVulnsResult(
        product_ids=ProductIDsResult(cpe=["cpe:2.3:a:v:p:1:*:*:*:*:*:*:*"]),
        pot_product_ids=PotProductIDsResult(),
        vulns={v.id: v},
        version_status=VersionStatusResult(),
    )


def _mock_backend(suggest_result=None, search_result=None):
    backend = MagicMock()
    backend.suggest.return_value = suggest_result or _make_result(
        pot_cpes=[("cpe:2.3:a:apache:tomcat:9.0.22:*:*:*:*:*:*:*", 0.95)]
    )
    backend.search.return_value = search_result or (True, _make_search_result())
    return backend


# ------------------------------------------------ _gather_suggestions
class TestGatherSuggestions(unittest.TestCase):
    def test_exact_cpes_first(self):
        result = _make_result(
            cpes=["cpe:exact"],
            pot_cpes=[("cpe:exact", 0.8), ("cpe:fuzzy", 0.8)],
        )
        items = _gather_suggestions(result)
        self.assertEqual(items[0][0], "cpe:exact")
        self.assertEqual(items[0][1], 0.8)

    def test_pot_sorted_by_score(self):
        result = _make_result(
            pot_cpes=[("cpe:low", 0.3), ("cpe:high", 0.9)],
        )
        items = _gather_suggestions(result)
        self.assertEqual(items[0][0], "cpe:high")

    def test_deduplicates(self):
        result = _make_result(
            cpes=["cpe:dup"],
            pot_cpes=[("cpe:dup", 0.9)],
        )
        items = _gather_suggestions(result)
        ids = [i[0] for i in items]
        self.assertEqual(ids.count("cpe:dup"), 1)

    def test_empty_result(self):
        result = _make_result()
        items = _gather_suggestions(result)
        self.assertEqual(items, [])

    def test_mixed_kinds(self):
        result = _make_result(
            cpes=["cpe:b"],
            purls=["pkg:npm/foo"],
            pot_cpes=[("cpe:b", 0.5)],
            pot_purls=[("pkg:npm/foo", 0.4)],
        )
        items = _gather_suggestions(result)
        kinds = {i[2] for i in items}
        self.assertIn("cpe", kinds)
        self.assertIn("purl", kinds)


# ------------------------------------------------ _pick_from_menu
class TestPickFromMenu(unittest.TestCase):
    def test_empty_items_returns_none(self):
        self.assertIsNone(_pick_from_menu([]))

    @patch("builtins.print")
    @patch("search_vulns.cli.interactive._prompt", return_value="1")
    def test_valid_selection(self, *_):
        items = [("cpe:a", 0.9, "cpe"), ("cpe:b", 0.8, "cpe")]
        result = _pick_from_menu(items)
        self.assertEqual(result, "cpe:a")

    @patch("builtins.print")
    @patch("search_vulns.cli.interactive._prompt", return_value="0")
    def test_zero_skips(self, *_):
        items = [("cpe:a", 0.9, "cpe")]
        result = _pick_from_menu(items)
        self.assertIsNone(result)

    @patch("builtins.print")
    @patch("search_vulns.cli.interactive._prompt", return_value="q")
    def test_quit_returns_none(self, *_):
        items = [("cpe:a", 0.9, "cpe")]
        result = _pick_from_menu(items)
        self.assertIsNone(result)

    @patch("builtins.print")
    @patch("search_vulns.cli.interactive._prompt", side_effect=["abc", "1"])
    def test_invalid_then_valid(self, *_):
        items = [("cpe:a", 0.9, "cpe")]
        result = _pick_from_menu(items)
        self.assertEqual(result, "cpe:a")


# ------------------------------------------------ run_interactive_loop
class TestRunInteractiveLoop(unittest.TestCase):
    @patch("search_vulns.cli.interactive._prompt", return_value="q")
    def test_quit_on_q(self, _):
        backend = _mock_backend()
        render = MagicMock()
        run_interactive_loop(backend, render_result=render, search_kwargs={})
        backend.suggest.assert_not_called()
        render.assert_not_called()

    @patch("search_vulns.cli.interactive._prompt", return_value="exit")
    def test_quit_on_exit(self, _):
        backend = _mock_backend()
        render = MagicMock()
        run_interactive_loop(backend, render_result=render, search_kwargs={})
        backend.suggest.assert_not_called()

    @patch("builtins.print")
    @patch("builtins.input", side_effect=EOFError)
    def test_quit_on_eof(self, *_):
        backend = _mock_backend()
        render = MagicMock()
        run_interactive_loop(backend, render_result=render, search_kwargs={})
        backend.suggest.assert_not_called()

    @patch("builtins.print")
    @patch(
        "search_vulns.cli.interactive._pick_from_menu",
        return_value="cpe:2.3:a:apache:tomcat:9.0.22:*:*:*:*:*:*:*",
    )
    @patch("search_vulns.cli.interactive._prompt", side_effect=["q"])
    def test_seed_queries_consumed_first(self, *_):
        backend = _mock_backend()
        render = MagicMock()
        run_interactive_loop(
            backend,
            seed_queries=["Apache 2.4"],
            render_result=render,
            search_kwargs={},
        )
        backend.suggest.assert_called_once_with("Apache 2.4")
        render.assert_called_once()

    @patch("builtins.print")
    @patch(
        "search_vulns.cli.interactive._pick_from_menu",
        return_value="cpe:2.3:a:apache:tomcat:9.0.22:*:*:*:*:*:*:*",
    )
    @patch("search_vulns.cli.interactive._prompt", side_effect=["q"])
    def test_render_result_called(self, *_):
        backend = _mock_backend()
        render = MagicMock()
        run_interactive_loop(
            backend,
            seed_queries=["test"],
            render_result=render,
            search_kwargs={},
        )
        render.assert_called_once()
        args = render.call_args[0]
        self.assertEqual(args[0], "test")

    @patch("builtins.print")
    @patch("search_vulns.cli.interactive._pick_from_menu", return_value=None)
    @patch("search_vulns.cli.interactive._prompt", side_effect=["q"])
    def test_menu_skip_no_search(self, *_):
        backend = _mock_backend()
        render = MagicMock()
        run_interactive_loop(
            backend,
            seed_queries=["test"],
            render_result=render,
            search_kwargs={},
        )
        backend.search.assert_not_called()
        render.assert_not_called()

    @patch("builtins.print")
    @patch("search_vulns.cli.interactive._prompt", side_effect=["Apache 2.4", "1", "q"])
    def test_prompts_for_query(self, *_):
        backend = _mock_backend()
        render = MagicMock()
        run_interactive_loop(backend, render_result=render, search_kwargs={})
        backend.suggest.assert_called_once_with("Apache 2.4")

    @patch("builtins.print")
    @patch("search_vulns.cli.interactive._pick_from_menu", return_value="cpe:x")
    @patch("search_vulns.cli.interactive._prompt", side_effect=["q"])
    def test_search_kwargs_passed(self, *_):
        backend = _mock_backend()
        render = MagicMock()
        run_interactive_loop(
            backend,
            seed_queries=["test"],
            render_result=render,
            search_kwargs={"ignore_general_product_vulns": True},
        )
        call_kwargs = backend.search.call_args
        self.assertTrue(call_kwargs[1].get("ignore_general_product_vulns"))


if __name__ == "__main__":
    unittest.main()

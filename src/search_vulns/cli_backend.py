"""Backend abstraction for local DB and remote API searches"""

import json
import os
import sys

from typing import Protocol, Tuple
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen

from .models.SearchVulnsResult import (
    PotProductIDsResult,
    ProductIDsResult,
    SearchVulnsResult,
    VersionStatus,
    VersionStatusResult,
)
from .models.Severity import SeverityCVSS, SeverityEPSS, SeverityType
from .models.Vulnerability import DataSource, Match, MatchReason, Vulnerability

from .core import search_vulns
from .core import check_and_try_sv_rerun_with_created_cpes, search_vulns


DEFAULT_API_URL = "https://search-vulns.com/api/"


class ApiError(Exception):
    pass


class SearchBackend(Protocol):
    def suggest(self, query: str) -> SearchVulnsResult: ...
    def search(self, query: str, **kwargs) -> Tuple[bool, SearchVulnsResult]: ...


# ------------------------------------------------ local backend
class LocalBackend:
    def __init__(self, config: dict, cli_overrides: dict | None = None):
        self._config = config
        self._overrides = cli_overrides or {}

    def _apply_overrides(self, config: dict) -> dict:
        import copy
        cfg = copy.deepcopy(config)
        if "cpe_search_threshold" in self._overrides and self._overrides["cpe_search_threshold"]:
            cfg["MODULES"]["cpe_search.search_vulns_cpe_search"]["CPE_SEARCH_THRESHOLD"] = (
                self._overrides["cpe_search_threshold"]
            )
        cfg["MODULES"]["cpe_search.search_vulns_cpe_search"]["CPE_SEARCH_COUNT"] = 1
        return cfg

    def suggest(self, query: str) -> SearchVulnsResult:
        cfg = self._apply_overrides(self._config)
        return search_vulns(query, config=cfg, skip_vuln_search=True)

    def search(self, query: str, **kwargs) -> Tuple[bool, SearchVulnsResult]:
        cfg = self._apply_overrides(self._config)
        is_product_id = kwargs.get("is_good_product_id", False)

        sv_result = search_vulns(
            query,
            None,
            None,
            None,
            is_product_id,
            kwargs.get("ignore_general_product_vulns", False),
            kwargs.get("include_single_version_vulns", False),
            kwargs.get("include_patched", False),
            cfg,
        )

        is_good, sv_result = check_and_try_sv_rerun_with_created_cpes(
            query,
            sv_result,
            kwargs.get("ignore_general_product_vulns", False),
            kwargs.get("include_single_version_vulns", False),
            kwargs.get("include_patched", False),
            kwargs.get("use_created_product_ids", False),
            cfg,
        )
        return is_good, sv_result


# ------------------------------------------------ API backend
class ApiBackend:
    def __init__(self, api_key: str, api_url: str = DEFAULT_API_URL):
        self._api_key = api_key
        self._api_url = api_url.rstrip("/")

    def _api_get(self, endpoint: str, params: dict, *, fatal: bool = True) -> dict:
        qs = urlencode(params, quote_via=quote)
        url = f"{self._api_url}{endpoint}?{qs}"
        req = Request(url, headers={"API-Key": self._api_key})
        errmsg = None

        try:
            with urlopen(req, timeout=30) as resp:
                return json.loads(resp.read().decode())
        except HTTPError as exc:
            body = exc.read().decode()
            try:
                detail = json.loads(body)
                msg = detail.get("message") or detail.get("detail") or body
            except json.JSONDecodeError:
                msg = body
            errmsg = f"HTTP {exc.code}: {msg}"
        except URLError as exc:
            errmsg = f"Network error: {exc.reason}"

        if fatal:
            print(f"Error: {errmsg}", file=sys.stderr)
            sys.exit(1)
        raise ApiError(errmsg)

    def suggest(self, query: str) -> SearchVulnsResult:
        data = self._api_get("/product-id-suggestions", {"query": query})
        return _parse_api_result(data)

    def search(self, query: str, **kwargs) -> Tuple[bool, SearchVulnsResult]:
        params: dict = {"query": query}

        flag_map = {
            "ignore_general_product_vulns": "ignore-general-product-vulns",
            "include_single_version_vulns": "include-single-version-vulns",
            "include_patched": "include-patched",
            "use_created_product_ids": "use-created-product-ids",
            "is_good_product_id": "is-good-product-id",
        }
        for attr, param in flag_map.items():
            val = kwargs.get(attr)
            if val is not None:
                params[param] = str(val).lower()

        data = self._api_get("/search-vulns", params)
        result = _parse_api_result(data)
        is_good = bool(result.product_ids.get_all()) or bool(result.vulns)
        return is_good, result


# ------------------------------------------------ API response parsing
def _parse_severity(raw: dict) -> dict:
    severity = {}
    for _, entry in raw.items():
        stype = entry.get("type", "")
        if stype == "CVSS":
            severity[SeverityType.CVSS] = SeverityCVSS(
                score=str(entry.get("score", "0")),
                version=str(entry.get("version", "0")),
                vector=entry.get("vector", "n/a"),
            )
        elif stype == "EPSS":
            severity[SeverityType.EPSS] = SeverityEPSS(
                score=str(entry.get("score", "0")),
            )
    return severity


def _parse_vuln(vid: str, raw: dict) -> Vulnerability:
    tracked_by = {}
    for src, ref in raw.get("tracked_by", {}).items():
        try:
            tracked_by[DataSource(src)] = ref
        except ValueError:
            tracked_by[src] = ref

    matched_by = {}
    for src, match_data in raw.get("matched_by", {}).items():
        try:
            ds = DataSource(src)
        except ValueError:
            ds = src
        matched_by[ds] = Match(
            match_reason=MatchReason(match_data.get("match_reason", "n_a")),
            confidence=match_data.get("confidence", 1.0),
        )

    match_reason_str = raw.get("match_reason", "n_a")
    try:
        match_reason = MatchReason(match_reason_str)
    except ValueError:
        match_reason = MatchReason.N_A

    kwargs = dict(
        id=vid,
        match_reason=match_reason,
        tracked_by=tracked_by or {DataSource.OTHER: ""},
        matched_by=matched_by or {DataSource.OTHER: Match(match_reason=match_reason, confidence=1.0)},
        description=raw.get("description", ""),
        severity=_parse_severity(raw.get("severity", {})),
        cisa_kev=raw.get("cisa_kev", False),
        exploits=set(raw.get("exploits", [])),
        cwe_ids=set(raw.get("cwe_ids", [])),
        aliases=raw.get("aliases", {vid: ""}),
    )
    if raw.get("published"):
        kwargs["published"] = raw["published"]
    if raw.get("modified"):
        kwargs["modified"] = raw["modified"]

    return Vulnerability(**kwargs)


def _parse_api_result(data: dict) -> SearchVulnsResult:
    pids = data.get("product_ids", {})
    product_ids = ProductIDsResult(
        cpe=pids.get("cpe", []),
        purl=pids.get("purl", []),
        raw=pids.get("raw", []),
    )

    pot = data.get("pot_product_ids", {})
    pot_product_ids = PotProductIDsResult(
        cpe=[(e[0], e[1]) for e in pot.get("cpe", [])],
        purl=[(e[0], e[1]) for e in pot.get("purl", [])],
        raw=[(e[0], e[1]) for e in pot.get("raw", [])],
    )

    vulns = {}
    for vid, raw_vuln in data.get("vulns", {}).items():
        vulns[vid] = _parse_vuln(vid, raw_vuln)

    vs_data = data.get("version_status", {})
    vs_status = None
    if vs_data.get("status"):
        try:
            vs_status = VersionStatus(vs_data["status"])
        except ValueError:
            pass
    version_status = VersionStatusResult(
        status=vs_status,
        latest=vs_data.get("latest"),
        reference=vs_data.get("reference"),
    )

    return SearchVulnsResult(
        product_ids=product_ids,
        pot_product_ids=pot_product_ids,
        vulns=vulns,
        version_status=version_status,
    )


# ------------------------------------------------ backend selection
def select_backend(args, config: dict) -> SearchBackend:
    api_key = getattr(args, "api_key", None) or os.environ.get("SV_API_KEY")
    api_url = getattr(args, "api_url", None)

    if api_key or (api_url and api_url != DEFAULT_API_URL):
        if not api_key:
            print("Error: --api-url requires --api-key or SV_API_KEY env var.", file=sys.stderr)
            sys.exit(1)
        return ApiBackend(api_key, api_url or DEFAULT_API_URL)

    overrides = {}
    if hasattr(args, "cpe_search_threshold"):
        overrides["cpe_search_threshold"] = args.cpe_search_threshold
    return LocalBackend(config, overrides)

"""Backend abstraction for local DB and remote API searches"""

import json
import os
import sys
from typing import Protocol, Tuple
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen

from ..core import check_and_try_sv_rerun_with_created_cpes, search_vulns
from ..models.SearchVulnsResult import (
    SearchVulnsResult,
)

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
        if (
            "cpe_search_threshold" in self._overrides
            and self._overrides["cpe_search_threshold"]
        ):
            cfg["MODULES"]["cpe_search.search_vulns_cpe_search"]["CPE_SEARCH_THRESHOLD"] = (
                self._overrides["cpe_search_threshold"]
            )
        return cfg

    def suggest(self, query: str) -> SearchVulnsResult:
        cfg = self._apply_overrides(self._config)
        return search_vulns(query, config=cfg, skip_vuln_search=True)

    def search(self, query: str, **kwargs) -> Tuple[bool, SearchVulnsResult]:
        cfg = self._apply_overrides(self._config)

        # when searching vulns locally, only one CPE needs to be retrieved
        cfg["MODULES"]["cpe_search.search_vulns_cpe_search"]["CPE_SEARCH_COUNT"] = 1

        is_good_product_id = kwargs.get("is_good_product_id", False)

        sv_result = search_vulns(
            query,
            None,
            None,
            None,
            is_good_product_id,
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
        return SearchVulnsResult.model_validate(data)

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
        result = SearchVulnsResult.model_validate(data)
        is_good = bool(result.product_ids.get_all()) or bool(result.vulns)
        return is_good, result


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

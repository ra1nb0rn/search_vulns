from __future__ import annotations

from enum import Enum
from typing import Annotated, Dict, List, Literal, Optional, Tuple

from pydantic import BaseModel, Field, field_serializer

from .Vulnerability import Vulnerability


class ProductIDsResult(BaseModel):
    cpe: List[str] = Field(default_factory=list, description="A list of CPEs")
    purl: List[str] = Field(default_factory=list, description="A list of PURLs")
    raw: List[str] = Field(
        default_factory=list, description="A list of raw/different/other product IDs"
    )

    model_config = {
        "title": "search_vulns ProductID Result Model",
        "description": "Represents the result of search_vulns matching product IDs to a query",
    }

    @classmethod
    def from_cpes(cls, cpes: List[str]):
        return cls(cpe=cpes)

    @classmethod
    def from_purls(cls, purls: List[str]):
        return cls(purl=purls)

    @classmethod
    def from_raw(cls, raws: List[str]):
        return cls(raw=raws)

    def add_cpes(self, cpes: List[str]):
        self.cpe = list(set(self.cpe + cpes))

    def add_cpe(self, cpe: str):
        self.add_cpes([cpe])

    def add_purls(self, purls: List[str]):
        self.purl = list(set(self.purl + purls))

    def add_purl(self, purl: str):
        self.add_purls([purl])

    def add_raws(self, raws: List[str]):
        self.raw = list(set(self.raw + raws))

    def add_raw(self, raw: str):
        self.add_raws([raw])

    def get_all(self):
        return self.cpe + self.purl + self.raw

    def merge_with(self, other: ProductIDsResult):
        if not other:
            return
        if not isinstance(other, self.__class__):
            raise TypeError("Can only merge with object of type ProductIDsResult")

        self.add_cpes(other.cpe)
        self.add_purls(other.purl)
        self.add_raws(other.raw)


class PotProductIDsResult(BaseModel):
    cpe: List[Tuple[str, Annotated[float, Field(ge=-1, le=1)]]] = Field(
        default_factory=list,
        description="A list containing tuples of a CPE and a match score, sorted by abs(match score)",
    )
    purl: List[Tuple[str, Annotated[float, Field(ge=-1, le=1)]]] = Field(
        default_factory=list,
        description="A list containing tuples of a PURL and a match score, sorted by abs(match score)",
    )
    raw: List[Tuple[str, Annotated[float, Field(ge=-1, le=1)]]] = Field(
        default_factory=list,
        description="A list containing tuples of a raw string / product ID and a match score, sorted by abs(match score)",
    )

    model_config = {
        "title": "search_vulns Potential ProductID Result Model",
        "description": "Represents the result of search_vulns retrieving product IDs for a query, which did not fully match. Negative match scores indicate a created product ID.",
    }

    @classmethod
    def from_cpes(cls, cpes: List[Tuple[str, float]]):
        return cls(cpe=sorted(cpes, key=lambda entry: abs(entry[1]), reverse=True))

    @classmethod
    def from_purls(cls, purls: List[Tuple[str, float]]):
        return cls(purls=sorted(purls, key=lambda entry: abs(entry[1]), reverse=True))

    @classmethod
    def from_raw(cls, raws: List[Tuple[str, float]]):
        return cls(raws=sorted(raws, key=lambda entry: abs(entry[1]), reverse=True))

    @classmethod
    def from_product_ids_result(cls, result: ProductIDsResult):
        pot_result = cls()
        for cpe in result.cpe:
            pot_result.add_cpe(cpe, 1)
        for purl in result.purl:
            pot_result.add_purl(purl, 1)
        for raw in result.raw:
            pot_result.add_raw(raw, 1)
        return pot_result

    @field_serializer("cpe", "purl", "raw")
    def serialize_pot_pids(self, value):
        return sorted(value, key=lambda pot_pid: abs(pot_pid[1]), reverse=True)

    def add_cpes(self, cpes: List[Tuple[str, float]]):
        self.cpe = list(set(self.cpe + cpes))

    def add_cpe(self, cpe: str, score: float):
        self.add_cpes([(cpe, score)])

    def add_purls(self, purls: List[Tuple[str, float]]):
        self.purl = list(set(self.purl + purls))

    def add_purl(self, purl: str, score: float):
        self.add_purls([(purl, score)])

    def add_raws(self, raws: List[Tuple[str, float]]):
        self.raw = list(set(self.raw + raws))

    def add_raw(self, raw: str, score: float):
        self.add_raws([(raw, score)])

    def merge_with(self, other: PotProductIDsResult):
        if not other:
            return
        if not isinstance(other, self.__class__):
            raise TypeError("Can only merge with object of type PotProductIDsResult")

        self.add_cpes(other.cpe)
        self.add_purls(other.purl)
        self.add_raws(other.raw)


class VersionStatus(str, Enum):
    EOL = "EOL"
    CURRENT = "CURRENT"
    OUTDATED = "OUTDATED"
    N_A = "N/A"


class VersionStatusResult(BaseModel):
    status: Optional[VersionStatus] = Field(default=None, description="Actual version status")
    latest: Optional[str] = Field(default=None, description="Latest version")
    reference: Optional[str] = Field(
        default=None, description="Reference / url where where the information originates"
    )

    model_config = {
        "title": "search_vulns Version Status Result Model",
        "description": "Represents information about the version status of the product queried during a search_vulns call",
    }


class SearchVulnsResult(BaseModel):
    schema_version: Literal["1.0.0"] = Field(
        "1.0.0", description="Schema version of this model"
    )
    product_ids: ProductIDsResult = Field(
        default_factory=ProductIDsResult, description="Stores successfully matched product IDs"
    )
    vulns: Dict[
        Annotated[str, Field(min_length=1, description="Vulnerability ID")], Vulnerability
    ] = Field(default_factory=dict, description="Stores retrieved vulnerabilities")
    pot_product_ids: PotProductIDsResult = Field(
        default_factory=PotProductIDsResult,
        description="Stores other relevant product IDs that did not match fully",
    )
    version_status: VersionStatusResult = Field(
        default_factory=VersionStatusResult,
        description="Provides status about queried software version if available",
    )

    model_config = {
        "title": "search_vulns Result Model",
        "description": "Represents the result of a search_vulns query",
    }

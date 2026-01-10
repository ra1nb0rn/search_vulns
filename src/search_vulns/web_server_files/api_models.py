from typing import Literal

from pydantic import BaseModel, Field


class SoftwareVersionResult(BaseModel):
    version: str = Field(description="Version of search_vulns software")
    last_db_update: str = Field(
        description="Datetime string of when the local database was last updated"
    )
    last_db_update_ts: float = Field(
        description="Epoch timestamp of when the local database was last updated"
    )


class CheckKeyStatusResult(BaseModel):
    status: str = Field(
        description="'valid' if key is valid, otherwise a reason for why it is not"
    )


class CheckKeyStatusIn(BaseModel):
    key: str = Field(description="API Key to check")


class ProductIDQuery(BaseModel):
    query: str = Field(description="Query product to search IDs for, e.g. 'Tomcat 9.0.22'")


class SearchVulnsQuery(BaseModel):
    query: str = Field(
        description="Query product to search vulnerabilities for, e.g. 'Tomcat 9.0.22'"
    )
    ignore_general_product_vulns: Literal["true", "false"] = Field(
        "false", alias="ignore-general-product-vulns"
    )
    include_single_version_vulns: Literal["true", "false"] = Field(
        "false", alias="include-single-version-vulns"
    )
    is_good_product_id: Literal["true", "false"] = Field("true", alias="is-good-product-id")
    include_patched: Literal["true", "false"] = Field("false", alias="include-patched")
    use_created_product_ids: Literal["true", "false"] = Field(
        "false", alias="use-created-product-ids"
    )

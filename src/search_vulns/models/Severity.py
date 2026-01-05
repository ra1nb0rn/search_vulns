from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field, field_validator


class SeverityType(str, Enum):
    CVSS = "CVSS"
    EPSS = "EPSS"

    def __str__(self) -> str:
        return str(self.value)


class Severity(BaseModel):
    type: SeverityType = Field(description="Severity type, .e.g., CVSS, EPSS or other")
    score: str = Field(min_length=1, description="Severity score")

    model_config = {
        "title": "Vulnerability Severity Model",
        "description": "Represents the severity of a vulnerability",
    }


class SeverityCVSS(Severity):
    type: Literal[SeverityType.CVSS] = SeverityType.CVSS
    score: str = Field(min_length=1, description="CVSS score")
    version: str = Field(min_length=1, description="CVSS version")
    vector: str = Field(min_length=1, description="CVSS vector")

    model_config = {
        "title": "CVSS Severity Model",
        "description": "Represents the CVSS severity of a vulnerability",
    }

    @field_validator("score")
    @classmethod
    def is_cvss_score_valid(cls, cvss_score: str) -> str:
        try:
            cvss_score = float(cvss_score)
            if cvss_score < 0 or cvss_score > 10:
                raise ValueError()
        except ValueError:
            raise ValueError("cvss score must be a decimal number between 0 and 10")
        return str(cvss_score)

    @field_validator("version")
    @classmethod
    def is_cvss_version_valid(cls, cvss_version: str) -> str:
        try:
            cvss_version = float(cvss_version)
            if cvss_version < 1:
                raise ValueError()
        except ValueError:
            raise ValueError("cvss version must be greater than 0")
        return str(cvss_version)


class SeverityEPSS(Severity):
    type: Literal[SeverityType.EPSS] = SeverityType.EPSS
    score: str = Field(min_length=1, description="EPSS score")

    @field_validator("score")
    @classmethod
    def is_epss_valid(cls, epss: str) -> str:
        if not epss:
            raise ValueError("epss cannot be empty")
        try:
            epss = float(epss)
            if epss < 0 or epss > 1:
                raise ValueError()
        except ValueError:
            raise ValueError("epss must be a decimal number between 0 and 1")
        return str(epss)

    model_config = {
        "title": "EPSS Severity Model",
        "description": "Represents the EPSS severity of a vulnerability",
    }

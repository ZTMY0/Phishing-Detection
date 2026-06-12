from __future__ import annotations
from enum import Enum
from typing import Annotated
import re
from pydantic import BaseModel, Field, field_validator

MAX_BODY = 10_000
MAX_URLS = 50
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class RiskLevel(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"


class UserRole(str, Enum):
    admin = "admin"
    analyst = "analyst"
    user = "user"


def _email(v: str) -> str:
    v = v.strip().lower()
    if not EMAIL_RE.match(v):
        raise ValueError("invalid email")
    return v


class LoginRequest(BaseModel):
    email: Annotated[str, Field(max_length=320)]
    password: Annotated[str, Field(min_length=6, max_length=128)]
    validate_email = field_validator("email")(_email)


class RegisterRequest(BaseModel):
    email: Annotated[str, Field(max_length=320)]
    password: Annotated[str, Field(min_length=6, max_length=128)]
    validate_email = field_validator("email")(_email)


class RefreshRequest(BaseModel):
    refresh_token: Annotated[str, Field(min_length=1, max_length=4096)]


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: UserRole
    uid: str
    refresh_token: str | None = None
    expires_in: int | None = None


class SubmissionRequest(BaseModel):
    declared_sender: Annotated[str, Field(max_length=320)]
    subject: Annotated[str, Field(max_length=998)]
    body: Annotated[str, Field(max_length=MAX_BODY)]
    urls: Annotated[list[str], Field(max_length=MAX_URLS)] = []
    has_attachments: bool = False

    @field_validator("declared_sender")
    @classmethod
    def strip_sender(cls, v: str) -> str:
        return v.strip()

    @field_validator("urls")
    @classmethod
    def cap_urls(cls, v: list[str]) -> list[str]:
        return [u[:2048] for u in v[:MAX_URLS]]


class AuditEvent(BaseModel):
    event_type: str
    user_id: str | None = None
    report_id: str | None = None
    ip: str | None = None
    detail: str | None = None
    success: bool = True

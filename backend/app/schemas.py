import ipaddress
from typing import Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .policy import canonical_path


class TargetInput(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    kind: Literal["owned", "local", "lab", "src"]
    scheme: Literal["http", "https"] = "https"
    host: str
    port: int = Field(default=443, ge=1, le=65535)
    paths: list[str] = Field(default_factory=lambda: ["/"], min_length=1, max_length=50)
    deny_paths: list[str] = Field(default_factory=list, max_length=50)
    bound_ips: list[str] = Field(default_factory=list, max_length=16)
    statement: str = Field(min_length=10, max_length=4000)
    expires_at: float
    request_budget: int = Field(default=50, ge=1, le=500)
    ownership_declared: bool = False

    @model_validator(mode="after")
    def validate_scope(self):
        self.host = self.host.encode("idna").decode().lower()
        if (
            any(c in self.host for c in "/*@?#%\\")
            or not self.host
            or self.host.endswith(".")
        ):
            raise ValueError("需要精确主机，禁止通配和 URL")
        parsed = urlsplit(
            f"{self.scheme}://{'[' + self.host + ']' if ':' in self.host else self.host}:{self.port}"
        )
        if parsed.hostname != self.host or any(c.isspace() for c in self.host):
            raise ValueError("无效主机")
        self.paths = [canonical_path(p) for p in self.paths]
        self.deny_paths = [canonical_path(p) for p in self.deny_paths]
        self.bound_ips = [str(ipaddress.ip_address(p)) for p in self.bound_ips]
        if self.kind == "lab" and not self.bound_ips:
            raise ValueError("靶场必须绑定精确 IP")
        if self.kind in ("owned", "local") and not self.ownership_declared:
            raise ValueError("必须声明应用所有权")
        if self.kind == "local" and (
            self.host not in ("localhost", "127.0.0.1", "::1") or self.scheme != "http"
        ):
            raise ValueError("本机应用仅支持 http 与精确 localhost、127.0.0.1 或 ::1")
        return self


class AccessVerificationRule(BaseModel):
    model_config = ConfigDict(extra="forbid")
    allowed_account_id: str = Field(min_length=1, max_length=64)
    denied_account_id: str | None = Field(default=None, min_length=1, max_length=64)
    json_field: str = Field(pattern=r"^[A-Za-z_][A-Za-z0-9_-]{0,63}$")
    expected_value_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")


class InputProbeRule(BaseModel):
    model_config = ConfigDict(extra="forbid")
    parameter: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_]{0,63}$")
    read_only_confirmed: Literal[True]
    synthetic_data_only: Literal[True]


class JobInput(BaseModel):
    target_id: str
    endpoint_ids: list[str] = Field(min_length=1, max_length=50)
    account_ids: list[str] = Field(default_factory=list, max_length=3)
    request_budget: int = Field(default=20, ge=1, le=500)
    duration_seconds: int = Field(default=120, ge=10, le=1800)
    endpoint_test_types: dict[str, Literal["baseline", "role_compare", "both", "injection_errors", "xss_passive", "csrf_passive", "ssrf_passive", "xxe_passive", "file_passive", "deserialization_passive", "auth_session_passive", "disclosure_passive", "configuration_passive", "crypto_passive", "supply_chain_passive", "business_logic_review", "other_web_passive", "race_condition_review", "memory_safety_passive", "dos_passive", "cors_verify", "access_verify", "sql_error_verify", "xss_reflection_verify", "redirect_verify"]] = Field(
        default_factory=dict
    )
    verification_rules: dict[str, AccessVerificationRule] = Field(default_factory=dict, max_length=50)
    input_probe_rules: dict[str, InputProbeRule] = Field(default_factory=dict, max_length=50)


class PlanRun(BaseModel):
    proposal_ids: list[str] = Field(min_length=1, max_length=30)
    account_ids: list[str] = Field(default_factory=list, max_length=3)
    request_budget: int = Field(default=20, ge=1, le=500)
    duration_seconds: int = Field(default=120, ge=10, le=1800)


class ImportInput(BaseModel):
    format: Literal["openapi", "har", "manual"]
    document: dict


class AccountInput(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    role: str = Field(min_length=1, max_length=100)
    headers: dict[str, str]
    synthetic_data_only: Literal[True]


class Proposal(BaseModel):
    model_config = ConfigDict(extra="forbid")
    endpoint_id: str
    test_type: Literal["baseline", "role_compare"]
    risk: Literal["low"]
    expected_evidence: str = Field(max_length=1000)
    request_budget: int = Field(ge=1, le=4)


class ModelInput(BaseModel):
    name: str
    base_url: str
    model: str
    api_key: str = ""
    local: bool = False
    max_output_tokens: int = Field(default=800, ge=100, le=2000)


class ModelRun(BaseModel):
    include_semantic_context: bool = False
    model_id: str
    endpoint_ids: list[str] = Field(min_length=1, max_length=30)
    context: str = Field(default="", max_length=4000)
    max_cost_usd: float = Field(default=0.1, gt=0, le=5)


class FindingUpdate(BaseModel):
    status: Literal["lead", "pending", "verified", "false_positive"]
    explanation: str = Field(min_length=10, max_length=4000)


class ManualEvidence(BaseModel):
    title: str = Field(min_length=3, max_length=200)
    root_cause: str = Field(min_length=3, max_length=200)
    observation: str = Field(min_length=10, max_length=4000)
    steps: str = Field(min_length=10, max_length=4000)
    preconditions: str = Field(min_length=5, max_length=2000)


class MergeFinding(BaseModel):
    source_id: str

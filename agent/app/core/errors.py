from __future__ import annotations

from enum import Enum


class ErrorCode(str, Enum):
    REPORT_NOT_FOUND = "REPORT_NOT_FOUND"
    REPORT_CONTENT_INSUFFICIENT = "REPORT_CONTENT_INSUFFICIENT"
    TLP_RESTRICTED = "TLP_RESTRICTED"
    LLM_TIMEOUT = "LLM_TIMEOUT"
    LLM_RATE_LIMITED = "LLM_RATE_LIMITED"
    PIPELINE_VALIDATION_FAILED = "PIPELINE_VALIDATION_FAILED"
    INTERNAL_ERROR = "INTERNAL_ERROR"
    JOB_NOT_FOUND = "JOB_NOT_FOUND"
    RATE_LIMITED = "RATE_LIMITED"
    AUTH_FAILED = "AUTH_FAILED"
    TENANT_REQUIRED = "TENANT_REQUIRED"


ERROR_MESSAGES: dict[ErrorCode, str] = {
    ErrorCode.REPORT_NOT_FOUND: "The specified report was not found in the upstream platform.",
    ErrorCode.REPORT_CONTENT_INSUFFICIENT: (
        "This report does not contain enough structured data to generate a meaningful attack flow. "
        "Ensure the report has at least {min_sdos} related objects (indicators, malware, attack patterns, etc.)."
    ),
    ErrorCode.TLP_RESTRICTED: (
        "This report's TLP marking ({tlp_level}) prevents external AI processing. "
        "Configure a local model to generate attack flows for restricted reports."
    ),
    ErrorCode.LLM_TIMEOUT: "The AI model did not respond within the allowed time. Please try again.",
    ErrorCode.LLM_RATE_LIMITED: "AI model rate limit reached. Please wait a moment and try again.",
    ErrorCode.PIPELINE_VALIDATION_FAILED: "The generated attack flow failed validation: {details}",
    ErrorCode.INTERNAL_ERROR: "An internal error occurred: {details}",
    ErrorCode.JOB_NOT_FOUND: "Job {job_id} was not found.",
    ErrorCode.RATE_LIMITED: (
        "Rate limit exceeded. Maximum {limit} generations per {window} for your tenant. "
        "Please try again later."
    ),
    ErrorCode.AUTH_FAILED: "Authentication failed. Invalid or expired HMAC signature.",
    ErrorCode.TENANT_REQUIRED: "Tenant ID is required for all requests.",
}


class AttackFlowError(Exception):
    def __init__(self, code: ErrorCode, details: dict[str, str] | None = None):
        self.code = code
        self.details = details or {}
        template = ERROR_MESSAGES.get(code, str(code))
        try:
            self.message = template.format(**self.details)
        except KeyError:
            self.message = template
        super().__init__(self.message)

    def to_dict(self) -> dict:
        return {
            "error_code": self.code.value,
            "message": self.message,
            "details": self.details,
        }

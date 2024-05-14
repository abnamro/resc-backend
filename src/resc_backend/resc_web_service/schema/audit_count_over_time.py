# Standard Library

# Third Party
from pydantic import BaseModel


class AuditCountOverTime(BaseModel):
    time_period: str
    audit_by_auditor_count: dict[str, int]
    total: int = 0

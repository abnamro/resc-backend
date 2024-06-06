# Third Party
from pydantic import BaseModel


class AuditorMetric(BaseModel):
    auditor: str
    true_positive: int
    false_positive: int
    clarification_required: int
    not_accessible: int
    outdated: int
    not_analyzed: int
    total: int

    class Config:
        orm_mode = True

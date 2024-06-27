# Third Party
from typing import Annotated

from pydantic import BaseModel, Field

# First Party
from resc_backend.resc_web_service.schema.auditor_metric import AuditorMetric


class PersonalAuditMetrics(BaseModel):
    today: Annotated[int, Field(gt=-1)] = 0
    current_week: Annotated[int, Field(gt=-1)] = 0
    last_week: Annotated[int, Field(gt=-1)] = 0
    current_month: Annotated[int, Field(gt=-1)] = 0
    current_year: Annotated[int, Field(gt=-1)] = 0
    forever: Annotated[int, Field(gt=-1)] = 0
    rank_current_week: Annotated[int, Field(gt=-1)] = 0
    forever_breakdown: AuditorMetric | None = None

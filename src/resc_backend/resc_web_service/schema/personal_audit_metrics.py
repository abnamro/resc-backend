# Third Party
from pydantic import BaseModel, conint

# First Party
from resc_backend.resc_web_service.schema.auditor_metric import AuditorMetric


class PersonalAuditMetrics(BaseModel):
    today: conint(gt=-1) = 0
    current_week: conint(gt=-1) = 0
    last_week: conint(gt=-1) = 0
    current_month: conint(gt=-1) = 0
    current_year: conint(gt=-1) = 0
    forever: conint(gt=-1) = 0
    rank_current_week: conint(gt=-1) = 0
    forever_breakdown: AuditorMetric | None = None

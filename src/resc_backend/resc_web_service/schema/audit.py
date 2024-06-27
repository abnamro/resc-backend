# Standard Library
import datetime
from typing import Annotated

# Third Party
from pydantic import BaseModel, ConfigDict, Field, StringConstraints

# First Party
from resc_backend.constants import MAX_RECORDS_PER_PAGE_LIMIT
from resc_backend.resc_web_service.schema.finding_status import FindingStatus


class AuditMultiple(BaseModel):
    finding_ids: Annotated[
        list[Annotated[int, Field(gt=0)]], Field(min_length=1, max_length=MAX_RECORDS_PER_PAGE_LIMIT)
    ]
    status: FindingStatus
    comment: Annotated[str, StringConstraints(max_length=255)]


class AuditRead(BaseModel):
    id_: Annotated[int, Field(gt=0)]
    status: FindingStatus
    auditor: Annotated[str, StringConstraints(max_length=250)]
    comment: Annotated[str, StringConstraints(max_length=255)] | None = None
    timestamp: datetime.datetime
    model_config = ConfigDict(from_attributes=True)

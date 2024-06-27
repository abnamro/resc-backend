# Standard Library
from datetime import datetime

# Third Party
from pydantic import ValidationInfo, field_validator
from pydantic.dataclasses import dataclass

# First Party
from resc_backend.resc_web_service.schema.finding_status import FindingStatus
from resc_backend.resc_web_service.schema.vcs_provider import VCSProviders


@dataclass
class FindingsFilter:
    vcs_providers: list[VCSProviders] = None
    finding_statuses: list[FindingStatus] = None
    rule_names: list[str] = None
    rule_tags: list[str] = None
    project_name: str = None
    repository_name: str = None
    scan_ids: list[int] = None
    start_date_time: datetime = None
    end_date_time: datetime = None
    event_sent: bool = None
    rule_pack_versions: list[str] = None
    include_deleted_repositories: bool = False

    @field_validator("end_date_time")
    @classmethod
    def date_range_check(cls, end_date_time: datetime, values: ValidationInfo):
        if end_date_time and values.data["start_date_time"]:
            if values.data["start_date_time"] >= end_date_time:
                raise ValueError("the start of the date range needs to be prior to the end of it.")

        return end_date_time

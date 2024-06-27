# Standard Library
import datetime
from typing import Annotated

# Third Party
from pydantic import BaseModel, ConfigDict, Field, HttpUrl, StringConstraints

# First Party
from resc_backend.resc_web_service.schema.vcs_provider import VCSProviders


class RepositoryEnrichedBase(BaseModel):
    project_key: Annotated[str, StringConstraints(min_length=1, max_length=100)]
    repository_id: Annotated[str, StringConstraints(min_length=1, max_length=100)]
    repository_name: Annotated[str, StringConstraints(min_length=1, max_length=100)]
    repository_url: HttpUrl
    vcs_provider: VCSProviders
    last_scan_id: Annotated[int, Field(gt=0)] | None = None
    last_scan_timestamp: datetime.datetime | None = None
    true_positive: Annotated[int, Field(gt=-1)]
    false_positive: Annotated[int, Field(gt=-1)]
    not_analyzed: Annotated[int, Field(gt=-1)]
    not_accessible: Annotated[int, Field(gt=-1)]
    clarification_required: Annotated[int, Field(gt=-1)]
    outdated: Annotated[int, Field(gt=-1)]
    total_findings_count: Annotated[int, Field(gt=-1)]
    deleted_at: datetime.datetime | None = None


class RepositoryEnriched(RepositoryEnrichedBase):
    pass


class RepositoryEnrichedRead(RepositoryEnriched):
    id_: Annotated[int, Field(gt=0)]
    model_config = ConfigDict(from_attributes=True)

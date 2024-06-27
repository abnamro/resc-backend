# Third Party

from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

from resc_backend.constants import MAX_RECORDS_PER_PAGE_LIMIT

# First Party
from resc_backend.resc_web_service.schema.status_count import StatusCount


class RuleFindingCountModel(BaseModel):
    """
    :param Generic[Model]:
        Type of the object in the data list
    """

    rule_name: Annotated[str, StringConstraints(max_length=100)]
    finding_count: Annotated[int, Field(gt=-1)] = 0
    finding_statuses_count: Annotated[
        list[StatusCount], Field(min_length=None, max_length=MAX_RECORDS_PER_PAGE_LIMIT)
    ] = []
    model_config = ConfigDict(from_attributes=True)

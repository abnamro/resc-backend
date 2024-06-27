# Standard Library
from typing import Annotated, Generic, TypeVar

# Third Party
# pylint: disable=no-name-in-module
from pydantic import BaseModel, ConfigDict, Field

# First Party
from resc_backend.constants import MAX_RECORDS_PER_PAGE_LIMIT

Model = TypeVar("Model", bound=BaseModel)


class PaginationModel(BaseModel, Generic[Model]):
    """
        Generic encapsulation class for paginated endpoints to standardize output of the API
        example creation, PaginationModel[FindingRead](data=db_findings, total=total, limit=limit, skip=skip)
    :param Generic[Model]:
        Type of the object in the data list
    """

    # data: List[Model]
    data: Annotated[list[Model], Field(min_length=None, max_length=MAX_RECORDS_PER_PAGE_LIMIT)]
    total: Annotated[int, Field(gt=-1)]
    limit: Annotated[int, Field(gt=-1)]
    skip: Annotated[int, Field(gt=-1)]
    model_config = ConfigDict(from_attributes=True)

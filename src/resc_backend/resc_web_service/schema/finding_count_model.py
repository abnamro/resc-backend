# Standard Library
from typing import Annotated, Generic, TypeVar

# Third Party
from pydantic import BaseModel, ConfigDict, Field

Model = TypeVar("Model", bound=BaseModel)


class FindingCountModel(BaseModel, Generic[Model]):
    """
        Generic encapsulation class for findings count end points to standardize output of the API
        example creation, FindingCountModel[FindingRead](data=db_findings, true_positive=true_positive,
        false_positive=false_positive, not_analyzed=not_analyzed, not_accessible=not_accessible,
        clarification_required=clarification_required, outdated=outdated,
        total_findings_count=total_findings_count)
    :param Generic[Model]:
        Type of the object in the data list
    """

    data: Model | None
    true_positive: Annotated[int, Field(gt=-1)]
    false_positive: Annotated[int, Field(gt=-1)]
    not_analyzed: Annotated[int, Field(gt=-1)]
    not_accessible: Annotated[int, Field(gt=-1)]
    clarification_required: Annotated[int, Field(gt=-1)]
    outdated: Annotated[int, Field(gt=-1)]
    total_findings_count: Annotated[int, Field(gt=-1)]
    model_config = ConfigDict(from_attributes=True)

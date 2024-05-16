# Standard Library
from typing import Generic, TypeVar

# Third Party
from pydantic import BaseModel, conint
from pydantic.generics import GenericModel

Model = TypeVar("Model", bound=BaseModel)


class FindingCountModel(GenericModel, Generic[Model]):
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
    true_positive: conint(gt=-1)
    false_positive: conint(gt=-1)
    not_analyzed: conint(gt=-1)
    not_accessible: conint(gt=-1)
    clarification_required: conint(gt=-1)
    outdated: conint(gt=-1)
    total_findings_count: conint(gt=-1)

    class Config:
        orm_mode = True

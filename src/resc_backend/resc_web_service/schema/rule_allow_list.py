# Standard Library

# Third Party
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, StringConstraints


class RuleAllowListBase(BaseModel):
    description: Annotated[str, StringConstraints(max_length=2000)] | None = None
    regexes: str | None = None
    paths: str | None = None
    commits: str | None = None
    stop_words: str | None = None


class RuleAllowListCreate(RuleAllowListBase):
    @classmethod
    def create_from_base_class(cls, base_object: RuleAllowListBase):
        return cls(**(dict(base_object)))


class RuleAllowList(RuleAllowListBase):
    pass


class RuleAllowListRead(RuleAllowListBase):
    id_: Annotated[int, Field(gt=0)]
    model_config = ConfigDict(from_attributes=True)

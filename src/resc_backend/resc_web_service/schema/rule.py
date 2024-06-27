# Standard Library

# Third Party
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, StringConstraints


class RuleBase(BaseModel):
    rule_name: Annotated[str, StringConstraints(min_length=1, max_length=400)]
    description: Annotated[str, StringConstraints(max_length=4000)] | None = None
    comment: Annotated[str, StringConstraints(max_length=2000)] | None = None
    entropy: float | None = None
    secret_group: int | None = None
    regex: str | None = None
    path: str | None = None
    keywords: str | None = None


class RuleCreate(RuleBase):
    rule_pack: Annotated[str, StringConstraints(pattern=r"^(\d+\.)?(\d+\.)?(\*|\d+)$")]
    allow_list: Annotated[int, Field(gt=0)] | None = None

    @classmethod
    def create_from_base_class(cls, base_object: RuleBase, rule_pack: str, allow_list=int):
        return cls(**(dict(base_object)), rule_pack=rule_pack, allow_list=allow_list)


class Rule(RuleBase):
    pass


class RuleRead(RuleCreate):
    id_: Annotated[int, Field(gt=0)]
    model_config = ConfigDict(from_attributes=True)

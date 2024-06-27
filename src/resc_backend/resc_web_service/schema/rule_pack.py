# Standard Library
import datetime
from typing import Annotated

# Third Party
from pydantic import BaseModel, ConfigDict, Field, StringConstraints

RULE_PACK_VERSION_REGEX = r"^\d+(?:\.\d+){2}$"


class RulePackBase(BaseModel):
    version: Annotated[str, StringConstraints(pattern=RULE_PACK_VERSION_REGEX)]
    active: bool = False
    global_allow_list: Annotated[int, Field(gt=0)] | None = None
    outdated: bool = False


class RulePackCreate(RulePackBase):
    version: Annotated[str, StringConstraints(pattern=RULE_PACK_VERSION_REGEX)]
    global_allow_list: Annotated[int, Field(gt=0)] | None = None

    @classmethod
    def create_from_base_class(cls, base_object: RulePackBase, global_allow_list: int):
        return cls(**(dict(base_object)), global_allow_list=global_allow_list)


class RulePack(RulePackBase):
    pass


class RulePackRead(RulePackBase):
    version: Annotated[str, StringConstraints(pattern=RULE_PACK_VERSION_REGEX)]
    created: datetime.datetime
    model_config = ConfigDict(from_attributes=True)


class RulePackVersion(BaseModel):
    version: Annotated[str, StringConstraints(pattern=RULE_PACK_VERSION_REGEX)]

# Standard Library

# Third Party
from pydantic import BaseModel, conint, constr


class RuleAllowListBase(BaseModel):
    description: constr(max_length=2000) | None
    regexes: str | None
    paths: str | None
    commits: str | None
    stop_words: str | None


class RuleAllowListCreate(RuleAllowListBase):
    @classmethod
    def create_from_base_class(cls, base_object: RuleAllowListBase):
        return cls(**(dict(base_object)))


class RuleAllowList(RuleAllowListBase):
    pass


class RuleAllowListRead(RuleAllowListBase):
    id_: conint(gt=0)

    class Config:
        orm_mode = True

from enum import Enum

from pydantic import BaseModel, ConfigDict

from src.input_models import Info, Variable


class FormType(str, Enum):
    formdata = "formdata"
    raw = "raw"


class Script(BaseModel):
    type: str = "text/javascript"
    exec: list[str]


class Event(BaseModel):
    listen: str = "test"
    script: Script


class QueryString(BaseModel):
    key: str
    value: str

    @classmethod
    def of_str(cls, key_value: str):
        key, value = key_value.split("=", 1)
        return QueryString(key=key, value=value)

    @classmethod
    def of_dict(cls, input_dict: dict[str, str | int]):
        key = list(input_dict.keys())[0]
        value = input_dict[key]
        return QueryString(key=key, value=str(value))

    def to_str(self) -> str:
        return self.key + "=" + self.value

    def to_dict(self) -> dict[str, str | int]:
        return {self.key: self.value}


class Body(BaseModel):
    model_config = ConfigDict(use_enum_values=True)

    mode: FormType
    raw: str | None = None
    formdata: list[dict[str, str]] | None = None


class Url(BaseModel):
    # raw: str
    host: list[str] = ["{{baseUrl}}"]
    path: list[str]
    query: list[QueryString] | None = None
    variable: list[QueryString] | None = None


class Request(BaseModel):
    method: str
    header: list[QueryString] = []
    body: Body | None = None
    url: Url


class Query(BaseModel):
    name: str
    event: list[Event] = []
    request: Request


class EndPoint(BaseModel):
    name: str
    item: list[Query] = []


class Domain(BaseModel):
    name: str
    item: list[EndPoint] = []


class TestSuite(BaseModel):
    info: Info
    item: list[Domain] = []
    variable: list[Variable]

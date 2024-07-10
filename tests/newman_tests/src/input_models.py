from enum import Enum, IntEnum
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field


class Method(str, Enum):
    get = "GET"
    post = "POST"
    put = "PUT"
    patch = "PATCH"
    delete = "DELETE"


class Code(IntEnum):
    ok = 200
    created = 201
    unauthorized = 401
    forbidden = 403
    not_found = 404
    conflict = 409
    validation_error = 422
    internal_server_error = 500


class Query(BaseModel):
    model_config = ConfigDict(use_enum_values=True)

    name: str
    method: Method
    header: dict[str, str | int] | None = None
    request: str
    variables: list[dict[str, str | int]] | None = None
    status_code: Code
    response_time: Annotated[int, Field(ge=300)] = 300
    tests: str | None = None
    prerequest: str | None = None
    form_raw: str | None = None
    form_data: list[dict[str, str]] | None = None


class EndPoint(BaseModel):
    name: str
    item: list[Query]


class Domain(BaseModel):
    name: str
    item: list[EndPoint]


class Info(BaseModel):
    postman_id: Annotated[str, Field(alias="_postman_id", serialization_alias="_postman_id")]
    name: str
    description: str
    schema_: Annotated[str, Field(alias="schema", serialization_alias="schema")]


class Variable(BaseModel):
    key: str
    value: str
    type: str


class TestSuite(BaseModel):
    info: Info
    item: list[Domain]
    variable: list[Variable]

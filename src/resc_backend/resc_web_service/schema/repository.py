import datetime
from typing import Annotated

# Third Party
from pydantic import BaseModel, ConfigDict, Field, HttpUrl, StringConstraints


class SimpleRepository(BaseModel):
    id: Annotated[str, StringConstraints(min_length=1, max_length=100)]
    name: Annotated[str, StringConstraints(min_length=1, max_length=100)]


class ActiveRepositories(BaseModel):
    project_key: Annotated[str, StringConstraints(min_length=1, max_length=100)]
    repositories: Annotated[list[SimpleRepository], Field(min_length=0)]
    vcs_instance_name: Annotated[str, StringConstraints(max_length=200)]


class RepositoryBase(BaseModel):
    project_key: Annotated[str, StringConstraints(min_length=1, max_length=100)]
    repository_id: Annotated[str, StringConstraints(min_length=1, max_length=100)]
    repository_name: Annotated[str, StringConstraints(min_length=1, max_length=100)]
    repository_url: HttpUrl
    deleted_at: datetime.datetime | None = None
    vcs_instance: Annotated[int, Field(gt=0)]


class Repository(RepositoryBase):
    pass


class RepositoryCreate(RepositoryBase):
    pass


class RepositoryRead(RepositoryBase):
    id_: Annotated[int, Field(gt=0)]
    model_config = ConfigDict(from_attributes=True)

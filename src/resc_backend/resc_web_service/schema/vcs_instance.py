# Standard Library
from typing import Annotated

# Third Party
from pydantic import BaseModel, ConfigDict, Field, StringConstraints, ValidationInfo, field_validator

# First Party
from resc_backend.constants import AZURE_DEVOPS
from resc_backend.resc_web_service.schema.vcs_provider import VCSProviders


class VCSInstanceBase(BaseModel):
    name: Annotated[str, StringConstraints(max_length=200)]
    provider_type: VCSProviders
    hostname: Annotated[str, StringConstraints(max_length=200)]
    port: Annotated[int, Field(gt=-0, lt=65536)]
    scheme: Annotated[str, StringConstraints(max_length=20)]
    exceptions: Annotated[list[str], Field(min_length=None, max_length=500)] | None = None
    scope: Annotated[list[str], Field(min_length=None, max_length=500)] | None = None
    organization: Annotated[str, StringConstraints(max_length=200)] | None = None

    @field_validator("scheme", mode="before")
    @classmethod
    def check_scheme(cls, value):
        allowed_schemes = ["http", "https"]
        if value not in allowed_schemes:
            raise ValueError(f"The scheme '{value}' must be one of the following {', '.join(allowed_schemes)}")
        return value

    @field_validator("organization", mode="before")
    @classmethod
    def check_organization(cls, value, values: ValidationInfo):
        if not value and values.data["provider_type"] == AZURE_DEVOPS:
            raise ValueError("The organization field needs to be specified for Azure devops vcs instances")
        return value

    @field_validator("scope", mode="before")
    @classmethod
    def check_scope_and_exceptions(cls, value, values: ValidationInfo):
        if value and values.data["exceptions"]:
            raise ValueError(
                "You cannot specify both the scope and exceptions to the scan, only one setting is supported."
            )
        return value


class VCSInstanceCreate(VCSInstanceBase):
    pass


class VCSInstanceRead(VCSInstanceBase):
    id_: Annotated[int, Field(gt=0)]

    @classmethod
    def create_from_db_vcs_instance(cls, db_vcs_instance):
        exceptions = []
        scope = []
        if db_vcs_instance.exceptions:
            exceptions = db_vcs_instance.exceptions.split(",")
        if db_vcs_instance.scope:
            scope = db_vcs_instance.scope.split(",")

        vcs_instance_read = cls(
            id_=db_vcs_instance.id_,
            name=db_vcs_instance.name,
            provider_type=db_vcs_instance.provider_type,
            hostname=db_vcs_instance.hostname,
            port=db_vcs_instance.port,
            scheme=db_vcs_instance.scheme,
            exceptions=exceptions,
            scope=scope,
            organization=db_vcs_instance.organization,
        )

        return vcs_instance_read

    model_config = ConfigDict(from_attributes=True)

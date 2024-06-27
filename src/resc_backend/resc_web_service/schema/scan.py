# Standard Library
import datetime
from typing import Annotated

# Third Party
from pydantic import BaseModel, ConfigDict, Field, StringConstraints

# First Party
from resc_backend.resc_web_service.schema.scan_type import ScanType


class ScanBase(BaseModel):
    scan_type: ScanType = ScanType.BASE
    last_scanned_commit: Annotated[str, StringConstraints(min_length=1, max_length=100)]
    timestamp: datetime.datetime
    increment_number: Annotated[int, Field(gt=-1)] = 0
    rule_pack: Annotated[str, StringConstraints(max_length=100)]


class ScanCreate(ScanBase):
    repository_id: Annotated[int, Field(gt=0)]

    @classmethod
    def create_from_base_class(cls, base_object: ScanBase, repository_id: int):
        return cls(**(dict(base_object)), repository_id=repository_id)


class Scan(ScanBase):
    pass


class ScanRead(ScanCreate):
    id_: Annotated[int, Field(gt=0)]
    model_config = ConfigDict(from_attributes=True)

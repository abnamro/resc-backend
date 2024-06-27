# Third Party
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, StringConstraints


class DateCountModel(BaseModel):
    date_lable: Annotated[str, StringConstraints(max_length=100)]
    finding_count: Annotated[int, Field(gt=-1)] = 0
    model_config = ConfigDict(from_attributes=True)

# Standard Library
import datetime
import logging
from typing import Annotated

# Third Party
from pydantic import BaseModel, ConfigDict, Field, HttpUrl, StringConstraints, model_validator

# First Party
from resc_backend.resc_web_service.schema.finding_status import FindingStatus
from resc_backend.resc_web_service.schema.vcs_provider import VCSProviders

logger = logging.getLogger(__name__)


class DetailedFindingBase(BaseModel):
    file_path: str
    line_number: Annotated[int, Field(gt=-1)]
    column_start: Annotated[int, Field(gt=-1)]
    column_end: Annotated[int, Field(gt=-1)]
    commit_id: Annotated[str, StringConstraints(max_length=120)]
    commit_message: str
    commit_timestamp: datetime.datetime
    author: Annotated[str, StringConstraints(max_length=200)]
    email: Annotated[str, StringConstraints(max_length=100)]
    status: FindingStatus | None = FindingStatus.NOT_ANALYZED.value
    comment: Annotated[str, StringConstraints(max_length=255)] | None = None
    rule_name: Annotated[str, StringConstraints(max_length=200)]
    rule_pack: Annotated[str, StringConstraints(max_length=100)]
    project_key: Annotated[str, StringConstraints(min_length=1, max_length=100)]
    repository_name: Annotated[str, StringConstraints(min_length=1, max_length=100)]
    repository_url: HttpUrl
    timestamp: datetime.datetime
    vcs_provider: VCSProviders
    last_scanned_commit: Annotated[str, StringConstraints(min_length=1, max_length=100)]
    scan_id: Annotated[int, Field(gt=0)]
    event_sent_on: datetime.datetime | None = None
    is_dir_scan: bool


class DetailedFinding(DetailedFindingBase):
    pass


class DetailedFindingRead(DetailedFinding):
    id_: Annotated[int, Field(gt=0)]
    commit_url: Annotated[str, StringConstraints(min_length=1)] | None = None

    @staticmethod
    def build_bitbucket_commit_url(
        repository_url: str,
        repository_name: str,
        project_key: str,
        file_path: str,
        commit_id: str,
        line_number: int,
        is_dir_scan: bool,
    ) -> str:
        arr = repository_url.split("/")
        if len(arr) >= 3:
            repo_base_url = arr[0] + "//" + arr[2]
        else:
            repo_base_url = repository_url

        if is_dir_scan:
            return (
                f"{repo_base_url}/projects/{project_key}/repos/"
                f"{repository_name}/browse/{file_path}?at={commit_id}#{line_number}"
            )

        return (
            f"{repo_base_url}/projects/{project_key}/repos/"
            f"{repository_name}/commits/{commit_id}#{file_path}?t={line_number}"
        )

    @staticmethod
    def build_ado_commit_url(
        repository_url: str,
        file_path: str,
        commit_id: str,
        line_number: int,
        is_dir_scan: bool,
    ) -> str:
        if is_dir_scan:
            return (
                f"{repository_url}?version=GC{commit_id}&path=/{file_path}&line={line_number}&lineEnd={line_number + 1}"
                "&lineStartColumn=1&lineEndColumn=1&type=2&lineStyle=plain"
            )

        return (
            f"{repository_url}/commit/{commit_id}?path=/{file_path}&line={line_number}&lineEnd={line_number + 1}"
            "&lineStartColumn=1&lineEndColumn=1&type=2&lineStyle=plain"
        )

    @staticmethod
    def build_github_commit_url(repository_url: str, file_path: str, commit_id: str) -> str:
        github_commit_url = f"{repository_url}/commit/{commit_id}?path=/{file_path}"
        return github_commit_url

    @model_validator(mode="before")
    def build_commit_url(cls, values: (tuple | dict)) -> dict:  # noqa: N805
        # We are dealing with a namedtuple (i.e. from a database query)
        if hasattr(values, "_asdict"):
            values = values._asdict()

        if "status" not in values or values["status"] is None:
            values["status"] = FindingStatus.NOT_ANALYZED.value
        if "comment" not in values or values["comment"] is None:
            values["comment"] = ""
        if values["vcs_provider"] == VCSProviders.BITBUCKET:
            values["commit_url"] = cls.build_bitbucket_commit_url(
                repository_url=values["repository_url"],
                repository_name=values["repository_name"],
                project_key=values["project_key"],
                file_path=values["file_path"],
                commit_id=values["commit_id"],
                line_number=values["line_number"],
                is_dir_scan=values["is_dir_scan"],
            )
        elif values["vcs_provider"] == VCSProviders.AZURE_DEVOPS:
            values["commit_url"] = cls.build_ado_commit_url(
                repository_url=values["repository_url"],
                file_path=values["file_path"],
                commit_id=values["commit_id"],
                line_number=values["line_number"],
                is_dir_scan=values["is_dir_scan"],
            )

        elif values["vcs_provider"] == VCSProviders.GITHUB_PUBLIC:
            values["commit_url"] = cls.build_github_commit_url(
                repository_url=values["repository_url"],
                file_path=values["file_path"],
                commit_id=values["commit_id"],
            )
        else:
            raise NotImplementedError(f"Unsupported VCSProvider: {values['vcs_provider']}")

        return values

    model_config = ConfigDict(from_attributes=True)

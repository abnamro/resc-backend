# Standard Library
import datetime

# Third Party
from pydantic import BaseModel, HttpUrl, conint, constr, root_validator

# First Party
from resc_backend.resc_web_service.schema.finding_status import FindingStatus
from resc_backend.resc_web_service.schema.vcs_provider import VCSProviders


class DetailedFindingBase(BaseModel):
    file_path: str
    line_number: conint(gt=-1)
    column_start: conint(gt=-1)
    column_end: conint(gt=-1)
    commit_id: constr(max_length=120)
    commit_message: str
    commit_timestamp: datetime.datetime
    author: constr(max_length=200)
    email: constr(max_length=100)
    status: FindingStatus | None = FindingStatus.NOT_ANALYZED.value
    comment: constr(max_length=255) | None = None
    rule_name: constr(max_length=200)
    rule_pack: constr(max_length=100)
    project_key: constr(min_length=1, max_length=100)
    repository_name: constr(min_length=1, max_length=100)
    repository_url: HttpUrl
    timestamp: datetime.datetime
    vcs_provider: VCSProviders
    last_scanned_commit: constr(min_length=1, max_length=100)
    scan_id: conint(gt=0)
    event_sent_on: datetime.datetime | None
    is_dir_scan: bool


class DetailedFinding(DetailedFindingBase):
    pass


class DetailedFindingRead(DetailedFinding):
    id_: conint(gt=0)
    commit_url: constr(min_length=1) | None

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

    @root_validator
    def build_commit_url(cls, values) -> dict:  # noqa: N805
        if values["status"] is None:
            values["status"] = FindingStatus.NOT_ANALYZED.value
        if values["comment"] is None:
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

    class Config:
        orm_mode = True

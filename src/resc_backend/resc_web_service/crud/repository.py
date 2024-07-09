# Standard Library
import logging
from datetime import UTC, datetime

# Third Party
from itertools import islice

from sqlalchemy import func, select, update
from sqlalchemy.orm import Session
from sqlalchemy.orm.query import Query

# First Party
from resc_backend.constants import (
    DEFAULT_RECORDS_PER_PAGE_LIMIT,
    MAX_RECORDS_PER_PAGE_LIMIT,
)
from resc_backend.db.model import (
    DBaudit,
    DBfinding,
    DBrepository,
    DBscan,
    DBscanFinding,
    DBVcsInstance,
)
from resc_backend.resc_web_service.crud import finding as finding_crud
from resc_backend.resc_web_service.crud import scan as scan_crud
from resc_backend.resc_web_service.crud import scan_finding as scan_finding_crud
from resc_backend.resc_web_service.schema import repository as repository_schema
from resc_backend.resc_web_service.schema.finding_status import FindingStatus
from resc_backend.resc_web_service.schema.scan_type import ScanType
from resc_backend.resc_web_service.schema.vcs_provider import VCSProviders

logger = logging.getLogger(__name__)


def _get_max_base_scan(db_connection: Session) -> Query:
    subquery: Query = db_connection.query(DBscan.repository_id, func.max(DBscan.id_).label("latest_base_scan_id"))
    subquery = subquery.where(DBscan.scan_type == ScanType.BASE)
    subquery = subquery.where(DBscan.is_latest == True)  # noqa: E712
    subquery = subquery.group_by(DBscan.repository_id)
    return subquery.subquery()


def _only_if_has_untriaged_findings_condition(db_connection: Session) -> Query:
    has_untriaged_sub_query: Query = db_connection.query(DBfinding.repository_id)
    has_untriaged_sub_query = has_untriaged_sub_query.join(
        DBaudit,
        (DBaudit.finding_id == DBfinding.id_) & (DBaudit.is_latest == True),  # noqa: E712
        isouter=True,
    )
    has_untriaged_sub_query = has_untriaged_sub_query.where(
        (DBaudit.status == None) | (DBaudit.status == FindingStatus.NOT_ANALYZED)  # noqa: E711
    )  # noqa: E711
    return has_untriaged_sub_query.distinct()


def _repository_id_only_if_has_findings(db_connection: Session) -> Query:
    last_scan_sub_query = _get_max_base_scan(db_connection)

    sub_query = db_connection.query(DBrepository.id_)
    sub_query = sub_query.join(
        last_scan_sub_query,
        DBrepository.id_ == last_scan_sub_query.c.repository_id,
    )
    sub_query = sub_query.join(
        DBscan,
        DBrepository.id_ == DBscan.repository_id,
    )
    sub_query = sub_query.where(DBscan.id_ >= last_scan_sub_query.c.latest_base_scan_id)
    sub_query = sub_query.join(DBscanFinding, DBscan.id_ == DBscanFinding.scan_id)
    return sub_query.distinct()


def _apply_filters(
    db_connection: Session,
    query: Query,
    include_deleted: bool,
    only_if_has_findings: bool,
    only_if_has_untriaged_findings: bool,
    vcs_providers: list[VCSProviders] | None,
) -> Query:
    if not include_deleted:
        query = query.filter(DBrepository.deleted_at == None)  # noqa: E711

    if only_if_has_findings:
        sub_query = _repository_id_only_if_has_findings(db_connection=db_connection)
        query = query.where(DBrepository.id_.in_(sub_query))

    if only_if_has_untriaged_findings:
        has_untriaged_sub_query = _only_if_has_untriaged_findings_condition(db_connection)
        query = query.where(DBrepository.id_.in_(has_untriaged_sub_query))

    if vcs_providers and vcs_providers is not None:
        query = query.where(DBVcsInstance.provider_type.in_(vcs_providers))

    return query


def get_repositories(
    db_connection: Session,
    vcs_providers: list[VCSProviders] | None = None,
    skip: int = 0,
    limit: int = DEFAULT_RECORDS_PER_PAGE_LIMIT,
    project_filter: str = "",
    repository_filter: str = "",
    only_if_has_findings: bool = False,
    include_deleted: bool = False,
    only_if_has_untriaged_findings: bool = False,
):
    """
        Retrieve repository records optionally filtered
    :param db_connection:
        Session of the database connection
    :param skip:
        integer amount of records to skip to support pagination
    :param limit:
        integer amount of records to return, to support pagination
    :param vcs_providers:
        optional [string] filtering the VCS provider
    :param project_filter:
        optional, filter on project name. Is used as a string contains filter
    :param repository_filter:
        optional, filter on repository name. Is used as a string contains filter
    :param only_if_has_findings:
        optional, filter on repositories with findings
    :return: repositories
        list of DBrepository objects
    """
    limit_val = MAX_RECORDS_PER_PAGE_LIMIT if limit > MAX_RECORDS_PER_PAGE_LIMIT else limit

    # Get the latest scan for repository
    sub_query: Query = db_connection.query(DBscan.repository_id, func.max(DBscan.timestamp).label("max_timestamp"))
    sub_query = sub_query.where(DBscan.is_latest == True)  # noqa: E712
    sub_query = sub_query.group_by(DBscan.repository_id)
    sub_query = sub_query.subquery()

    query = db_connection.query(
        DBrepository.id_,
        DBrepository.project_key,
        DBrepository.repository_id,
        DBrepository.repository_name,
        DBrepository.repository_url,
        DBrepository.vcs_instance,
        DBrepository.deleted_at,
        DBVcsInstance.provider_type,
        func.coalesce(DBscan.id_, None).label("last_scan_id"),
        func.coalesce(DBscan.timestamp, None).label("last_scan_timestamp"),
    )

    query = query.join(DBVcsInstance, DBVcsInstance.id_ == DBrepository.vcs_instance)
    query = query.join(
        sub_query,
        DBrepository.id_ == sub_query.c.repository_id,
        isouter=True,
    )
    query = query.join(
        DBscan,
        (DBscan.repository_id == sub_query.c.repository_id) & (DBscan.timestamp == sub_query.c.max_timestamp),
        isouter=True,
    )

    query = _apply_filters(
        db_connection, query, include_deleted, only_if_has_findings, only_if_has_untriaged_findings, vcs_providers
    )

    if project_filter:
        query = query.where(DBrepository.project_key == project_filter)

    if repository_filter:
        query = query.where(DBrepository.repository_name == repository_filter)

    repositories = query.order_by(DBrepository.repository_name).offset(skip).limit(limit_val).all()

    return repositories


def get_repositories_count(
    db_connection: Session,
    vcs_providers: list[VCSProviders] = None,
    project_filter: str = "",
    repository_filter: str = "",
    only_if_has_findings: bool = False,
    include_deleted: bool = False,
    only_if_has_untriaged_findings: bool = False,
) -> int:
    """
        Retrieve count of repository records optionally filtered
    :param db_connection:
        Session of the database connection
    :param vcs_providers:
        optional [string] filtering the VCS provider
    :param project_filter:
        optional, filter on project name
    :param repository_filter:
        optional, filter on repository name
    :param only_if_has_findings:
        optional, filter on repositories with findings
    :return: total_count
        count of repositories
    """
    query = db_connection.query(func.count(DBrepository.id_))
    query = query.join(DBVcsInstance, DBVcsInstance.id_ == DBrepository.vcs_instance)

    query = _apply_filters(
        db_connection, query, include_deleted, only_if_has_findings, only_if_has_untriaged_findings, vcs_providers
    )

    if project_filter:
        query = query.where(DBrepository.project_key == project_filter)

    if repository_filter:
        query = query.where(DBrepository.repository_name == repository_filter)

    total_count = query.scalar()
    return total_count


def get_repository(db_connection: Session, repository_id: int):
    repository = db_connection.query(DBrepository).where(DBrepository.id_ == repository_id).first()
    return repository


def update_repository(
    db_connection: Session,
    repository_id: int,
    repository: repository_schema.RepositoryCreate,
):
    db_repository = db_connection.query(DBrepository).filter_by(id_=repository_id).first()

    db_repository.repository_name = repository.repository_name
    db_repository.repository_url = str(repository.repository_url)
    db_repository.vcs_instance = repository.vcs_instance
    db_repository.deleted_at = repository.deleted_at

    db_connection.commit()
    db_connection.refresh(db_repository)
    return db_repository


def create_repository(db_connection: Session, repository: repository_schema.RepositoryCreate):
    db_repository = DBrepository(
        project_key=repository.project_key,
        repository_id=repository.repository_id,
        repository_name=repository.repository_name,
        repository_url=str(repository.repository_url),
        vcs_instance=repository.vcs_instance,
        deleted_at=None,
    )
    db_connection.add(db_repository)
    db_connection.commit()
    db_connection.refresh(db_repository)
    return db_repository


def create_repository_if_not_exists(db_connection: Session, repository: repository_schema.RepositoryCreate):
    # Query the database to see if the repository object exists based on the unique constraint parameters
    query: Query = db_connection.query(DBrepository)
    query = query.where(DBrepository.project_key == repository.project_key)
    query = query.where(DBrepository.repository_id == repository.repository_id)
    query = query.where(DBrepository.vcs_instance == repository.vcs_instance)
    db_select_repository = query.first()

    if db_select_repository is not None:
        return db_select_repository

    # Create non-existing repository object
    return create_repository(db_connection, repository)


def get_distinct_projects(
    db_connection: Session,
    vcs_providers: list[VCSProviders] = None,
    repository_filter: str = "",
    only_if_has_findings: bool = False,
    include_deleted: bool = False,
    only_if_has_untriaged_findings: bool = False,
):
    """
        Retrieve all unique project names
    :param db_connection:
        Session of the database connection
    :param vcs_providers:
        optional, filter of supported vcs provider types
    :param repository_filter:
        optional, filter on repository name. Is used as a string contains filter
    :param only_if_has_findings:
        optional, filter on repositories that have findings
    :return: distinct_projects
        The output will contain a list of unique projects
    """
    query = db_connection.query(DBrepository.project_key)
    query = query.join(DBVcsInstance, DBVcsInstance.id_ == DBrepository.vcs_instance)

    query = _apply_filters(
        db_connection, query, include_deleted, only_if_has_findings, only_if_has_untriaged_findings, vcs_providers
    )

    if repository_filter:
        query = query.where(DBrepository.repository_name == repository_filter)

    query = query.distinct()
    query = query.order_by(DBrepository.project_key)
    distinct_projects = query.all()
    return distinct_projects


def get_distinct_repositories(
    db_connection: Session,
    vcs_providers: list[VCSProviders] = None,
    project_name: str = "",
    only_if_has_findings: bool = False,
    include_deleted: bool = False,
    only_if_has_untriaged_findings: bool = False,
):
    """
        Retrieve all unique repository names
    :param db_connection:
        Session of the database connection
    :param vcs_providers:
        optional, filter of supported vcs provider types
    :param project_name:
        optional, filter on project name. Is used as a full string match filter
    :param only_if_has_findings:
        optional, filter on repositories that have findings
    :return: distinct_repositories
        The output will contain a list of unique repositories
    """
    query = db_connection.query(DBrepository.repository_name)
    query = query.join(DBVcsInstance, DBVcsInstance.id_ == DBrepository.vcs_instance)

    query = _apply_filters(
        db_connection, query, include_deleted, only_if_has_findings, only_if_has_untriaged_findings, vcs_providers
    )

    if project_name:
        query = query.where(DBrepository.project_key == project_name)

    query = query.distinct()
    query = query.order_by(DBrepository.repository_name)
    distinct_repositories = query.all()
    return distinct_repositories


def get_findings_metadata_by_repository_id(db_connection: Session, repository_ids: list[int]):
    """
        Retrieves the finding metadata for a repository id from the database with most recent scan information
    :param db_connection:
        Session of the database connection
    :param repository_ids:
        ids of the repository for which findings metadata to be retrieved
    :return: findings_metadata
        findings_metadata containing the count for each status
    """
    query: Query = db_connection.query(DBrepository.id_, DBaudit.status, func.count(DBscanFinding.finding_id))

    last_scan_sub_query = _get_max_base_scan(db_connection)
    query = query.join(
        last_scan_sub_query,
        DBrepository.id_ == last_scan_sub_query.c.repository_id,
    )
    query = query.join(
        DBscan,
        DBrepository.id_ == DBscan.repository_id,
    )
    query = query.where(DBscan.id_ >= last_scan_sub_query.c.latest_base_scan_id)
    query = query.join(DBscanFinding, DBscan.id_ == DBscanFinding.scan_id)
    query = query.join(
        DBaudit,
        (DBaudit.finding_id == DBscanFinding.finding_id) & (DBaudit.is_latest == True),  # noqa: E712
        isouter=True,
    )
    query = query.where(DBrepository.id_.in_(repository_ids))
    query = query.group_by(
        DBrepository.id_,
        DBaudit.status,
    )
    status_counts = query.all()
    repo_count_dict = {}
    for repository_id in repository_ids:
        repo_count_dict[repository_id] = FindingStatus.init_statistics()

    for status_count in status_counts:
        repository_id: str = status_count[0]
        finding_status: str | None = status_count[1]
        count: int = status_count[2]

        repo_count_dict[repository_id]["total_findings_count"] += count
        if finding_status is None:
            repo_count_dict[repository_id][FindingStatus.NOT_ANALYZED.value.lower()] += count
        else:
            repo_count_dict[repository_id][finding_status.lower()] += count

    return repo_count_dict


def delete_repository(db_connection: Session, repository_id: int, delete_related: bool = False):
    """
        Delete a repository object
    :param db_connection:
        Session of the database connection
    :param repository_id:
        id of the repository to be deleted
    :param delete_related:
        if related records need to be deleted
    """
    if delete_related:
        scan_finding_crud.delete_scan_finding_by_repository_id(db_connection, repository_id=repository_id)
        finding_crud.delete_findings_by_repository_id(db_connection, repository_id=repository_id)
        scan_crud.delete_scans_by_repository_id(db_connection, repository_id=repository_id)
    db_connection.query(DBrepository).where(DBrepository.id_ == repository_id).delete(synchronize_session=False)
    db_connection.commit()


def delete_repositories_by_vcs_instance_id(db_connection: Session, vcs_instance_id: int):
    """
        Delete repositories for a given vcs instance
    :param db_connection:
        Session of the database connection
    :param vcs_instance_id:
        id of the vcs instance
    """
    db_connection.query(DBrepository).where(
        DBrepository.vcs_instance == DBVcsInstance.id_,
        DBVcsInstance.id_ == vcs_instance_id,
    ).delete(synchronize_session=False)
    db_connection.commit()


def soft_delete_repository(db_connection: Session, repository_ids: list[int]):
    """
        Soft delete a repository object
    :param db_connection:
        Session of the database connection
    :param repository_ids:
        list of id of the repository to be deleted
    """
    iterator = iter(repository_ids)
    while chunk := list(islice(iterator, 1000)):
        db_connection.execute(
            update(DBrepository).where(DBrepository.id_.in_(chunk)).values(deleted_at=datetime.now(UTC))
        )
    db_connection.commit()


def undelete_repository(db_connection: Session, repository_ids: list[int]):
    """
        Undelete a repository object
    :param db_connection:
        Session of the database connection
    :param repository_ids:
        list of id of the repository to be undeleted
    """
    iterator = iter(repository_ids)
    while chunk := list(islice(iterator, 1000)):
        db_connection.execute(update(DBrepository).where(DBrepository.id_.in_(chunk)).values(deleted_at=None))
    db_connection.commit()


def get_active_repository_ids_by_project_and_vcs_instance(
    db_connection: Session, project_key: str, vcs_instance_name: str
) -> list[str]:
    logger.debug(f"Fetching active repository ids for project {project_key} and vcs instance {vcs_instance_name}")
    query = select(DBrepository.repository_id)
    query = query.join(DBVcsInstance, DBVcsInstance.id_ == DBrepository.vcs_instance)
    query = query.where(DBrepository.project_key == project_key)
    query = query.where(DBVcsInstance.name == vcs_instance_name)
    query = query.where(DBrepository.deleted_at.is_(None))
    return db_connection.execute(query).scalars().all()


def fetch_id_from_undeleted_repository_string_id(
    db_connection: Session, vcs_instance_name: str, repository_ids: list[str]
) -> list[int]:
    """
        Fetch the id of the undeleted repository from the string id
    :param db_connection:
        Session of the database connection
    :param repository_ids:
        list of id of the repository
    """
    iterator = iter(repository_ids)
    repository_ids = []
    while chunk := list(islice(iterator, 1000)):
        query = select(DBrepository.id_)
        query = query.join(DBVcsInstance, DBVcsInstance.id_ == DBrepository.vcs_instance)
        query = query.where(DBrepository.repository_id.in_(chunk))
        query = query.where(DBVcsInstance.name == vcs_instance_name)
        query = query.where(DBrepository.deleted_at.is_(None))
        repository_ids.extend(db_connection.execute(query).scalars().all())
    return repository_ids

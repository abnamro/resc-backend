# Standard Library
import logging
from datetime import UTC, datetime, timedelta
from itertools import islice

# Third Party
from sqlalchemy import Column, extract, func, select, union
from sqlalchemy.engine import Row
from sqlalchemy.orm import Session
from sqlalchemy.orm.query import Query
from sqlalchemy.sql.expression import literal_column

# First Party
from resc_backend.constants import (
    DEFAULT_RECORDS_PER_PAGE_LIMIT,
    MAX_RECORDS_PER_PAGE_LIMIT,
)
from resc_backend.db.model import (
    DBaudit,
    DBfinding,
    DBrepository,
    DBrule,
    DBrulePack,
    DBruleTag,
    DBscan,
    DBscanFinding,
    DBtag,
    DBVcsInstance,
)
from resc_backend.helpers.list_mapper import dict_of_list
from resc_backend.resc_web_service.crud import scan_finding as scan_finding_crud
from resc_backend.resc_web_service.filters import FindingsFilter
from resc_backend.resc_web_service.schema import finding as finding_schema
from resc_backend.resc_web_service.schema.date_filter import DateFilter
from resc_backend.resc_web_service.schema.finding_status import FindingStatus
from resc_backend.resc_web_service.schema.scan_type import ScanType
from resc_backend.resc_web_service.schema.vcs_provider import VCSProviders

logger = logging.getLogger(__name__)


def patch_finding(db_connection: Session, finding_id: int, finding_update: finding_schema.FindingPatch):
    db_finding = db_connection.query(DBfinding).filter_by(id_=finding_id).first()

    finding_update_dict = finding_update.dict(exclude_unset=True)
    for key in finding_update_dict:
        setattr(db_finding, key, finding_update_dict[key])

    db_connection.commit()
    db_connection.refresh(db_finding)
    return db_finding


def _long_key(finding: DBfinding | finding_schema.FindingCreate) -> str:
    key = (
        f"{finding.commit_id}|{finding.rule_name}|{finding.file_path}"
        + f"|{finding.line_number}|{finding.column_start}|{finding.column_end}"
    )
    return key


def create_findings(db_connection: Session, findings: list[finding_schema.FindingCreate]) -> list[DBfinding]:
    if len(findings) < 1:
        # Function is called with an empty list of findings
        return []

    repository_id = findings[0].repository_id

    # get a list of known / registered findings for this repository
    query = db_connection.query(DBfinding)
    query = query.where(DBfinding.repository_id == repository_id)
    db_repository_findings = query.all()

    map_repository_finding: dict[str, DBfinding] = dict_of_list(_long_key, db_repository_findings)
    map_findings: dict[str, finding_schema.FindingCreate] = dict_of_list(_long_key, findings)

    intersection = map_findings.keys() & map_repository_finding.keys()

    db_findings: list[DBfinding] = []
    for key in intersection:
        db_findings.append(map_repository_finding.get(key))
        del map_findings[key]

    new_findings: list[finding_schema.FindingCreate] = map_findings.values()
    logger.info(
        f"create_findings repository {repository_id}, Requested: {len(findings)}. "
        f"New findings: {len(new_findings)}. Already in db: {len(db_findings)}"
    )

    db_create_findings = []
    # Map the to be created findings to the DBfinding type object
    for new_finding in new_findings:
        db_create_finding = DBfinding.create_from_finding(new_finding)
        db_create_findings.append(db_create_finding)
    # Store all the to be created findings in the database
    if len(db_create_findings) >= 1:
        db_connection.add_all(db_create_findings)
        db_connection.flush()
        db_connection.commit()
        db_findings.extend(db_create_findings)
    # Return the known findings that are part of the request and the newly created findings
    return db_findings


def _short_key(finding: DBfinding | finding_schema.FindingCreate) -> str:
    return f"{finding.rule_name}|{finding.file_path}|{finding.line_number}|{finding.column_start}|{finding.column_end}"


def create_or_update_findings(db_connection: Session, findings: list[finding_schema.FindingCreate]) -> list[DBfinding]:
    """
    Create or update findings.
    This is used in the case of rules which are applied to directories.

    Args:
        db_connection (Session): connection to DB
        findings (list[finding_schema.FindingCreate]): list of findings to create or update
        db_scan (DBscan): current scan (used for the new commit ID)

    Returns:
        list[DBfinding]: list of created findings
    """
    if len(findings) < 1:
        # Function is called with an empty list of findings
        return []

    repository_id = findings[0].repository_id

    # get a list of known / registered findings for this repository
    query = db_connection.query(DBfinding)
    query = query.where(DBfinding.repository_id == repository_id)
    db_repository_findings = query.all()

    map_repository_finding: dict[str, DBfinding] = dict_of_list(_short_key, db_repository_findings)
    map_findings: dict[str, finding_schema.FindingCreate] = dict_of_list(_short_key, findings)

    intersection = map_findings.keys() & map_repository_finding.keys()

    db_findings: list[DBfinding] = []
    for key in intersection:
        repository_finding = map_repository_finding.get(key)
        finding = map_findings.get(key)
        repository_finding.commit_id = finding.commit_id
        repository_finding.commit_message = finding.commit_message
        repository_finding.commit_timestamp = finding.commit_timestamp
        repository_finding.author = finding.author
        repository_finding.is_dir_scan = True
        db_findings.append(repository_finding)
        del map_findings[key]

    new_findings: list[finding_schema.FindingCreate] = map_findings.values()

    logger.info(
        f"create_or_update_findings repository {repository_id}, Requested: {len(findings)}. "
        f"New findings: {len(new_findings)}. Already in db: {len(db_findings)}"
    )

    db_create_findings = []
    # Map the to be created findings to the DBfinding type object
    for new_finding in new_findings:
        db_create_finding = DBfinding.create_from_finding(new_finding, is_dir_scan=True)
        db_create_findings.append(db_create_finding)

    # Store all the to be created findings in the database
    if len(db_create_findings) >= 1:
        db_connection.add_all(db_create_findings)

    if len(db_findings) > 0 or len(db_create_findings) > 0:
        db_connection.flush()
        db_connection.commit()

    db_findings.extend(db_create_findings)

    # Return the known findings that are part of the request and the newly created findings
    return db_findings


def get_finding(db_connection: Session, finding_id: int) -> DBfinding:
    finding = db_connection.query(DBfinding)
    finding = finding.where(DBfinding.id_ == finding_id).first()
    return finding


def count_findings(db_connection: Session, finding_ids: set[int]) -> int:
    query = db_connection.query(func.count(DBfinding.id_))
    query = query.where(DBfinding.id_.in_(finding_ids))
    return query.scalar()


def get_findings(db_connection: Session, skip: int = 0, limit: int = DEFAULT_RECORDS_PER_PAGE_LIMIT):
    limit_val = MAX_RECORDS_PER_PAGE_LIMIT if limit > MAX_RECORDS_PER_PAGE_LIMIT else limit
    findings = db_connection.query(DBfinding)
    findings = findings.order_by(DBfinding.id_).offset(skip).limit(limit_val).all()
    return findings


def get_scans_findings(
    db_connection,
    scan_ids: list[int],
    skip: int = 0,
    limit: int = DEFAULT_RECORDS_PER_PAGE_LIMIT,
    rules_filter: list[str] | None = None,
    statuses_filter: list[FindingStatus] | None = None,
) -> list[DBfinding]:
    """
        Retrieve all finding child objects of a scan object from the database
    :param db_connection:
        Session of the database connection
    :param scan_ids:
        ids of the parent scan object of which to retrieve finding objects
    :param skip:
        integer amount of records to skip to support pagination
    :param limit:
        integer amount of records to return, to support pagination
    :param rules_filter:
        optional, filter on rule name. Is used as a string contains filter
    :param statuses_filter:
        optional, filter on status of findings
    :return: [DBfinding]
        The output will contain a list of DBfinding type objects,
        or an empty list if no finding was found for the given scan_ids
    """
    if len(scan_ids) == 0:
        return []

    limit_val = MAX_RECORDS_PER_PAGE_LIMIT if limit > MAX_RECORDS_PER_PAGE_LIMIT else limit

    query: Query = db_connection.query(DBfinding)
    query = query.join(DBscanFinding, DBscanFinding.finding_id == DBfinding.id_)

    if statuses_filter:
        query = query.join(
            DBaudit,
            (DBaudit.finding_id == DBfinding.id_) & (DBaudit.is_latest == True),  # noqa: E712
            isouter=True,
        )

        if FindingStatus.NOT_ANALYZED.value in statuses_filter:
            query = query.where(
                DBaudit.status.in_(statuses_filter) | (DBaudit.status == None)  # noqa: E711
            )
        else:
            query = query.where(DBaudit.status.in_(statuses_filter))

    query = query.where(DBscanFinding.scan_id.in_(scan_ids))

    if rules_filter:
        query = query.where(DBfinding.rule_name.in_(rules_filter))

    query = query.order_by(DBfinding.id_)
    query = query.offset(skip).limit(limit_val)
    findings = query.all()
    return findings


def get_findings_from_repo_of_scan_as_dir(db_connection: Session, scan: DBscan) -> list[int]:
    """
    Retrieve all the findings which are:
     - tied to the repository of the scan
     - for the rule pack of the scan
     - which are not tied to the scan (in other words out-dated)

    Args:
        db_connection (Session): session
        scan (DBscan): scan to restrict with

    Returns:
        list[int]: list of ids of findings which are to be audited
    """

    query = select(DBfinding.id_)
    query = query.join(DBrule, DBrule.rule_name == DBfinding.rule_name)
    query = query.join(
        DBaudit,
        (DBaudit.finding_id == DBfinding.id_) & (DBaudit.is_latest == True),  # noqa: E712
        isouter=True,
    )
    query = query.where(DBrule.rule_pack == scan.rule_pack)
    query = query.where(DBfinding.repository_id == scan.repository_id)
    query = query.where(DBfinding.is_dir_scan == True)  # noqa: E712
    query = query.where(
        (DBaudit.status != FindingStatus.OUTDATED) | (DBaudit.status == None)  # noqa: E711
    )

    sub_query: Query = select(DBscanFinding.finding_id)
    sub_query = sub_query.where(DBscanFinding.scan_id == scan.id_)
    sub_query = sub_query.subquery()
    query = query.where(DBfinding.id_.not_in(sub_query))

    return db_connection.execute(query).scalars().all()


def get_untriaged_finding_outdated_for_current_scan(db_connection: Session, scan: DBscan) -> list[int]:
    """
    Retrieve all the findings which are:
     - tied to the repository of the scan
     - where the rule is not in the rule pack of the scan
     - which are not analyzed

    Args:
        db_connection (Session): session
        scan (DBscan): scan to restrict with

    Returns:
        list[int]: list of ids of findings which are to be audited
    """

    sub_query_rule_name: Query = select(DBrule.rule_name)
    sub_query_rule_name = sub_query_rule_name.where(DBrule.rule_pack == scan.rule_pack)
    sub_query_rule_name = sub_query_rule_name.subquery()

    query = select(DBfinding.id_)
    query = query.where(DBfinding.repository_id == scan.repository_id)
    query = query.where(DBfinding.rule_name.not_in(sub_query_rule_name))
    query = query.join(
        DBaudit,
        (DBaudit.finding_id == DBfinding.id_) & (DBaudit.is_latest == True),  # noqa: E712
        isouter=True,
    )
    query = query.where(
        (DBaudit.status == FindingStatus.NOT_ANALYZED) | (DBaudit.status == None)  # noqa: E711
    )

    return db_connection.execute(query).scalars().all()


def get_finding_for_repository(
    db_connection: Session, repository_ids: list[int], status: FindingStatus | None, not_status: FindingStatus | None
) -> list[int]:
    """
    Retrieve the findings associated to a repository.
    Optionally filter by status.

    Args:
        db_connection (Session): Database connection
        repository_id (int): repository id
        status (FindingStatus | None): Status to filter on.

    Returns:
        list[int]: List of finding ids
    """

    iterator = iter(repository_ids)
    db_audits = []
    while chunk := list(islice(iterator, 1000)):
        query = select(DBfinding.id_)
        query = query.where(DBfinding.repository_id.in_(chunk))

        # Set up the join for filtering
        if status is not None or not_status is not None:
            query = query.join(
                DBaudit,
                (DBaudit.finding_id == DBfinding.id_) & (DBaudit.is_latest == True),  # noqa: E712
                isouter=True,
            )

        # filter by status
        if status == FindingStatus.NOT_ANALYZED:
            query = query.where((DBaudit.status == FindingStatus.NOT_ANALYZED) | (DBaudit.status == None))  # noqa: E711
        elif status is not None:
            query = query.where(DBaudit.status == status)

        # filter by status negation.
        if not_status == FindingStatus.NOT_ANALYZED:
            query = query.where((DBaudit.status != FindingStatus.NOT_ANALYZED) & (DBaudit.status != None))  # noqa: E711
        elif not_status is not None:
            query = query.where((DBaudit.status != not_status) | (DBaudit.status == None))  # noqa: E711
        db_audits.extend(db_connection.execute(query).scalars().all())

    return db_audits


def get_total_findings_count(db_connection: Session, findings_filter: FindingsFilter = None) -> int:
    """
        Retrieve count of finding records of a given scan
    :param findings_filter:
    :param db_connection:
        Session of the database connection
    :return: total_count
        count of findings
    """

    query = db_connection.query(func.count(DBfinding.id_))

    if findings_filter:
        if findings_filter.finding_statuses:
            query = query.join(
                DBaudit,
                (DBaudit.finding_id == DBfinding.id_) & (DBaudit.is_latest == True),  # noqa: E712
                isouter=True,
            )

        if findings_filter.start_date_time or findings_filter.end_date_time:
            query = query.join(DBscanFinding, DBscanFinding.finding_id == DBfinding.id_)
            query = query.join(DBscan, DBscan.id_ == DBscanFinding.scan_id)

        if (
            findings_filter.vcs_providers
            and findings_filter.vcs_providers is not None
            or findings_filter.project_name
            or findings_filter.repository_name
            or not findings_filter.include_deleted_repositories
        ):
            query = query.join(DBrepository, DBrepository.id_ == DBfinding.repository_id)
            query = query.join(DBVcsInstance, DBVcsInstance.id_ == DBrepository.vcs_instance)

        if findings_filter.start_date_time:
            query = query.where(DBscan.timestamp >= findings_filter.start_date_time)
        if findings_filter.end_date_time:
            query = query.where(DBscan.timestamp <= findings_filter.end_date_time)

        if findings_filter.repository_name:
            query = query.where(DBrepository.repository_name == findings_filter.repository_name)

        if not findings_filter.include_deleted_repositories and findings_filter.end_date_time:
            query = query.where(
                (DBrepository.deleted_at == None)  # noqa: E711
                | (DBrepository.deleted_at > findings_filter.end_date_time)
            )
        elif not findings_filter.include_deleted_repositories:
            query = query.where(DBrepository.deleted_at == None)  # noqa: E711

        if findings_filter.vcs_providers and findings_filter.vcs_providers is not None:
            query = query.where(DBVcsInstance.provider_type.in_(findings_filter.vcs_providers))
        if findings_filter.project_name:
            query = query.where(DBrepository.project_key == findings_filter.project_name)
        if findings_filter.rule_names:
            query = query.where(DBfinding.rule_name.in_(findings_filter.rule_names))
        if findings_filter.finding_statuses:
            if FindingStatus.NOT_ANALYZED.value in findings_filter.finding_statuses:
                query = query.where(
                    DBaudit.status.in_(findings_filter.finding_statuses) | (DBaudit.status == None)  # noqa: E711
                )
            else:
                query = query.where(DBaudit.status.in_(findings_filter.finding_statuses))
        if findings_filter.scan_ids and len(findings_filter.scan_ids) == 1:
            query = query.join(DBscanFinding, DBscanFinding.finding_id == DBfinding.id_)
            query = query.where(DBscanFinding.scan_id == findings_filter.scan_ids[0])

        if findings_filter.scan_ids and len(findings_filter.scan_ids) >= 2:
            query = query.join(DBscanFinding, DBscanFinding.finding_id == DBfinding.id_)
            query = query.where(DBscanFinding.scan_id.in_(findings_filter.scan_ids))

    total_count = query.scalar()
    return total_count


def get_findings_by_rule(
    db_connection: Session,
    skip: int = 0,
    limit: int = DEFAULT_RECORDS_PER_PAGE_LIMIT,
    rule_name: str = "",
    include_deleted_repositories: bool = False,
):
    limit_val = MAX_RECORDS_PER_PAGE_LIMIT if limit > MAX_RECORDS_PER_PAGE_LIMIT else limit
    findings = db_connection.query(DBfinding)
    findings = findings.join(DBrepository, DBrepository.id_ == DBfinding.repository_id)
    findings = findings.where(DBfinding.rule_name == rule_name)
    if not include_deleted_repositories:
        findings = findings.where(DBrepository.deleted_at == None)  # noqa: E711

    findings = findings.order_by(DBfinding.id_).offset(skip).limit(limit_val).all()
    return findings


def get_distinct_rule_names_from_findings(
    db_connection: Session,
    scan_id: int = -1,
    finding_statuses: list[FindingStatus] = None,
    vcs_providers: list[VCSProviders] = None,
    project_name: str = "",
    repository_name: str = "",
    start_date_time: datetime = None,
    end_date_time: datetime = None,
    rule_pack_versions: list[str] = None,
    include_deleted_repositories: bool = False,
) -> list[str]:
    """
        Retrieve distinct rules detected
    :param db_connection:
        Session of the database connection
    :param scan_id:
        Optional filter by the id of a scan
    :param finding_statuses:
        Optional, filter of supported finding statuses
    :param vcs_providers:
        Optional, filter of supported vcs provider types
    :param project_name:
        Optional, filter on project name. Is used as a full string match filter
    :param repository_name:
        optional, filter on repository name. Is used as a string contains filter
    :param start_date_time:
        optional, filter on start date
    :param end_date_time:
        optional, filter on end date
    :param rule_pack_versions:
        optional, filter on rule pack version
    :return: rules
        List of unique rules
    """
    query = select(DBfinding.rule_name)

    if (start_date_time or end_date_time or rule_pack_versions) and scan_id < 0:
        query = query.join(DBscanFinding, DBscanFinding.finding_id == DBfinding.id_)
        query = query.join(DBscan, DBscan.id_ == DBscanFinding.scan_id)

    if vcs_providers or project_name or repository_name or not include_deleted_repositories:
        query = query.join(DBrepository, DBrepository.id_ == DBfinding.repository_id)
        query = query.join(DBVcsInstance, DBVcsInstance.id_ == DBrepository.vcs_instance)

    if finding_statuses:
        query = query.join(
            DBaudit,
            (DBaudit.finding_id == DBfinding.id_) & (DBaudit.is_latest == True),  # noqa: E712
            isouter=True,
        )

    if scan_id > 0:
        query = query.join(DBscanFinding, DBscanFinding.finding_id == DBfinding.id_)
        query = query.where(DBscanFinding.scan_id == scan_id)
    else:
        if finding_statuses:
            if FindingStatus.NOT_ANALYZED.value in finding_statuses:
                query = query.where(
                    DBaudit.status.in_(finding_statuses) | (DBaudit.status == None)  # noqa: E711
                )
            else:
                query = query.where(DBaudit.status.in_(finding_statuses))

        if vcs_providers:
            query = query.where(DBVcsInstance.provider_type.in_(vcs_providers))

        if project_name:
            query = query.where(DBrepository.project_key == project_name)

        if repository_name:
            query = query.where(DBrepository.repository_name == repository_name)

        if not include_deleted_repositories and end_date_time:
            query = query.where(
                (DBrepository.deleted_at == None)  # noqa: E711
                | (DBrepository.deleted_at > end_date_time)
            )
        elif not include_deleted_repositories:
            query = query.where(DBrepository.deleted_at == None)  # noqa: E711

        if start_date_time:
            query = query.where(DBscan.timestamp >= start_date_time)

        if end_date_time:
            query = query.where(DBscan.timestamp <= end_date_time)

        if rule_pack_versions:
            query = query.where(DBscan.rule_pack.in_(rule_pack_versions))

    query = query.distinct().order_by(DBfinding.rule_name)

    rules = db_connection.execute(query).scalars().all()

    return rules


def get_findings_count_by_status(
    db_connection: Session,
    scan_ids: list[int] = None,
    finding_statuses: list[FindingStatus] = None,
    rule_name: str = "",
    include_deleted_repositories: bool = False,
):
    """
        Retrieve count of findings based on finding status
    :param db_connection:
        Session of the database connection
    :param scan_ids:
        List of scan ids for which findings should be filtered
    :param finding_statuses:
        finding statuses to filter, type FindingStatus
    :param rule_name:
        rule_name to filter on
    :return: findings_count
        count of findings
    """
    query = db_connection.query(func.count(DBfinding.id_).label("status_count"), DBaudit.status)
    query = query.join(
        DBaudit,
        (DBaudit.finding_id == DBfinding.id_) & (DBaudit.is_latest == True),  # noqa: E712
        isouter=True,
    )

    if not include_deleted_repositories:
        query = query.join(DBrepository, DBrepository.id_ == DBfinding.repository_id)
        query = query.where(DBrepository.deleted_at == None)  # noqa: E711

    if scan_ids and len(scan_ids) > 0:
        query = query.join(DBscanFinding, DBscanFinding.finding_id == DBfinding.id_)
        query = query.join(DBscan, DBscan.id_ == DBscanFinding.scan_id)
        query = query.where(DBscan.id_.in_(scan_ids))

    if finding_statuses:
        if FindingStatus.NOT_ANALYZED.value in finding_statuses:
            query = query.where(
                DBaudit.status.in_(finding_statuses) | (DBaudit.status == None)  # noqa: E711
            )
        else:
            query = query.where(DBaudit.status.in_(finding_statuses))
    if rule_name:
        query = query.where(DBfinding.rule_name == rule_name)

    findings_count_by_status = query.group_by(DBaudit.status).all()

    return findings_count_by_status


def get_rule_findings_count_by_status(
    db_connection: Session,
    rule_pack_versions: list[str] = None,
    rule_tags: list[str] = None,
    include_deleted_repositories: bool = False,
):
    """
        Retrieve count of findings based on rulename and status
    :param db_connection:
        Session of the database connection
    :param rule_pack_versions:
        optional, filter on rule pack version
    :param rule_tags:
        optional, filter on rule tag
    :return: findings_count
        per rulename and status the count of findings
    """
    query = db_connection.query(DBfinding.rule_name, DBaudit.status, func.count(DBfinding.id_))

    if not include_deleted_repositories:
        query = query.join(DBrepository, DBrepository.id_ == DBfinding.repository_id)
        query = query.where(DBrepository.deleted_at == None)  # noqa: E711

    max_base_scan_subquery = db_connection.query(
        DBscan.repository_id, func.max(DBscan.id_).label("latest_base_scan_id")
    )
    max_base_scan_subquery = max_base_scan_subquery.where(DBscan.scan_type == ScanType.BASE)
    if rule_pack_versions:
        max_base_scan_subquery = max_base_scan_subquery.where(DBscan.rule_pack.in_(rule_pack_versions))
    max_base_scan_subquery: Query = max_base_scan_subquery.group_by(DBscan.repository_id).subquery()

    query = query.join(DBscanFinding, DBfinding.id_ == DBscanFinding.finding_id)
    query = query.join(
        max_base_scan_subquery,
        DBfinding.repository_id == max_base_scan_subquery.c.repository_id,
    )
    query = query.join(DBscan, (DBscanFinding.scan_id == DBscan.id_))
    query = query.where(DBscan.id_ >= max_base_scan_subquery.c.latest_base_scan_id)

    if rule_tags:
        rule_tag_subquery: Query = db_connection.query(DBruleTag.rule_id).join(DBtag, DBruleTag.tag_id == DBtag.id_)
        if rule_pack_versions:
            rule_tag_subquery = rule_tag_subquery.join(DBrule, DBrule.id_ == DBruleTag.rule_id)
            rule_tag_subquery = rule_tag_subquery.where(DBrule.rule_pack.in_(rule_pack_versions))

        rule_tag_subquery = rule_tag_subquery.where(DBtag.name.in_(rule_tags))
        rule_tag_subquery = rule_tag_subquery.group_by(DBruleTag.rule_id).subquery()

        query = query.join(
            DBrule,
            (DBrule.rule_name == DBfinding.rule_name) & (DBrule.rule_pack == DBscan.rule_pack),
        )
        query = query.join(rule_tag_subquery, DBrule.id_ == rule_tag_subquery.c.rule_id)

    if rule_pack_versions:
        query = query.where(DBscan.rule_pack.in_(rule_pack_versions))

    query = query.join(
        DBaudit,
        (DBaudit.finding_id == DBfinding.id_) & (DBaudit.is_latest == True),  # noqa: E712
        isouter=True,
    )
    query = query.group_by(DBfinding.rule_name, DBaudit.status)
    query = query.order_by(DBfinding.rule_name, DBaudit.status)
    status_counts = query.all()

    rule_count_dict = {}
    for status_count in status_counts:
        rule_name: str = status_count[0]
        rule_count_dict[rule_name] = FindingStatus.init_statistics()

    for status_count in status_counts:
        rule_name: str = status_count[0]
        count: int = status_count[2]
        finding_status: str | None = status_count[1]
        rule_count_dict[rule_name]["total_findings_count"] += count
        if finding_status is None:
            rule_count_dict[rule_name][FindingStatus.NOT_ANALYZED.value.lower()] += count
        else:
            rule_count_dict[rule_name][finding_status.lower()] += count

    return rule_count_dict


def get_findings_count_by_time(
    db_connection: Session,
    date_type: DateFilter,
    start_date_time: datetime = None,
    end_date_time: datetime = None,
    skip: int = 0,
    limit: int = DEFAULT_RECORDS_PER_PAGE_LIMIT,
):
    """
        Retrieve count based on date_type
    :param db_connection:
        Session of the database connection
    :param date_type:
        required, filter on time_type
    :param start_date_time:
        optional, filter on start date
    :param end_date_time:
        optional, filter on end date
    :param skip:
        integer amount of records to skip to support pagination
    :param limit:
        integer amount of records to return, to support pagination
    """
    if date_type == DateFilter.MONTH:
        query = db_connection.query(
            extract("year", DBscan.timestamp),
            extract("month", DBscan.timestamp),
            func.count(DBscanFinding.finding_id),
        )
    elif date_type == DateFilter.WEEK:
        query = db_connection.query(
            extract("year", DBscan.timestamp),
            extract("week", DBscan.timestamp),
            func.count(DBscanFinding.finding_id),
        )
    elif date_type == DateFilter.DAY:
        query = db_connection.query(
            extract("year", DBscan.timestamp),
            extract("month", DBscan.timestamp),
            extract("day", DBscan.timestamp),
            func.count(DBscanFinding.finding_id),
        )

    query: Query = query.join(DBscanFinding, DBscanFinding.scan_id == DBscan.id_)

    query = query.join(DBrepository, DBrepository.id_ == DBscan.repository_id)
    if end_date_time:
        query = query.where(
            (DBrepository.deleted_at == None)  # noqa: E711
            | (DBrepository.deleted_at > end_date_time)
        )
    else:
        query = query.where(DBrepository.deleted_at == None)  # noqa: E711

    if start_date_time:
        query = query.where(DBscan.timestamp >= start_date_time)
    if end_date_time:
        query = query.where(DBscan.timestamp <= end_date_time)

    if date_type == DateFilter.MONTH:
        query = query.group_by(extract("year", DBscan.timestamp), extract("month", DBscan.timestamp))
        query = query.order_by(extract("year", DBscan.timestamp), extract("month", DBscan.timestamp))
    elif date_type == DateFilter.WEEK:
        query = query.group_by(extract("year", DBscan.timestamp), extract("week", DBscan.timestamp))
        query = query.order_by(extract("year", DBscan.timestamp), extract("week", DBscan.timestamp))
    elif date_type == DateFilter.DAY:
        query = query.group_by(
            extract("year", DBscan.timestamp),
            extract("month", DBscan.timestamp),
            extract("day", DBscan.timestamp),
        )
        query = query.order_by(
            extract("year", DBscan.timestamp),
            extract("month", DBscan.timestamp),
            extract("day", DBscan.timestamp),
        )

    finding_count = query.offset(skip).limit(limit).all()
    return finding_count


def get_findings_count_by_time_total(
    db_connection: Session,
    date_type: DateFilter,
    start_date_time: datetime = None,
    end_date_time: datetime = None,
):
    """
        Retrieve total count on date_type
    :param db_connection:
        Session of the database connection
    :param date_type:
        required, filter on time_type
    :param start_date_time:
        optional, filter on start date
    :param end_date_time:
        optional, filter on end date
    """
    if date_type == DateFilter.MONTH:
        query: Query = db_connection.query(extract("year", DBscan.timestamp), extract("month", DBscan.timestamp))
    elif date_type == DateFilter.WEEK:
        query: Query = db_connection.query(extract("year", DBscan.timestamp), extract("week", DBscan.timestamp))
    elif date_type == DateFilter.DAY:
        query: Query = db_connection.query(
            extract("year", DBscan.timestamp),
            extract("month", DBscan.timestamp),
            extract("day", DBscan.timestamp),
        )

    query = query.join(DBscanFinding, DBscan.id_ == DBscanFinding.scan_id)
    query = query.join(DBrepository, DBrepository.id_ == DBscan.repository_id)
    if end_date_time:
        query = query.where(
            (DBrepository.deleted_at == None)  # noqa: E711
            | (DBrepository.deleted_at > end_date_time)
        )
    else:
        query = query.where(DBrepository.deleted_at == None)  # noqa: E711

    if start_date_time:
        query = query.where(DBscan.timestamp >= start_date_time)
    if end_date_time:
        query = query.where(DBscan.timestamp <= end_date_time)

    query = query.distinct()

    result = query.count()
    return result


def get_distinct_rules_from_scans(db_connection: Session, scan_ids: list[int] = None) -> list[DBrule]:
    """
        Retrieve distinct rules detected
    :param db_connection:
        Session of the database connection
    :param scan_ids:
        List of scan ids
    :return: rules
        List of unique rules
    """
    query = db_connection.query(DBfinding.rule_name)

    if scan_ids:
        query = query.join(DBscanFinding, DBscanFinding.finding_id == DBfinding.id_)
        query = query.where(DBscanFinding.scan_id.in_(scan_ids))

    query = query.distinct()
    query = query.order_by(DBfinding.rule_name)
    rules = query.all()
    return rules


def delete_finding(db_connection: Session, finding_id: int, delete_related: bool = False):
    """
        Delete a finding object
    :param db_connection:
        Session of the database connection
    :param finding_id:
        id of the finding to be deleted
    :param delete_related:
        if related records need to be deleted
    """
    if delete_related:
        scan_finding_crud.delete_scan_finding(db_connection, finding_id=finding_id)

    db_connection.query(DBfinding).where(DBfinding.id_ == finding_id).delete(synchronize_session=False)
    db_connection.commit()


def delete_findings_by_repository_id(db_connection: Session, repository_id: int):
    """
        Delete findings for a given repository
    :param db_connection:
        Session of the database connection
    :param repository_id:
        id of the repository
    """
    db_connection.query(DBfinding).where(DBfinding.repository_id == repository_id).delete(synchronize_session=False)
    db_connection.commit()


def delete_findings_by_vcs_instance_id(db_connection: Session, vcs_instance_id: int):
    """
        Delete findings for a given vcs instance
    :param db_connection:
        Session of the database connection
    :param vcs_instance_id:
        id of the vcs instance
    """
    db_connection.query(DBfinding).where(
        DBfinding.repository_id == DBrepository.id_,
        DBrepository.vcs_instance == DBVcsInstance.id_,
        DBVcsInstance.id_ == vcs_instance_id,
    ).delete(synchronize_session=False)
    db_connection.commit()


def _get_iso_date_now_diff_week(week: int) -> datetime:
    """
        Taking now() computes the timestamp associated to the
        ISO calendar year.

    Args:
        week (int): Number of weeks to substract to the timestamp.

    Returns:
        datetime: shifted iso time stamp for easier computations.
    """
    current_utc_time = datetime.now(UTC)
    current_iso = current_utc_time.isocalendar()
    current_iso_year = current_iso[0]
    current_iso_week = current_iso[1]
    # We use 6 (Saturday) to include the current week when 0
    # rather than doing a shift from current day.
    last_nth_week_date_time = datetime.fromisocalendar(current_iso_year, current_iso_week, 6) - timedelta(weeks=week)
    return last_nth_week_date_time


def _max_base_scan_subequery(db_connection: Session, last_nth_week_date_time: datetime) -> Query:
    """
        Creates a subquery given a cut-off date to have the max base scan
        per repository

    Args:
        db_connection (Session): Session to generate the subquery
        last_nth_week_date_time (datetime): max cut-off date

    Returns:
        Query: subquery to have the max base scan under a cut-off date
    """
    subquery: Query = db_connection.query(func.max(DBscan.id_).label("scan_id"), DBscan.repository_id)
    subquery = subquery.where(DBscan.timestamp <= last_nth_week_date_time)
    subquery = subquery.where(DBscan.scan_type == ScanType.BASE)
    subquery = subquery.group_by(DBscan.repository_id)
    return subquery.subquery()


def _max_audit_subequery(db_connection: Session, last_nth_week_date_time: datetime) -> Query:
    """
        Creates a subquery given a cut-off date to have the last audit
        per finding

    Args:
        db_connection (Session): Session to generate the subquery
        last_nth_week_date_time (datetime): max cut-off date

    Returns:
        Query: subquery to have the last audit under a cut-off date
    """
    subquery: Query = db_connection.query(func.max(DBaudit.id_).label("audit_id"), DBaudit.finding_id)
    subquery = subquery.where(DBaudit.timestamp < last_nth_week_date_time)
    subquery = subquery.group_by(DBaudit.finding_id)
    return subquery.subquery()


def get_finding_audit_status_count_over_time(db_connection: Session, status: FindingStatus, weeks: int = 13) -> dict:
    """
        Retrieve count of true positive findings over time for given weeks
    :param db_connection:
        Session of the database connection
    :param status:
        mandatory, status for which to get the audit counts over time
    :param weeks:
        optional, filter on last n weeks, default 13
    :return: true_positive_count_over_time
        list of rows containing finding statuses count over time per week
    """
    all_tables = []
    for week in range(0, weeks):
        last_nth_week_date_time = _get_iso_date_now_diff_week(week)
        max_audit_subquery = _max_audit_subequery(db_connection, last_nth_week_date_time)

        query = db_connection.query(
            literal_column(str(last_nth_week_date_time.isocalendar()[0])).label("year"),
            literal_column(str(last_nth_week_date_time.isocalendar()[1])).label("week"),
            DBVcsInstance.provider_type.label("provider_type"),
            func.count(DBaudit.id_).label("finding_count"),
        )
        query = query.join(max_audit_subquery, max_audit_subquery.c.audit_id == DBaudit.id_)
        query = query.join(DBfinding, DBfinding.id_ == DBaudit.finding_id)
        query = query.join(DBrepository, DBrepository.id_ == DBfinding.repository_id)
        query = query.join(DBVcsInstance, DBVcsInstance.id_ == DBrepository.vcs_instance)
        query = query.where(DBaudit.status == status)
        query = query.where(
            (DBrepository.deleted_at == None)  # noqa: E711
            | (DBrepository.deleted_at > last_nth_week_date_time)
        )
        query = query.group_by(DBVcsInstance.provider_type)

        all_tables.append(query)

    # union
    unioned_query = union(*all_tables)
    status_count_over_time = db_connection.execute(unioned_query).all()
    return status_count_over_time


def get_finding_count_by_vcs_provider_over_time(db_connection: Session, weeks: int = 13) -> list[Row]:
    """
        Retrieve count findings over time for given weeks
    :param db_connection:
        Session of the database connection
    :param weeks:
        optional, filter on last n weeks, default 13
    :return: count_over_time
        list of rows containing finding count over time per week
    """
    all_tables = []
    for week in range(0, weeks):
        last_nth_week_date_time = _get_iso_date_now_diff_week(week)

        max_base_scan = _max_base_scan_subequery(db_connection, last_nth_week_date_time)

        query = db_connection.query(
            literal_column(str(last_nth_week_date_time.isocalendar()[0])).label("year"),
            literal_column(str(last_nth_week_date_time.isocalendar()[1])).label("week"),
            DBVcsInstance.provider_type.label("provider_type"),
            func.count(DBfinding.id_).label("finding_count"),
        )
        query = query.join(DBscanFinding, DBfinding.id_ == DBscanFinding.finding_id)
        query = query.join(DBscan, DBscan.id_ == DBscanFinding.scan_id)
        query = query.join(max_base_scan, max_base_scan.c.repository_id == DBscan.repository_id)
        query = query.where(DBscan.id_ >= max_base_scan.c.scan_id)
        query = query.where(DBscan.timestamp <= last_nth_week_date_time)
        query = query.join(DBrepository, DBrepository.id_ == DBscan.repository_id)
        query = query.join(DBVcsInstance, DBVcsInstance.id_ == DBrepository.vcs_instance)
        query = query.where(
            (DBrepository.deleted_at == None)  # noqa: E711
            | (DBrepository.deleted_at > last_nth_week_date_time)
        )
        query = query.group_by(DBVcsInstance.provider_type)

        all_tables.append(query)

    # union
    unioned_query = union(*all_tables)
    count_over_time = db_connection.execute(unioned_query).all()
    return count_over_time


def get_untriaged_finding_count_by_vcs_provider_over_time(db_connection: Session, weeks: int = 13) -> list[Row]:
    """
        Retrieve count of un triaged findings over time for given weeks
    :param db_connection:
        Session of the database connection
    :param weeks:
        optional, filter on last n weeks, default 13
    :return: count_over_time
        list of rows containing un triaged findings count over time per week
    """
    all_tables = []
    for week in range(0, weeks):
        last_nth_week_date_time = _get_iso_date_now_diff_week(week)
        max_base_scan = _max_base_scan_subequery(db_connection, last_nth_week_date_time)
        max_audit_subquery = _max_audit_subequery(db_connection, last_nth_week_date_time)

        query = db_connection.query(
            literal_column(str(last_nth_week_date_time.isocalendar()[0])).label("year"),
            literal_column(str(last_nth_week_date_time.isocalendar()[1])).label("week"),
            DBVcsInstance.provider_type.label("provider_type"),
            func.count(DBfinding.id_).label("finding_count"),
        )
        query = query.join(DBscanFinding, DBfinding.id_ == DBscanFinding.finding_id)
        query = query.join(DBscan, DBscan.id_ == DBscanFinding.scan_id)
        query = query.join(DBrepository, DBrepository.id_ == DBscan.repository_id)
        query = query.join(DBVcsInstance, DBVcsInstance.id_ == DBrepository.vcs_instance)
        query = query.join(max_base_scan, max_base_scan.c.repository_id == DBscan.repository_id)
        query = query.where(DBscan.id_ >= max_base_scan.c.scan_id)
        query = query.where(DBscan.timestamp <= last_nth_week_date_time)
        query = query.where(
            (DBrepository.deleted_at == None)  # noqa: E711
            | (DBrepository.deleted_at > last_nth_week_date_time)
        )
        query = query.join(
            max_audit_subquery,
            max_audit_subquery.c.finding_id == DBfinding.id_,
            isouter=True,
        )
        query = query.join(
            DBaudit,
            (DBaudit.finding_id == DBfinding.id_) & (DBaudit.id_ == max_audit_subquery.c.audit_id),
            isouter=True,
        )
        query = query.where(
            (DBaudit.id_ == None) | (DBaudit.status == FindingStatus.NOT_ANALYZED.value)  # noqa: E711
        )
        query = query.group_by(DBVcsInstance.provider_type)
        all_tables.append(query)

    # union
    unioned_query = union(*all_tables)
    count_over_time = db_connection.execute(unioned_query).all()
    return count_over_time


def query_untriaged_findings_for_rule_pack(query: Query, version: str | Column[str]) -> Query:
    query = query.join(DBfinding, DBfinding.id_ == DBscanFinding.finding_id)
    query = query.join(DBscan, DBscan.id_ == DBscanFinding.scan_id)
    query = query.join(DBrule, DBrule.rule_name == DBfinding.rule_name)
    query = query.join(
        DBaudit,
        (DBaudit.finding_id == DBfinding.id_) & (DBaudit.is_latest == True),  # noqa: E712
        isouter=True,
    )
    query = query.where(DBrule.rule_pack == version)
    query = query.where(DBscan.rule_pack == version)
    query = query.where((DBaudit.status == FindingStatus.NOT_ANALYZED) | (DBaudit.status == None))  # noqa: E711
    return query


def get_untriaged_finding_for_old_rulepacks(db_connection: Session, version: str) -> list[int]:
    # Select the age of the version.
    age_query: Query = select(DBrulePack.created)
    age_query = age_query.where(DBrulePack.version == version)
    age_query = age_query.scalar_subquery()

    # Select the findings that appears in scan more recent that version
    do_not_touch_finding_query: Query = select(DBscanFinding.finding_id)
    do_not_touch_finding_query = do_not_touch_finding_query.join(DBscan, DBscan.id_ == DBscanFinding.scan_id)
    do_not_touch_finding_query = do_not_touch_finding_query.join(DBrulePack, DBrulePack.version == DBscan.rule_pack)
    do_not_touch_finding_query = do_not_touch_finding_query.where(DBrulePack.created > age_query)
    do_not_touch_finding_query = do_not_touch_finding_query.scalar_subquery()

    query: Query = select(DBfinding.id_)
    query = query.join(
        DBaudit,
        (DBaudit.finding_id == DBfinding.id_) & (DBaudit.is_latest == True),  # noqa: E712
        isouter=True,
    )
    query = query.where((DBaudit.status == None) | (DBaudit.status == FindingStatus.NOT_ANALYZED))  # noqa: E711
    query = query.where(DBfinding.id_.not_in(do_not_touch_finding_query))
    # We limit to 100 000 because otherwise it crashes because too many data
    query = query.limit(100_000)

    return db_connection.execute(query).scalars().all()

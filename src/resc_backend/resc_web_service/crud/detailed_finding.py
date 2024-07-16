# Standard Library

# Third Party
from sqlalchemy import func
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
    DBrule,
    DBruleTag,
    DBscan,
    DBscanFinding,
    DBtag,
    DBVcsInstance,
)
from resc_backend.resc_web_service.filters import FindingsFilter
from resc_backend.resc_web_service.schema import (
    detailed_finding as detailed_finding_schema,
)
from resc_backend.resc_web_service.schema.finding_status import FindingStatus
from resc_backend.resc_web_service.schema.scan_type import ScanType


def _query_join_if_multiple_rule_pack(query: Query, rule_pack_versions: list[str]) -> Query:
    """
    When we are working with rule pack it is sometimes necessary to use a join
    with a subquery (i.e. when there are 0 or > 1 rule pack selected).

    This takes care of the join of the sub query.

    Note that the filtering per rulepack is not applied here. We only search for the max
    base scan id for the specific set of rulepacks.

    Args:
        query (Query): Query to work on
        rule_pack_versions (List[str]): rule pack versions to filter on.

    Returns:
        Query: Updated query
    """
    if rule_pack_versions is not None and len(rule_pack_versions) == 1:
        return query

    subquery: Query = query.session.query(DBscan.repository_id, func.max(DBscan.id_).label("latest_base_scan_id"))

    # This contraint is not necessary, but it will make the table smaller.
    subquery = subquery.where(DBscan.is_latest == True)  # noqa: E712
    subquery = subquery.where(DBscan.scan_type == ScanType.BASE)
    if rule_pack_versions is not None and len(rule_pack_versions) > 0:
        subquery = subquery.where(DBscan.rule_pack.in_(rule_pack_versions))
    subquery = subquery.group_by(DBscan.repository_id)
    subquery = subquery.subquery()

    query = query.join(
        subquery,
        DBfinding.repository_id == subquery.c.repository_id,
    )
    query = query.where(DBscan.id_ >= subquery.c.latest_base_scan_id)

    return query


def _query_join_if_rule_tag(query: Query, rule_tags: list[str]) -> Query:
    """
    When we are working with a set of Rule tag with need to join a few extra tables.
    This filtering requires a few extra tables, hence if the field is None,
    we do not apply the join.

    Args:
        query (Query): query to join on.
        rule_tags (List[str] | None): tags to apply filter.

    Returns:
        Query: query with rule tag filtering applied
    """
    if rule_tags is None:
        return query

    subquery: Query = query.session.query(DBruleTag.rule_id)
    subquery = subquery.join(DBtag, DBruleTag.tag_id == DBtag.id_)
    subquery = subquery.where(DBtag.name.in_(rule_tags))
    subquery = subquery.group_by(DBruleTag.rule_id)
    subquery = subquery.subquery()

    query = query.join(
        DBrule,
        (DBrule.rule_name == DBfinding.rule_name) & (DBrule.rule_pack == DBscan.rule_pack),
    )
    query = query.where(DBrule.id_.in_(subquery))
    return query


def _query_apply_findings_filters(query: Query, findings_filter: FindingsFilter) -> Query:
    """
    Apply filtering on the query.
    This only applies filtering for:
        - rule_pack_versions
        - scan_ids
        - rule_names
        - start_date_time
        - event_sent
        - repository_name
        - vcs_providers
        - project_name
        - finding_statuses

    Args:
        query (Query): query to join on.
        findings_filter (FindingsFilter): Filters to apply.

    Returns:
        Query: query with filtering applied
    """
    if findings_filter.rule_pack_versions is not None:
        query = (
            query.where(DBscan.rule_pack == findings_filter.rule_pack_versions[0])
            if len(findings_filter.rule_pack_versions) == 1
            else query.where(DBscan.rule_pack.in_(findings_filter.rule_pack_versions))
        )

    if findings_filter.scan_ids:
        query = query.where(
            DBscan.id_.in_(findings_filter.scan_ids),
        )
    else:
        query = query.where(DBscan.is_latest == True)  # noqa: E712

    if findings_filter.rule_names:
        query = query.where(DBfinding.rule_name.in_(findings_filter.rule_names))

    if findings_filter.start_date_time:
        query = query.where(DBscan.timestamp >= findings_filter.start_date_time)

    if findings_filter.end_date_time:
        query = query.where(DBscan.timestamp <= findings_filter.end_date_time)

    if findings_filter.event_sent is not None:
        if findings_filter.event_sent:
            query = query.where(DBfinding.event_sent_on != None)  # noqa: E711
        else:
            query = query.where(DBfinding.event_sent_on == None)  # noqa: E711

    if not findings_filter.include_deleted_repositories and findings_filter.end_date_time:
        query = query.where(
            (DBrepository.deleted_at == None)  # noqa: E711
            | (DBrepository.deleted_at > findings_filter.end_date_time)
        )
    elif not findings_filter.include_deleted_repositories:
        query = query.where(DBrepository.deleted_at == None)  # noqa: E711

    if findings_filter.repository_name:
        query = query.where(DBrepository.repository_name == findings_filter.repository_name)

    if findings_filter.vcs_providers and findings_filter.vcs_providers is not None:
        query = query.where(DBVcsInstance.provider_type.in_(findings_filter.vcs_providers))

    if findings_filter.project_name:
        query = query.where(DBrepository.project_key == findings_filter.project_name)

    if findings_filter.finding_statuses:
        if FindingStatus.NOT_ANALYZED.value in findings_filter.finding_statuses:
            query = query.where(
                (DBaudit.status.in_(findings_filter.finding_statuses)) | (DBaudit.status == None)  # noqa: E711
            )
        else:
            query = query.where(DBaudit.status.in_(findings_filter.finding_statuses))
    return query


def get_detailed_findings(
    db_connection: Session,
    findings_filter: FindingsFilter,
    skip: int = 0,
    limit: int = DEFAULT_RECORDS_PER_PAGE_LIMIT,
) -> list[detailed_finding_schema.DetailedFindingRead]:
    """
    Retrieve all detailed findings objects matching the provided FindingsFilter
    :param findings_filter:
        Object of type FindingsFilter, only DetailedFindingRead objects matching the attributes in this filter will be
            fetched
    :param db_connection:
        Session of the database connection
    :param skip:
        integer amount of records to skip to support pagination
    :param limit:
        integer amount of records to return, to support pagination
    :return: [DetailedFindingRead]
        The output will contain a list of DetailedFindingRead objects,
        or an empty list if no finding was found for the given findings_filter
    """

    limit_val = MAX_RECORDS_PER_PAGE_LIMIT if limit > MAX_RECORDS_PER_PAGE_LIMIT else limit

    query = db_connection.query(
        DBfinding.id_,
        DBfinding.file_path,
        DBfinding.line_number,
        DBfinding.column_start,
        DBfinding.column_end,
        DBfinding.commit_id,
        DBfinding.commit_message,
        DBfinding.commit_timestamp,
        DBfinding.author,
        DBfinding.email,
        DBfinding.is_dir_scan,
        DBaudit.status,
        DBaudit.comment,
        DBfinding.rule_name,
        DBscan.rule_pack,
        DBfinding.event_sent_on,
        DBscan.timestamp,
        DBscan.id_.label("scan_id"),
        DBscan.last_scanned_commit,
        DBVcsInstance.provider_type.label("vcs_provider"),
        DBrepository.project_key,
        DBrepository.repository_name,
        DBrepository.repository_url,
    )
    # Prepare the joins, then we do the filtering.
    # There are no benefits in doing filtering on Where rather than On as we are doing Inner joins.
    # Source: https://stackoverflow.com/questions/2509987/which-sql-query-is-faster-filter-on-join-criteria-or-where-clause
    # The goal here is to avoid sub queries.
    query = query.join(DBscanFinding, DBfinding.id_ == DBscanFinding.finding_id)
    query = query.join(DBrepository, DBfinding.repository_id == DBrepository.id_)
    query = query.join(DBVcsInstance, DBrepository.vcs_instance == DBVcsInstance.id_)
    query = query.join(DBscan, DBscanFinding.scan_id == DBscan.id_)
    query = _query_join_if_multiple_rule_pack(query, findings_filter.rule_pack_versions)
    query = _query_join_if_rule_tag(query, findings_filter.rule_tags)
    query = query.join(
        DBaudit,
        (DBaudit.finding_id == DBfinding.id_) & (DBaudit.is_latest == True),  # noqa: E712
        isouter=True,
    )
    query = _query_apply_findings_filters(query, findings_filter)
    query = query.order_by(DBfinding.id_)
    query = query.offset(skip).limit(limit_val)
    findings: list[detailed_finding_schema.DetailedFindingRead] = query.all()

    return findings


def get_detailed_findings_count(db_connection: Session, findings_filter: FindingsFilter) -> int:
    """
    Retrieve count of detailed findings objects matching the provided FindingsFilter
    :param findings_filter:
        Object of type FindingsFilter, only DetailedFindingRead objects matching the attributes in this filter will be
            fetched
    :param db_connection:
        Session of the database connection
    :return: total_count
        count of findings
    """

    query = db_connection.query(func.count(DBfinding.id_))
    # Prepare the joins, then we do the filtering.
    # There are no benefits in doing filtering on Where rather than On as we are doing Inner joins.
    # Source: https://stackoverflow.com/questions/2509987/which-sql-query-is-faster-filter-on-join-criteria-or-where-clause
    # The goal here is to avoid sub queries.
    query = query.join(DBscanFinding, DBfinding.id_ == DBscanFinding.finding_id)
    query = query.join(DBrepository, DBfinding.repository_id == DBrepository.id_)
    query = query.join(DBVcsInstance, DBrepository.vcs_instance == DBVcsInstance.id_)
    query = query.join(DBscan, DBscanFinding.scan_id == DBscan.id_)
    query = _query_join_if_multiple_rule_pack(query, findings_filter.rule_pack_versions)
    query = _query_join_if_rule_tag(query, findings_filter.rule_tags)
    query = query.join(
        DBaudit,
        (DBaudit.finding_id == DBfinding.id_) & (DBaudit.is_latest == True),  # noqa: E712
        isouter=True,
    )
    query = _query_apply_findings_filters(query, findings_filter)
    findings_count = query.scalar()
    return findings_count


def get_detailed_finding(db_connection: Session, finding_id: int) -> detailed_finding_schema.DetailedFindingRead:
    """
    Retrieve a detailed finding objects matching the provided finding_id
    :param db_connection:
        Session of the database connection
    :param finding_id:
        ID of the finding object for which a DetailedFinding is to be fetched
    :return: DetailedFindingRead
        The output will contain an object of type DetailedFindingRead,
            or a null object finding was found for the given finding_id
    """
    query = (
        db_connection.query(
            DBfinding.id_,
            DBfinding.file_path,
            DBfinding.line_number,
            DBfinding.column_start,
            DBfinding.column_end,
            DBfinding.commit_id,
            DBfinding.commit_message,
            DBfinding.commit_timestamp,
            DBfinding.author,
            DBfinding.email,
            DBfinding.is_dir_scan,
            DBaudit.status,
            DBaudit.comment,
            DBfinding.rule_name,
            DBscan.rule_pack,
            DBscan.timestamp,
            DBscan.id_.label("scan_id"),
            DBscan.last_scanned_commit,
            DBVcsInstance.provider_type.label("vcs_provider"),
            DBrepository.project_key,
            DBrepository.repository_name,
            DBrepository.repository_url,
        )
        .join(DBscanFinding, DBfinding.id_ == DBscanFinding.finding_id)
        .join(
            DBscan,
            (DBscan.id_ == DBscanFinding.scan_id) & (DBscan.is_latest == True),  # noqa: E712
        )
        .join(DBrepository, DBrepository.id_ == DBscan.repository_id)
        .join(DBVcsInstance, DBVcsInstance.id_ == DBrepository.vcs_instance)
        .join(
            DBaudit,
            (DBaudit.finding_id == DBfinding.id_) & (DBaudit.is_latest == True),  # noqa: E712
            isouter=True,
        )
        .where(DBfinding.id_ == finding_id)
        .order_by(DBscan.id_.desc())
    )
    finding = query.first()
    return finding

# Standard Library
from typing import List

# Third Party
from sqlalchemy import and_, func, or_
from sqlalchemy.orm import Session

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


def get_detailed_findings(
    db_connection: Session,
    findings_filter: FindingsFilter,
    skip: int = 0,
    limit: int = DEFAULT_RECORDS_PER_PAGE_LIMIT,
) -> List[detailed_finding_schema.DetailedFindingRead]:
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
    max_base_scan_subquery = db_connection.query(
        DBscan.repository_id, func.max(DBscan.id_).label("latest_base_scan_id")
    )
    max_base_scan_subquery = max_base_scan_subquery.filter(
        DBscan.scan_type == ScanType.BASE
    )
    if findings_filter.rule_pack_versions:
        max_base_scan_subquery = max_base_scan_subquery.filter(
            DBscan.rule_pack.in_(findings_filter.rule_pack_versions)
        )
    max_base_scan_subquery = max_base_scan_subquery.group_by(
        DBscan.repository_id
    ).subquery()

    # subquery to select latest audit ids of findings
    max_audit_subquery = (
        db_connection.query(DBaudit.finding_id, func.max(DBaudit.id_).label("audit_id"))
        .group_by(DBaudit.finding_id)
        .subquery()
    )

    rule_tag_subquery = db_connection.query(DBruleTag.rule_id).join(
        DBtag, DBruleTag.tag_id == DBtag.id_
    )
    if findings_filter.rule_tags:
        rule_tag_subquery = rule_tag_subquery.filter(
            DBtag.name.in_(findings_filter.rule_tags)
        )
    if findings_filter.rule_pack_versions or findings_filter.rule_names:
        rule_tag_subquery = rule_tag_subquery.join(
            DBrule, DBrule.id_ == DBruleTag.rule_id
        )
        if findings_filter.rule_pack_versions:
            rule_tag_subquery = rule_tag_subquery.filter(
                DBrule.rule_pack.in_(findings_filter.rule_pack_versions)
            )
        if findings_filter.rule_names:
            rule_tag_subquery = rule_tag_subquery.filter(
                DBrule.rule_name.in_(findings_filter.rule_names)
            )
    rule_tag_subquery = rule_tag_subquery.group_by(DBruleTag.rule_id).subquery()

    limit_val = (
        MAX_RECORDS_PER_PAGE_LIMIT if limit > MAX_RECORDS_PER_PAGE_LIMIT else limit
    )

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
    query = query.join(DBscanFinding, DBfinding.id_ == DBscanFinding.finding_id)
    if findings_filter.scan_ids:
        query = query.join(
            DBscan,
            and_(
                DBscanFinding.scan_id == DBscan.id_,
                DBscan.id_.in_(findings_filter.scan_ids),
            ),
        )
    else:
        query = query.join(
            max_base_scan_subquery,
            DBfinding.repository_id == max_base_scan_subquery.c.repository_id,
        )
        query = query.join(
            DBscan,
            and_(
                DBscanFinding.scan_id == DBscan.id_,
                DBscan.id_ >= max_base_scan_subquery.c.latest_base_scan_id,
            ),
        )
    query = query.join(DBrepository, DBrepository.id_ == DBfinding.repository_id).join(
        DBVcsInstance, DBVcsInstance.id_ == DBrepository.vcs_instance
    )
    query = query.join(
        max_audit_subquery,
        max_audit_subquery.c.finding_id == DBfinding.id_,
        isouter=True,
    )
    query = query.join(
        DBaudit,
        and_(
            DBaudit.finding_id == DBfinding.id_,
            DBaudit.id_ == max_audit_subquery.c.audit_id,
        ),
        isouter=True,
    )

    if findings_filter.rule_tags:
        query = query.join(
            DBrule,
            and_(
                DBrule.rule_name == DBfinding.rule_name,
                DBrule.rule_pack == DBscan.rule_pack,
            ),
        )
        query = query.join(rule_tag_subquery, DBrule.id_ == rule_tag_subquery.c.rule_id)

    if findings_filter.rule_pack_versions:
        query = query.filter(DBscan.rule_pack.in_(findings_filter.rule_pack_versions))
    if findings_filter.start_date_time:
        query = query.filter(DBscan.timestamp >= findings_filter.start_date_time)
    if findings_filter.end_date_time:
        query = query.filter(DBscan.timestamp <= findings_filter.end_date_time)

    if findings_filter.event_sent is not None:
        if findings_filter.event_sent:
            query = query.filter(DBfinding.event_sent_on.is_not(None))
        else:
            query = query.filter(DBfinding.event_sent_on.is_(None))

    if findings_filter.repository_name:
        query = query.filter(
            DBrepository.repository_name == findings_filter.repository_name
        )
    if findings_filter.vcs_providers and findings_filter.vcs_providers is not None:
        query = query.filter(
            DBVcsInstance.provider_type.in_(findings_filter.vcs_providers)
        )
    if findings_filter.project_name:
        query = query.filter(DBrepository.project_key == findings_filter.project_name)
    if findings_filter.rule_names:
        query = query.filter(DBfinding.rule_name.in_(findings_filter.rule_names))
    if findings_filter.finding_statuses:
        if FindingStatus.NOT_ANALYZED in findings_filter.finding_statuses:
            query = query.filter(
                or_(
                    DBaudit.status.in_(findings_filter.finding_statuses),
                    DBaudit.status == None,  # noqa: E711
                )
            )
        else:
            query = query.filter(DBaudit.status.in_(findings_filter.finding_statuses))

    query = query.order_by(DBfinding.id_)
    query = query.offset(skip).limit(limit_val)
    findings: List[detailed_finding_schema.DetailedFindingRead] = query.all()

    return findings


def get_detailed_findings_count(
    db_connection: Session, findings_filter: FindingsFilter
) -> int:
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
    # subquery to select latest audit ids of findings
    max_audit_subquery = (
        db_connection.query(DBaudit.finding_id, func.max(DBaudit.id_).label("audit_id"))
        .group_by(DBaudit.finding_id)
        .subquery()
    )

    max_base_scan_subquery = db_connection.query(
        DBscan.repository_id, func.max(DBscan.id_).label("latest_base_scan_id")
    )
    max_base_scan_subquery = max_base_scan_subquery.filter(
        DBscan.scan_type == ScanType.BASE
    )
    if findings_filter.rule_pack_versions:
        max_base_scan_subquery = max_base_scan_subquery.filter(
            DBscan.rule_pack.in_(findings_filter.rule_pack_versions)
        )
    max_base_scan_subquery = max_base_scan_subquery.group_by(
        DBscan.repository_id
    ).subquery()

    rule_tag_subquery = db_connection.query(DBruleTag.rule_id).join(
        DBtag, DBruleTag.tag_id == DBtag.id_
    )
    if findings_filter.rule_tags:
        rule_tag_subquery = rule_tag_subquery.filter(
            DBtag.name.in_(findings_filter.rule_tags)
        )
    if findings_filter.rule_pack_versions or findings_filter.rule_names:
        rule_tag_subquery = rule_tag_subquery.join(
            DBrule, DBrule.id_ == DBruleTag.rule_id
        )
        if findings_filter.rule_pack_versions:
            rule_tag_subquery = rule_tag_subquery.filter(
                DBrule.rule_pack.in_(findings_filter.rule_pack_versions)
            )
        if findings_filter.rule_names:
            rule_tag_subquery = rule_tag_subquery.filter(
                DBrule.rule_name.in_(findings_filter.rule_names)
            )
    rule_tag_subquery = rule_tag_subquery.group_by(DBruleTag.rule_id).subquery()

    query = db_connection.query(func.count(DBfinding.id_))

    query = query.join(DBscanFinding, DBfinding.id_ == DBscanFinding.finding_id)
    if findings_filter.scan_ids:
        query = query.join(
            DBscan,
            and_(
                DBscanFinding.scan_id == DBscan.id_,
                DBscan.id_.in_(findings_filter.scan_ids),
            ),
        )
    else:
        query = query.join(
            max_base_scan_subquery,
            DBfinding.repository_id == max_base_scan_subquery.c.repository_id,
        )
        query = query.join(
            DBscan,
            and_(
                DBscanFinding.scan_id == DBscan.id_,
                DBscan.id_ >= max_base_scan_subquery.c.latest_base_scan_id,
            ),
        )

    query = query.join(DBrepository, DBrepository.id_ == DBfinding.repository_id).join(
        DBVcsInstance, DBVcsInstance.id_ == DBrepository.vcs_instance
    )
    query = query.join(
        max_audit_subquery,
        max_audit_subquery.c.finding_id == DBfinding.id_,
        isouter=True,
    )
    query = query.join(
        DBaudit,
        and_(
            DBaudit.finding_id == DBfinding.id_,
            DBaudit.id_ == max_audit_subquery.c.audit_id,
        ),
        isouter=True,
    )

    if findings_filter.rule_tags:
        query = query.join(
            DBrule,
            and_(
                DBrule.rule_name == DBfinding.rule_name,
                DBrule.rule_pack == DBscan.rule_pack,
            ),
        )
        query = query.join(rule_tag_subquery, DBrule.id_ == rule_tag_subquery.c.rule_id)

    if findings_filter.rule_pack_versions:
        query = query.filter(DBscan.rule_pack.in_(findings_filter.rule_pack_versions))
    if findings_filter.start_date_time:
        query = query.filter(DBscan.timestamp >= findings_filter.start_date_time)
    if findings_filter.end_date_time:
        query = query.filter(DBscan.timestamp <= findings_filter.end_date_time)

    if findings_filter.event_sent is not None:
        if findings_filter.event_sent:
            query = query.filter(DBfinding.event_sent_on.is_not(None))
        else:
            query = query.filter(DBfinding.event_sent_on.is_(None))

    if findings_filter.repository_name:
        query = query.filter(
            DBrepository.repository_name == findings_filter.repository_name
        )
    if findings_filter.vcs_providers and findings_filter.vcs_providers is not None:
        query = query.filter(
            DBVcsInstance.provider_type.in_(findings_filter.vcs_providers)
        )
    if findings_filter.project_name:
        query = query.filter(DBrepository.project_key == findings_filter.project_name)
    if findings_filter.rule_names:
        query = query.filter(DBfinding.rule_name.in_(findings_filter.rule_names))
    if findings_filter.finding_statuses:
        if FindingStatus.NOT_ANALYZED in findings_filter.finding_statuses:
            query = query.filter(
                or_(
                    DBaudit.status.in_(findings_filter.finding_statuses),
                    DBaudit.status == None,  # noqa: E711
                )
            )
        else:
            query = query.filter(DBaudit.status.in_(findings_filter.finding_statuses))

    findings_count = query.scalar()
    return findings_count


def get_detailed_finding(
    db_connection: Session, finding_id: int
) -> detailed_finding_schema.DetailedFindingRead:
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
    max_scan_subquery = db_connection.query(
        DBscanFinding.finding_id, func.max(DBscanFinding.scan_id).label("scan_id")
    )
    max_scan_subquery = max_scan_subquery.group_by(DBscanFinding.finding_id).subquery()

    # subquery to select latest audit ids of findings
    max_audit_subquery = (
        db_connection.query(DBaudit.finding_id, func.max(DBaudit.id_).label("audit_id"))
        .group_by(DBaudit.finding_id)
        .subquery()
    )

    scan_id = DBscan.id_.label("scan_id")
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
            DBaudit.status,
            DBaudit.comment,
            DBfinding.rule_name,
            DBscan.rule_pack,
            DBscan.timestamp,
            scan_id,
            DBscan.last_scanned_commit,
            DBVcsInstance.provider_type.label("vcs_provider"),
            DBrepository.project_key,
            DBrepository.repository_name,
            DBrepository.repository_url,
        )
        .join(max_scan_subquery, DBfinding.id_ == max_scan_subquery.c.finding_id)
        .join(DBscan, DBscan.id_ == max_scan_subquery.c.scan_id)
        .join(DBrepository, DBrepository.id_ == DBscan.repository_id)
        .join(DBVcsInstance, DBVcsInstance.id_ == DBrepository.vcs_instance)
        .join(
            max_audit_subquery,
            max_audit_subquery.c.finding_id == DBfinding.id_,
            isouter=True,
        )
        .join(
            DBaudit,
            and_(
                DBaudit.finding_id == DBfinding.id_,
                DBaudit.id_ == max_audit_subquery.c.audit_id,
            ),
            isouter=True,
        )
        .filter(DBfinding.id_ == finding_id)
    )
    finding = query.first()
    return finding

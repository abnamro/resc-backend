# Standard Library
import logging
from datetime import datetime, timedelta
from typing import List

# Third Party
from sqlalchemy import and_, extract, func, or_, union
from sqlalchemy.engine import Row
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
from resc_backend.resc_web_service.crud import scan_finding as scan_finding_crud
from resc_backend.resc_web_service.filters import FindingsFilter
from resc_backend.resc_web_service.schema import finding as finding_schema
from resc_backend.resc_web_service.schema.date_filter import DateFilter
from resc_backend.resc_web_service.schema.finding_status import FindingStatus
from resc_backend.resc_web_service.schema.scan_type import ScanType
from resc_backend.resc_web_service.schema.vcs_provider import VCSProviders

logger = logging.getLogger(__name__)


def patch_finding(
    db_connection: Session, finding_id: int, finding_update: finding_schema.FindingPatch
):
    db_finding = db_connection.query(DBfinding).filter_by(id_=finding_id).first()

    finding_update_dict = finding_update.dict(exclude_unset=True)
    for key in finding_update_dict:
        setattr(db_finding, key, finding_update_dict[key])

    db_connection.commit()
    db_connection.refresh(db_finding)
    return db_finding


def create_findings(
    db_connection: Session, findings: List[finding_schema.FindingCreate]
) -> List[DBfinding]:
    if len(findings) < 1:
        # Function is called with an empty list of findings
        return []
    repository_id = findings[0].repository_id

    # get a list of known / registered findings for this repository
    db_repository_findings = (
        db_connection.query(DBfinding)
        .filter(DBfinding.repository_id == repository_id)
        .all()
    )

    # Compare new findings list with findings in the db
    new_findings = findings[:]
    db_findings = []
    for finding in findings:
        for repository_finding in db_repository_findings:
            # Compare based on the unique key in the findings table
            if (
                repository_finding.commit_id == finding.commit_id
                and repository_finding.rule_name == finding.rule_name
                and repository_finding.file_path == finding.file_path
                and repository_finding.line_number == finding.line_number
                and repository_finding.column_start == finding.column_start
                and repository_finding.column_end == finding.column_end
            ):
                # Store the already known finding
                db_findings.append(repository_finding)
                # Remove from the db_repository_findings to increase performance for the next loop
                db_repository_findings.remove(repository_finding)
                # Remove from the to be created findings
                new_findings.remove(finding)
                break
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


def get_finding(db_connection: Session, finding_id: int):
    finding = db_connection.query(DBfinding)
    finding = finding.filter(DBfinding.id_ == finding_id).first()
    return finding


def get_findings(
    db_connection: Session, skip: int = 0, limit: int = DEFAULT_RECORDS_PER_PAGE_LIMIT
):
    limit_val = (
        MAX_RECORDS_PER_PAGE_LIMIT if limit > MAX_RECORDS_PER_PAGE_LIMIT else limit
    )
    findings = db_connection.query(DBfinding)
    findings = findings.order_by(DBfinding.id_).offset(skip).limit(limit_val).all()
    return findings


def get_scans_findings(
    db_connection,
    scan_ids: List[int],
    skip: int = 0,
    limit: int = DEFAULT_RECORDS_PER_PAGE_LIMIT,
    rules_filter: List[str] = None,
    statuses_filter: List[FindingStatus] = None,
) -> List[DBfinding]:
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
    limit_val = (
        MAX_RECORDS_PER_PAGE_LIMIT if limit > MAX_RECORDS_PER_PAGE_LIMIT else limit
    )

    query = db_connection.query(DBfinding)
    query = query.join(DBscanFinding, DBscanFinding.finding_id == DBfinding.id_)

    if statuses_filter:
        # subquery to select latest audit ids findings
        max_audit_subquery = (
            db_connection.query(
                DBaudit.finding_id, func.max(DBaudit.id_).label("audit_id")
            )
            .group_by(DBaudit.finding_id)
            .subquery()
        )

        query = query.join(
            max_audit_subquery,
            max_audit_subquery.c.finding_id == DBfinding.id_,
            isouter=True,
        ).join(
            DBaudit,
            and_(
                DBaudit.finding_id == DBfinding.id_,
                DBaudit.id_ == max_audit_subquery.c.audit_id,
            ),
            isouter=True,
        )
        if FindingStatus.NOT_ANALYZED in statuses_filter:
            query = query.filter(
                or_(DBaudit.status.in_(statuses_filter), DBaudit.status == None)  # noqa: E711
            )
        else:
            query = query.filter(DBaudit.status.in_(statuses_filter))

    query = query.filter(DBscanFinding.scan_id.in_(scan_ids))

    if rules_filter:
        query = query.filter(DBfinding.rule_name.in_(rules_filter))

    findings = query.order_by(DBfinding.id_).offset(skip).limit(limit_val).all()
    return findings


def get_total_findings_count(
    db_connection: Session, findings_filter: FindingsFilter = None
) -> int:
    """
        Retrieve count of finding records of a given scan
    :param findings_filter:
    :param db_connection:
        Session of the database connection
    :return: total_count
        count of findings
    """

    total_count_query = db_connection.query(func.count(DBfinding.id_))
    if findings_filter:
        if findings_filter.finding_statuses:
            # subquery to select latest audit ids findings
            max_audit_subquery = (
                db_connection.query(
                    DBaudit.finding_id, func.max(DBaudit.id_).label("audit_id")
                )
                .group_by(DBaudit.finding_id)
                .subquery()
            )

            total_count_query = total_count_query.join(
                max_audit_subquery,
                max_audit_subquery.c.finding_id == DBfinding.id_,
                isouter=True,
            ).join(
                DBaudit,
                and_(
                    DBaudit.finding_id == DBfinding.id_,
                    DBaudit.id_ == max_audit_subquery.c.audit_id,
                ),
                isouter=True,
            )
        if (
            (
                findings_filter.vcs_providers
                and findings_filter.vcs_providers is not None
            )
            or findings_filter.project_name
            or findings_filter.repository_name
            or findings_filter.start_date_time
            or findings_filter.end_date_time
        ):
            total_count_query = (
                total_count_query.join(
                    DBscanFinding, DBscanFinding.finding_id == DBfinding.id_
                )
                .join(DBscan, DBscan.id_ == DBscanFinding.scan_id)
                .join(DBrepository, DBrepository.id_ == DBscan.repository_id)
                .join(DBVcsInstance, DBVcsInstance.id_ == DBrepository.vcs_instance)
            )

        if findings_filter.start_date_time:
            total_count_query = total_count_query.filter(
                DBscan.timestamp >= findings_filter.start_date_time
            )
        if findings_filter.end_date_time:
            total_count_query = total_count_query.filter(
                DBscan.timestamp <= findings_filter.end_date_time
            )

        if findings_filter.repository_name:
            total_count_query = total_count_query.filter(
                DBrepository.repository_name == findings_filter.repository_name
            )

        if findings_filter.vcs_providers and findings_filter.vcs_providers is not None:
            total_count_query = total_count_query.filter(
                DBVcsInstance.provider_type.in_(findings_filter.vcs_providers)
            )
        if findings_filter.project_name:
            total_count_query = total_count_query.filter(
                DBrepository.project_key == findings_filter.project_name
            )
        if findings_filter.rule_names:
            total_count_query = total_count_query.filter(
                DBfinding.rule_name.in_(findings_filter.rule_names)
            )
        if findings_filter.finding_statuses:
            if FindingStatus.NOT_ANALYZED in findings_filter.finding_statuses:
                total_count_query = total_count_query.filter(
                    or_(
                        DBaudit.status.in_(findings_filter.finding_statuses),
                        DBaudit.status == None,  # noqa: E711
                    )
                )
            else:
                total_count_query = total_count_query.filter(
                    DBaudit.status.in_(findings_filter.finding_statuses)
                )
        if findings_filter.scan_ids and len(findings_filter.scan_ids) == 1:
            total_count_query = total_count_query.join(
                DBscanFinding, DBscanFinding.finding_id == DBfinding.id_
            )
            total_count_query = total_count_query.filter(
                DBscanFinding.scan_id == findings_filter.scan_ids[0]
            )

        if findings_filter.scan_ids and len(findings_filter.scan_ids) >= 2:
            total_count_query = total_count_query.join(
                DBscanFinding, DBscanFinding.finding_id == DBfinding.id_
            )
            total_count_query = total_count_query.filter(
                DBscanFinding.scan_id.in_(findings_filter.scan_ids)
            )

    total_count = total_count_query.scalar()
    return total_count


def get_findings_by_rule(
    db_connection: Session,
    skip: int = 0,
    limit: int = DEFAULT_RECORDS_PER_PAGE_LIMIT,
    rule_name: str = "",
):
    limit_val = (
        MAX_RECORDS_PER_PAGE_LIMIT if limit > MAX_RECORDS_PER_PAGE_LIMIT else limit
    )
    findings = db_connection.query(DBfinding)
    findings = findings.filter(DBfinding.rule_name == rule_name)
    findings = findings.order_by(DBfinding.id_).offset(skip).limit(limit_val).all()
    return findings


def get_distinct_rules_from_findings(
    db_connection: Session,
    scan_id: int = -1,
    finding_statuses: List[FindingStatus] = None,
    vcs_providers: List[VCSProviders] = None,
    project_name: str = "",
    repository_name: str = "",
    start_date_time: datetime = None,
    end_date_time: datetime = None,
    rule_pack_versions: List[str] = None,
) -> List[DBrule]:
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
    query = db_connection.query(DBfinding.rule_name)

    if (
        vcs_providers
        or project_name
        or repository_name
        or start_date_time
        or end_date_time
        or rule_pack_versions
    ) and scan_id < 0:
        query = (
            query.join(DBscanFinding, DBscanFinding.finding_id == DBfinding.id_)
            .join(DBscan, DBscan.id_ == DBscanFinding.scan_id)
            .join(DBrepository, DBrepository.id_ == DBscan.repository_id)
            .join(DBVcsInstance, DBVcsInstance.id_ == DBrepository.vcs_instance)
        )
    if finding_statuses:
        # subquery to select latest audit ids findings
        max_audit_subquery = (
            db_connection.query(
                DBaudit.finding_id, func.max(DBaudit.id_).label("audit_id")
            )
            .group_by(DBaudit.finding_id)
            .subquery()
        )

        query = query.join(
            max_audit_subquery,
            max_audit_subquery.c.finding_id == DBfinding.id_,
            isouter=True,
        ).join(
            DBaudit,
            and_(
                DBaudit.finding_id == DBfinding.id_,
                DBaudit.id_ == max_audit_subquery.c.audit_id,
            ),
            isouter=True,
        )
    if scan_id > 0:
        query = query.join(DBscanFinding, DBscanFinding.finding_id == DBfinding.id_)
        query = query.filter(DBscanFinding.scan_id == scan_id)
    else:
        if finding_statuses:
            if FindingStatus.NOT_ANALYZED in finding_statuses:
                query = query.filter(
                    or_(DBaudit.status.in_(finding_statuses), DBaudit.status == None)  # noqa: E711
                )
            else:
                query = query.filter(DBaudit.status.in_(finding_statuses))

        if vcs_providers:
            query = query.filter(DBVcsInstance.provider_type.in_(vcs_providers))

        if project_name:
            query = query.filter(DBrepository.project_key == project_name)

        if repository_name:
            query = query.filter(DBrepository.repository_name == repository_name)

        if start_date_time:
            query = query.filter(DBscan.timestamp >= start_date_time)

        if end_date_time:
            query = query.filter(DBscan.timestamp <= end_date_time)

        if rule_pack_versions:
            query = query.filter(DBscan.rule_pack.in_(rule_pack_versions))

    rules = query.distinct().order_by(DBfinding.rule_name).all()
    return rules


def get_findings_count_by_status(
    db_connection: Session,
    scan_ids: List[int] = None,
    finding_statuses: List[FindingStatus] = None,
    rule_name: str = "",
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
    # subquery to select latest audit ids findings
    max_audit_subquery = (
        db_connection.query(DBaudit.finding_id, func.max(DBaudit.id_).label("audit_id"))
        .group_by(DBaudit.finding_id)
        .subquery()
    )

    query = db_connection.query(
        func.count(DBfinding.id_).label("status_count"), DBaudit.status
    )

    query = query.join(
        max_audit_subquery,
        max_audit_subquery.c.finding_id == DBfinding.id_,
        isouter=True,
    ).join(
        DBaudit,
        and_(
            DBaudit.finding_id == DBfinding.id_,
            DBaudit.id_ == max_audit_subquery.c.audit_id,
        ),
        isouter=True,
    )

    if scan_ids and len(scan_ids) > 0:
        query = (
            query.join(DBscanFinding, DBscanFinding.finding_id == DBfinding.id_)
            .join(DBscan, DBscan.id_ == DBscanFinding.scan_id)
            .filter(DBscan.id_.in_(scan_ids))
        )
    if finding_statuses:
        if FindingStatus.NOT_ANALYZED in finding_statuses:
            query = query.filter(
                or_(DBaudit.status.in_(finding_statuses), DBaudit.status == None)  # noqa: E711
            )
        else:
            query = query.filter(DBaudit.status.in_(finding_statuses))
    if rule_name:
        query = query.filter(DBfinding.rule_name == rule_name)

    findings_count_by_status = query.group_by(DBaudit.status).all()

    return findings_count_by_status


def get_rule_findings_count_by_status(
    db_connection: Session,
    rule_pack_versions: List[str] = None,
    rule_tags: List[str] = None,
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
    query = db_connection.query(
        DBfinding.rule_name, DBaudit.status, func.count(DBfinding.id_)
    )

    max_base_scan_subquery = db_connection.query(
        DBscan.repository_id, func.max(DBscan.id_).label("latest_base_scan_id")
    )
    max_base_scan_subquery = max_base_scan_subquery.filter(
        DBscan.scan_type == ScanType.BASE
    )
    if rule_pack_versions:
        max_base_scan_subquery = max_base_scan_subquery.filter(
            DBscan.rule_pack.in_(rule_pack_versions)
        )
    max_base_scan_subquery = max_base_scan_subquery.group_by(
        DBscan.repository_id
    ).subquery()

    max_audit_subquery = (
        db_connection.query(DBaudit.finding_id, func.max(DBaudit.id_).label("audit_id"))
        .group_by(DBaudit.finding_id)
        .subquery()
    )

    query = query.join(DBscanFinding, DBfinding.id_ == DBscanFinding.finding_id)
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
    if rule_tags:
        rule_tag_subquery = db_connection.query(DBruleTag.rule_id).join(
            DBtag, DBruleTag.tag_id == DBtag.id_
        )
        if rule_pack_versions:
            rule_tag_subquery = rule_tag_subquery.join(
                DBrule, DBrule.id_ == DBruleTag.rule_id
            )
            rule_tag_subquery = rule_tag_subquery.filter(
                DBrule.rule_pack.in_(rule_pack_versions)
            )

        rule_tag_subquery = rule_tag_subquery.filter(DBtag.name.in_(rule_tags))
        rule_tag_subquery = rule_tag_subquery.group_by(DBruleTag.rule_id).subquery()

        query = query.join(
            DBrule,
            and_(
                DBrule.rule_name == DBfinding.rule_name,
                DBrule.rule_pack == DBscan.rule_pack,
            ),
        )
        query = query.join(rule_tag_subquery, DBrule.id_ == rule_tag_subquery.c.rule_id)

    if rule_pack_versions:
        query = query.filter(DBscan.rule_pack.in_(rule_pack_versions))

    query = query.join(
        max_audit_subquery,
        max_audit_subquery.c.finding_id == DBscanFinding.finding_id,
        isouter=True,
    )
    query = query.join(
        DBaudit,
        and_(
            DBaudit.finding_id == DBscanFinding.finding_id,
            DBaudit.id_ == max_audit_subquery.c.audit_id,
        ),
        isouter=True,
    )
    query = query.group_by(DBfinding.rule_name, DBaudit.status)
    query = query.order_by(DBfinding.rule_name, DBaudit.status)
    status_counts = query.all()

    rule_count_dict = {}
    for status_count in status_counts:
        rule_count_dict[status_count[0]] = {
            "true_positive": 0,
            "false_positive": 0,
            "not_analyzed": 0,
            "under_review": 0,
            "clarification_required": 0,
            "total_findings_count": 0,
        }

    for status_count in status_counts:
        rule_count_dict[status_count[0]]["total_findings_count"] += status_count[2]
        if status_count[1] == FindingStatus.NOT_ANALYZED or status_count[1] is None:
            rule_count_dict[status_count[0]]["not_analyzed"] += status_count[2]
        elif status_count[1] == FindingStatus.FALSE_POSITIVE:
            rule_count_dict[status_count[0]]["false_positive"] += status_count[2]
        elif status_count[1] == FindingStatus.TRUE_POSITIVE:
            rule_count_dict[status_count[0]]["true_positive"] += status_count[2]
        elif status_count[1] == FindingStatus.UNDER_REVIEW:
            rule_count_dict[status_count[0]]["under_review"] += status_count[2]
        elif status_count[1] == FindingStatus.CLARIFICATION_REQUIRED:
            rule_count_dict[status_count[0]]["clarification_required"] += status_count[
                2
            ]

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

    query = query.join(DBscanFinding, DBscanFinding.scan_id == DBscan.id_)

    if start_date_time:
        query = query.filter(DBscan.timestamp >= start_date_time)
    if end_date_time:
        query = query.filter(DBscan.timestamp <= end_date_time)

    if date_type == DateFilter.MONTH:
        query = query.group_by(
            extract("year", DBscan.timestamp), extract("month", DBscan.timestamp)
        )
        query = query.order_by(
            extract("year", DBscan.timestamp), extract("month", DBscan.timestamp)
        )
    elif date_type == DateFilter.WEEK:
        query = query.group_by(
            extract("year", DBscan.timestamp), extract("week", DBscan.timestamp)
        )
        query = query.order_by(
            extract("year", DBscan.timestamp), extract("week", DBscan.timestamp)
        )
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
        query = db_connection.query(
            extract("year", DBscan.timestamp), extract("month", DBscan.timestamp)
        )
    elif date_type == DateFilter.WEEK:
        query = db_connection.query(
            extract("year", DBscan.timestamp), extract("week", DBscan.timestamp)
        )
    elif date_type == DateFilter.DAY:
        query = db_connection.query(
            extract("year", DBscan.timestamp),
            extract("month", DBscan.timestamp),
            extract("day", DBscan.timestamp),
        )

    if start_date_time:
        query = query.filter(DBscan.timestamp >= start_date_time)
    if end_date_time:
        query = query.filter(DBscan.timestamp <= end_date_time)

    query = query.distinct()

    result = query.count()
    return result


def get_distinct_rules_from_scans(
    db_connection: Session, scan_ids: List[int] = None
) -> List[DBrule]:
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
        query = query.filter(DBscanFinding.scan_id.in_(scan_ids))

    rules = query.distinct().order_by(DBfinding.rule_name).all()
    return rules


def delete_finding(
    db_connection: Session, finding_id: int, delete_related: bool = False
):
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

    db_connection.query(DBfinding).filter(DBfinding.id_ == finding_id).delete(
        synchronize_session=False
    )
    db_connection.commit()


def delete_findings_by_repository_id(db_connection: Session, repository_id: int):
    """
        Delete findings for a given repository
    :param db_connection:
        Session of the database connection
    :param repository_id:
        id of the repository
    """
    db_connection.query(DBfinding).filter(
        DBfinding.repository_id == repository_id
    ).delete(synchronize_session=False)
    db_connection.commit()


def delete_findings_by_vcs_instance_id(db_connection: Session, vcs_instance_id: int):
    """
        Delete findings for a given vcs instance
    :param db_connection:
        Session of the database connection
    :param vcs_instance_id:
        id of the vcs instance
    """
    db_connection.query(DBfinding).filter(
        DBfinding.repository_id == DBrepository.id_,
        DBrepository.vcs_instance == DBVcsInstance.id_,
        DBVcsInstance.id_ == vcs_instance_id,
    ).delete(synchronize_session=False)
    db_connection.commit()


def get_finding_audit_status_count_over_time(
    db_connection: Session, status: FindingStatus, weeks: int = 13
) -> dict:
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
        last_nth_week_date_time = datetime.utcnow() - timedelta(weeks=week)
        query = db_connection.query(
            extract("year", last_nth_week_date_time).label("year"),
            extract("week", last_nth_week_date_time).label("week"),
            DBVcsInstance.provider_type.label("provider_type"),
            func.count(DBaudit.id_).label("finding_count"),
        )
        max_audit_subquery = (
            db_connection.query(func.max(DBaudit.id_).label("audit_id"))
            .filter(
                or_(
                    extract("year", DBaudit.timestamp)
                    < extract("year", last_nth_week_date_time),
                    and_(
                        extract("year", DBaudit.timestamp)
                        == extract("year", last_nth_week_date_time),
                        extract("week", DBaudit.timestamp)
                        <= extract("week", last_nth_week_date_time),
                    ),
                )
            )
            .group_by(DBaudit.finding_id)
            .subquery()
        )
        query = query.join(
            max_audit_subquery, max_audit_subquery.c.audit_id == DBaudit.id_
        )
        query = query.join(DBfinding, DBfinding.id_ == DBaudit.finding_id)
        query = query.join(DBrepository, DBrepository.id_ == DBfinding.repository_id)
        query = query.join(
            DBVcsInstance, DBVcsInstance.id_ == DBrepository.vcs_instance
        )
        query = query.filter(DBaudit.status == status)
        query = query.group_by(DBVcsInstance.provider_type)

        all_tables.append(query)

    # union
    unioned_query = union(*all_tables)
    status_count_over_time = db_connection.execute(unioned_query).all()
    return status_count_over_time


def get_finding_count_by_vcs_provider_over_time(
    db_connection: Session, weeks: int = 13
) -> list[Row]:
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
        last_nth_week_date_time = datetime.utcnow() - timedelta(weeks=week)
        query = db_connection.query(
            extract("year", last_nth_week_date_time).label("year"),
            extract("week", last_nth_week_date_time).label("week"),
            DBVcsInstance.provider_type.label("provider_type"),
            func.count(DBfinding.id_).label("finding_count"),
        )
        max_base_scan = (
            db_connection.query(
                func.max(DBscan.id_).label("scan_id"), DBscan.repository_id
            )
            .filter(
                or_(
                    extract("year", DBaudit.timestamp)
                    < extract("year", last_nth_week_date_time),
                    and_(
                        extract("year", DBaudit.timestamp)
                        == extract("year", last_nth_week_date_time),
                        extract("week", DBaudit.timestamp)
                        <= extract("week", last_nth_week_date_time),
                    ),
                )
            )
            .filter(DBscan.scan_type == ScanType.BASE)
            .group_by(DBscan.repository_id)
            .subquery()
        )

        query = query.join(DBscanFinding, DBfinding.id_ == DBscanFinding.finding_id)
        query = query.join(DBscan, DBscan.id_ == DBscanFinding.scan_id)
        query = query.join(
            max_base_scan,
            and_(
                max_base_scan.c.repository_id == DBscan.repository_id,
                or_(
                    DBscan.id_ == max_base_scan.c.scan_id,
                    (
                        and_(
                            DBscan.id_ > max_base_scan.c.scan_id,
                            DBscan.scan_type == ScanType.INCREMENTAL,
                            extract("week", DBscan.timestamp)
                            <= extract("week", last_nth_week_date_time),
                            extract("year", DBscan.timestamp)
                            == extract("year", last_nth_week_date_time),
                        )
                    ),
                ),
            ),
        )
        query = query.join(DBrepository, DBrepository.id_ == DBscan.repository_id)
        query = query.join(
            DBVcsInstance, DBVcsInstance.id_ == DBrepository.vcs_instance
        )
        query = query.group_by(DBVcsInstance.provider_type)

        all_tables.append(query)

    # union
    unioned_query = union(*all_tables)
    count_over_time = db_connection.execute(unioned_query).all()
    return count_over_time


def get_un_triaged_finding_count_by_vcs_provider_over_time(
    db_connection: Session, weeks: int = 13
) -> list[Row]:
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
        last_nth_week_date_time = datetime.utcnow() - timedelta(weeks=week)
        query = db_connection.query(
            extract("year", last_nth_week_date_time).label("year"),
            extract("week", last_nth_week_date_time).label("week"),
            DBVcsInstance.provider_type.label("provider_type"),
            func.count(DBfinding.id_).label("finding_count"),
        )
        max_base_scan = (
            db_connection.query(
                func.max(DBscan.id_).label("scan_id"), DBscan.repository_id
            )
            .filter(
                or_(
                    extract("year", DBaudit.timestamp)
                    < extract("year", last_nth_week_date_time),
                    and_(
                        extract("year", DBaudit.timestamp)
                        == extract("year", last_nth_week_date_time),
                        extract("week", DBaudit.timestamp)
                        <= extract("week", last_nth_week_date_time),
                    ),
                )
            )
            .filter(DBscan.scan_type == ScanType.BASE)
            .group_by(DBscan.repository_id)
            .subquery()
        )

        max_audit_subquery = (
            db_connection.query(
                DBaudit.finding_id, func.max(DBaudit.id_).label("audit_id")
            )
            .filter(
                or_(
                    extract("year", DBaudit.timestamp)
                    < extract("year", last_nth_week_date_time),
                    and_(
                        extract("year", DBaudit.timestamp)
                        == extract("year", last_nth_week_date_time),
                        extract("week", DBaudit.timestamp)
                        <= extract("week", last_nth_week_date_time),
                    ),
                )
            )
            .group_by(DBaudit.finding_id)
            .subquery()
        )

        query = query.join(DBscanFinding, DBfinding.id_ == DBscanFinding.finding_id)
        query = query.join(DBscan, DBscan.id_ == DBscanFinding.scan_id)
        query = query.join(
            max_base_scan,
            and_(
                max_base_scan.c.repository_id == DBscan.repository_id,
                or_(
                    DBscan.id_ == max_base_scan.c.scan_id,
                    (
                        and_(
                            DBscan.id_ > max_base_scan.c.scan_id,
                            DBscan.scan_type == ScanType.INCREMENTAL,
                            extract("week", DBscan.timestamp)
                            <= extract("week", last_nth_week_date_time),
                            extract("year", DBscan.timestamp)
                            == extract("year", last_nth_week_date_time),
                        )
                    ),
                ),
            ),
        )
        query = query.join(DBrepository, DBrepository.id_ == DBscan.repository_id)
        query = query.join(
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
        query = query.filter(
            or_(DBaudit.id_ == None, DBaudit.status == FindingStatus.NOT_ANALYZED)  # noqa: E711
        )

        query = query.group_by(DBVcsInstance.provider_type)

        all_tables.append(query)

    # union
    unioned_query = union(*all_tables)
    count_over_time = db_connection.execute(unioned_query).all()
    return count_over_time

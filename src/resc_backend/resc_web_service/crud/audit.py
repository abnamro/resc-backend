# Standard Library
import logging
from datetime import UTC, datetime, timedelta
from itertools import islice

# Third Party
from sqlalchemy import extract, func, select, update
from sqlalchemy.engine import Row
from sqlalchemy.orm import Query, Session

# First Party
from resc_backend.constants import (
    AUDIT_AUTOMATED_AUDITOR,
    AUDIT_AUTOMATED_COMMENT,
    DEFAULT_RECORDS_PER_PAGE_LIMIT,
    MAX_RECORDS_PER_PAGE_LIMIT,
)
from resc_backend.db.model import DBaudit
from resc_backend.resc_web_service.schema.auditor_metric import AuditorMetric
from resc_backend.resc_web_service.schema.finding_status import FindingStatus
from resc_backend.resc_web_service.schema.time_period import TimePeriod

logger = logging.getLogger(__name__)

YEAR = "year"
MONTH = "month"
WEEK = "week"
DAY = "day"


def create_audits(
    db_connection: Session,
    finding_ids: set[int],
    auditor: str,
    status: FindingStatus,
    comment: str = "",
) -> list[DBaudit]:
    """
        Audit finding, updating the status and comment
    :param db_connection:
        Session of the database connection
    :param finding_ids:
        List of id of the finding to audit
    :param auditor:
        identifier of the person performing the audit action
    :param status:
        audit status to set, type FindingStatus
    :param comment:
        audit comment to set
    :return: DBaudit
        The output will contain the audit that was created
    """
    # Iterate over those ids by chunk.
    # This is necessary because SQL tends to crash when you do IN with more than 1000 values.
    # source: trust me bro.
    iterator = iter(finding_ids)
    db_audits = []
    while chunk := list(islice(iterator, 1000)):
        db_connection.execute(update(DBaudit).where(DBaudit.finding_id.in_(chunk)).values(is_latest=False))
        db_audits_created = []

        # Loop around the findings and audit one by one.
        for finding_id in chunk:
            db_audit = DBaudit(
                finding_id=finding_id,
                auditor=auditor,
                status=status,
                comment=comment,
                timestamp=datetime.now(UTC),
                is_latest=True,
            )
            db_audits_created.append(db_audit)

        # Insert new Audits by chunk.
        db_connection.add_all(db_audits_created)

        db_audits.extend(db_audits_created)

    # Commit the change.
    db_connection.commit()

    return db_audits


def create_automated_audits(db_connection: Session, findings_ids: list[int], status: FindingStatus) -> list[DBaudit]:
    """
        Create automated audit for a list of findings.

    Args:
        db_connection (Session): Session of the database connection
        findings_ids (list[int]): list of id to audit
        status (FindingStatus): status to apply

    Returns:
        list[DBaudit]: newly created audits
    """

    # Iterate over those ids by chunk.
    # This is necessary because SQL tends to crash when you do IN with more than 1000 values.
    # source: trust me bro.
    iterator = iter(findings_ids)
    db_audits = []
    while chunk := list(islice(iterator, 1000)):
        db_connection.execute(update(DBaudit).where(DBaudit.finding_id.in_(chunk)).values(is_latest=False))
        db_audits_created = [DBaudit.create_automated(finding_id, status) for finding_id in chunk]
        db_connection.add_all(db_audits_created)
        db_audits.extend(db_audits_created)

    db_connection.commit()

    logger.debug(f"Automated audit of {len(db_audits)} findings.")

    return db_audits


def clear_outdated_no_longer_outdated(db_connection: Session, findings_ids: list[int]) -> None:
    """
        Remove outdated status from findings which have been automatically added

    Args:
        db_connection (Session): Session of the database connection
        findings_ids (list[int]): list of id to audit
    """
    iterator = iter(findings_ids)
    while chunk := list(islice(iterator, 1000)):
        query = db_connection.query(DBaudit)
        query = query.where(DBaudit.finding_id.in_(chunk))
        query = query.where(DBaudit.auditor == AUDIT_AUTOMATED_AUDITOR)
        query = query.where(DBaudit.comment == AUDIT_AUTOMATED_COMMENT)
        query.delete(synchronize_session=False)

    fix_last_audit(db_connection, findings_ids)


def get_finding_audits(
    db_connection: Session,
    finding_id: int,
    skip: int = 0,
    limit: int = DEFAULT_RECORDS_PER_PAGE_LIMIT,
) -> list[DBaudit]:
    """
        Get Audit entries for finding
    :param db_connection:
        Session of the database connection
    :param finding_id:
        id of the finding to audit
    :param skip:
        integer amount of records to skip to support pagination
    :param limit:
        integer amount of records to return, to support pagination
    :return: [DBaudit]
        The output will contain the list of audit items for the given finding
    """
    limit_val = MAX_RECORDS_PER_PAGE_LIMIT if limit > MAX_RECORDS_PER_PAGE_LIMIT else limit
    query = select(DBaudit).where(DBaudit.finding_id == finding_id)
    query = query.order_by(DBaudit.id_.desc()).offset(skip).limit(limit_val)
    finding_audits = db_connection.execute(query).scalars().all()
    return finding_audits


def get_finding_audits_count(db_connection: Session, finding_id: int) -> int:
    """
        Get count of Audit entries for finding
    :param db_connection:
        Session of the database connection
    :param finding_id:
        id of the finding to audit
    :return: total_count
        count of audit entries
    """
    query = select(func.count(DBaudit.id_)).where(DBaudit.finding_id == finding_id)
    total_count = db_connection.execute(query).scalars().one()
    return total_count


def get_audit_count_by_auditor_over_time(db_connection: Session, weeks: int = 13) -> list[Row]:
    """
        Retrieve count audits by auditor over time for given weeks
    :param db_connection:
        Session of the database connection
    :param weeks:
        optional, filter on last n weeks, default 13
    :return: count_over_time
        list of rows containing audit count over time per week
    """
    last_nth_week_date_time = datetime.now(UTC) - timedelta(weeks=weeks)

    query = (
        db_connection.query(
            extract(YEAR, DBaudit.timestamp).label(YEAR),
            extract(WEEK, DBaudit.timestamp).label(WEEK),
            DBaudit.auditor,
            func.count(DBaudit.id_).label("audit_count"),
        )
        .filter(
            (extract(YEAR, DBaudit.timestamp) > extract(YEAR, last_nth_week_date_time))
            | (
                (extract(YEAR, DBaudit.timestamp) == extract(YEAR, last_nth_week_date_time))
                & (extract(WEEK, DBaudit.timestamp) >= extract(WEEK, last_nth_week_date_time))
            )
        )
        .group_by(
            extract(YEAR, DBaudit.timestamp).label(YEAR),
            extract(WEEK, DBaudit.timestamp).label(WEEK),
            DBaudit.auditor,
        )
        .order_by(
            extract(YEAR, DBaudit.timestamp).label(YEAR),
            extract(WEEK, DBaudit.timestamp).label(WEEK),
            DBaudit.auditor,
        )
    )
    finding_audits = query.all()

    return finding_audits


def get_personal_audit_count(db_connection: Session, auditor: str, time_period: TimePeriod) -> int:
    """
        Get count of Audit entries for finding
    :param db_connection:
        Session of the database connection
    :param auditor:
        id of the auditor
    :param time_period:
        period for which to retrieve the audit counts
    :return: total_count
        count of audit entries
    """
    date_today = datetime.now(UTC)

    total_count = db_connection.query(func.count(DBaudit.id_))

    if time_period in (time_period.DAY, time_period.MONTH, time_period.YEAR):
        total_count = total_count.filter(extract(YEAR, DBaudit.timestamp) == extract(YEAR, date_today))

        if time_period in (time_period.DAY, time_period.MONTH):
            total_count = total_count.filter(extract(MONTH, DBaudit.timestamp) == extract(MONTH, date_today))

            if time_period == time_period.DAY:
                total_count = total_count.filter(extract(DAY, DBaudit.timestamp) == extract(DAY, date_today))

    if time_period in (time_period.WEEK, time_period.LAST_WEEK):
        date_last_week = datetime.now(UTC) - timedelta(weeks=1)
        date_week = date_last_week if time_period == time_period.LAST_WEEK else date_today
        total_count = total_count.filter(extract(YEAR, DBaudit.timestamp) == extract(YEAR, date_week))
        total_count = total_count.filter(extract(WEEK, DBaudit.timestamp) == extract(WEEK, date_week))

    total_count = total_count.filter(DBaudit.auditor == auditor).scalar()
    return total_count


def get_audit_stats_count(db_connection: Session, auditor: str | None) -> list[AuditorMetric]:
    """Retrieve the stats True Positive, False Positive etc... per auditor

    Args:
        db_connection (Session): Session of the database connection
        auditor (str): id of the auditor

    Returns:
        list: List of AuditorMetrics
    """
    true_positive: Query = select(DBaudit.auditor, func.count(DBaudit.auditor).label("true_positive"))
    true_positive = true_positive.where(DBaudit.status == FindingStatus.TRUE_POSITIVE)
    true_positive = true_positive.group_by(DBaudit.auditor)
    true_positive = true_positive.subquery()

    false_positive: Query = select(DBaudit.auditor, func.count(DBaudit.auditor).label("false_positive"))
    false_positive = false_positive.where(DBaudit.status == FindingStatus.FALSE_POSITIVE)
    false_positive = false_positive.group_by(DBaudit.auditor)
    false_positive = false_positive.subquery()

    clarification_required: Query = select(DBaudit.auditor, func.count(DBaudit.auditor).label("clarification_required"))
    clarification_required = clarification_required.where(DBaudit.status == FindingStatus.CLARIFICATION_REQUIRED)
    clarification_required = clarification_required.group_by(DBaudit.auditor)
    clarification_required = clarification_required.subquery()

    not_accessible: Query = select(DBaudit.auditor, func.count(DBaudit.auditor).label("not_accessible"))
    not_accessible = not_accessible.where(DBaudit.status == FindingStatus.NOT_ACCESSIBLE)
    not_accessible = not_accessible.group_by(DBaudit.auditor)
    not_accessible = not_accessible.subquery()

    outdated: Query = select(DBaudit.auditor, func.count(DBaudit.auditor).label("outdated"))
    outdated = outdated.where(DBaudit.status == FindingStatus.OUTDATED)
    outdated = outdated.group_by(DBaudit.auditor)
    outdated = outdated.subquery()

    not_analyzed: Query = select(DBaudit.auditor, func.count(DBaudit.auditor).label("not_analyzed"))
    not_analyzed = not_analyzed.where(DBaudit.status == FindingStatus.NOT_ANALYZED)
    not_analyzed = not_analyzed.group_by(DBaudit.auditor)
    not_analyzed = not_analyzed.subquery()

    total: Query = select(DBaudit.auditor, func.count(DBaudit.auditor).label("total"))
    total = total.group_by(DBaudit.auditor)
    total = total.subquery()

    query = select(
        DBaudit.auditor,
        func.coalesce(true_positive.c.true_positive, 0).label("true_positive"),
        func.coalesce(false_positive.c.false_positive, 0).label("false_positive"),
        func.coalesce(clarification_required.c.clarification_required, 0).label("clarification_required"),
        func.coalesce(not_accessible.c.not_accessible, 0).label("not_accessible"),
        func.coalesce(outdated.c.outdated, 0).label("outdated"),
        func.coalesce(not_analyzed.c.not_analyzed, 0).label("not_analyzed"),
        func.coalesce(total.c.total, 0).label("total"),
    )
    query = query.join(true_positive, true_positive.c.auditor == DBaudit.auditor, isouter=True)
    query = query.join(false_positive, false_positive.c.auditor == DBaudit.auditor, isouter=True)
    query = query.join(clarification_required, clarification_required.c.auditor == DBaudit.auditor, isouter=True)
    query = query.join(not_accessible, not_accessible.c.auditor == DBaudit.auditor, isouter=True)
    query = query.join(outdated, outdated.c.auditor == DBaudit.auditor, isouter=True)
    query = query.join(not_analyzed, not_analyzed.c.auditor == DBaudit.auditor, isouter=True)
    query = query.join(total, total.c.auditor == DBaudit.auditor, isouter=True)

    if auditor is not None:
        query = query.where(DBaudit.auditor == auditor)

    query = query.distinct()

    return db_connection.execute(query).all()


def fix_last_audit(db_connection: Session, finding_ids: list[int]) -> None:
    # Iterate over those ids by chunk.
    # This is necessary because SQL tends to crash when you do IN with more than 1000 values.
    # source: trust me bro.
    finding_ids_iterator = iter(finding_ids)
    while chunk := list(islice(finding_ids_iterator, 1000)):
        # Create a sub query with group by on finding.
        max_audit_subquery: Query = select(DBaudit.finding_id, func.max(DBaudit.id_).label("audit_id"))
        max_audit_subquery = max_audit_subquery.where(DBaudit.finding_id.in_(chunk))
        max_audit_subquery = max_audit_subquery.group_by(DBaudit.finding_id)
        max_audit_subquery = max_audit_subquery.subquery()

        # Select the id from previously selected tupples.
        latest_audits_query = select(DBaudit.id_)
        latest_audits_query = latest_audits_query.join(max_audit_subquery, max_audit_subquery.c.audit_id == DBaudit.id_)
        latest_audits = db_connection.execute(latest_audits_query).scalars().all()
        query = update(DBaudit).where(DBaudit.id_.in_(latest_audits)).values(is_latest=True)
        db_connection.execute(query)

    db_connection.commit()


def revert_last_audit(db_connection: Session, finding_ids: list[int], status: FindingStatus | None) -> None:
    """
    Revert the last audit for a set of findings with specific status

    Args:
        db_connection (Session): Database session
        finding_ids (list[int]): List of findings
        status (FindingStatus | None): status to remove.
    """
    iterator = iter(finding_ids)
    while chunk := list(islice(iterator, 1000)):
        query = db_connection.query(DBaudit)
        query = query.where(DBaudit.finding_id.in_(chunk))
        query = query.where(DBaudit.is_latest == True)  # noqa: E712
        if status is not None:
            query = query.where(DBaudit.status == status)
        query.delete(synchronize_session=False)

    fix_last_audit(db_connection, finding_ids)

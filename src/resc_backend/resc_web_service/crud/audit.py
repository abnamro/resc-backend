# Standard Library
import logging
from datetime import datetime, timedelta, UTC

# Third Party
from sqlalchemy import extract, func, select, update
from sqlalchemy.engine import Row
from sqlalchemy.orm import Session

# First Party
from resc_backend.constants import (
    DEFAULT_RECORDS_PER_PAGE_LIMIT,
    MAX_RECORDS_PER_PAGE_LIMIT,
)
from resc_backend.db.model import DBaudit
from resc_backend.resc_web_service.schema.finding_status import FindingStatus
from resc_backend.resc_web_service.schema.time_period import TimePeriod

logger = logging.getLogger(__name__)

YEAR = "year"
MONTH = "month"
WEEK = "week"
DAY = "day"


def create_audit(
    db_connection: Session,
    finding_id: int,
    auditor: str,
    status: FindingStatus,
    comment: str = "",
) -> DBaudit:
    """
        Audit finding, updating the status and comment
    :param db_connection:
        Session of the database connection
    :param finding_id:
        id of the finding to audit
    :param auditor:
        identifier of the person performing the audit action
    :param status:
        audit status to set, type FindingStatus
    :param comment:
        audit comment to set
    :return: DBaudit
        The output will contain the audit that was created
    """
    # UPDATE FINDING to set is_latest to FALSE.
    db_connection.execute(update(DBaudit).where(DBaudit.finding_id == finding_id).values(is_latest=False))

    # Insert new Audit.
    db_audit = DBaudit(
        finding_id=finding_id,
        auditor=auditor,
        status=status,
        comment=comment,
        timestamp=datetime.now(UTC),
        is_latest=True,
    )
    db_connection.add(db_audit)
    db_connection.commit()
    db_connection.refresh(db_audit)

    return db_audit


def create_automated_audit(db_connection: Session, findings_ids: list[int], status: FindingStatus) -> list[DBaudit]:
    """
        Create automated audit for a list of findings.

    Args:
        db_connection (Session): Session of the database connection
        findings_ids (list[int]): list of id to audit
        status (FindingStatus): status to apply

    Returns:
        list[DBaudit]: newly created audits
    """
    db_connection.execute(update(DBaudit).where(DBaudit.finding_id.in_(findings_ids)).values(is_latest=False))

    db_audits = [DBaudit.create_automated(finding_id, status) for finding_id in findings_ids]
    db_connection.add_all(db_audits)
    db_connection.commit()

    logger.debug(f"Automated audit of {len(db_audits)} findings.")

    return db_audits


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

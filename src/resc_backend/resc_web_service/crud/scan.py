# Standard Library
from datetime import datetime

# Third Party
from sqlalchemy import func, update
from sqlalchemy.orm import Session

# First Party
from resc_backend.constants import (
    DEFAULT_RECORDS_PER_PAGE_LIMIT,
    MAX_RECORDS_PER_PAGE_LIMIT,
)
from resc_backend.db.model import (
    DBfinding,
    DBrepository,
    DBscan,
    DBscanFinding,
    DBVcsInstance,
)
from resc_backend.resc_web_service.crud import finding as finding_crud
from resc_backend.resc_web_service.crud import scan_finding as scan_finding_crud
from resc_backend.resc_web_service.schema import scan as scan_schema
from resc_backend.resc_web_service.schema.finding_status import FindingStatus, StatusStats
from resc_backend.resc_web_service.schema.scan_type import ScanType


def get_scan(db_connection: Session, scan_id: int) -> DBscan:
    scan = db_connection.query(DBscan).where(DBscan.id_ == scan_id).first()
    return scan


def get_latest_scan_for_repository(db_connection: Session, repository_id: int) -> DBscan:
    """
        Retrieve the most recent scan of a given repository object
    :param db_connection:
        Session of the database connection
    :param repository_id:
        id of the repository object for which to retrieve the most recent scan
    :return: scan
        scan object having the most recent timestamp for a given repository object
    """
    # TODO: refactor me to use is_latest intead of timestamps play?
    subquery = db_connection.query(func.max(DBscan.timestamp).label("max_time"))
    subquery = subquery.where(DBscan.repository_id == repository_id)
    subquery = subquery.subquery()

    query = db_connection.query(DBscan)
    query = query.join(subquery, DBscan.timestamp == subquery.c.max_time)
    query = query.where(DBscan.repository_id == repository_id)
    scan = query.first()

    return scan


def get_scans(
    db_connection: Session,
    skip: int = 0,
    limit: int = DEFAULT_RECORDS_PER_PAGE_LIMIT,
    repository_id: int = -1,
) -> list[DBscan]:
    """
        Retrieve the scan records, ordered by scan_id and optionally filtered by repository_id
    :param db_connection:
        Session of the database connection
    :param repository_id:
        optional int filtering the repository for which to retrieve scans
    :param skip:
        integer amount of records to skip to support pagination
    :param limit:
        integer amount of records to return, to support pagination
    :return: [DBscan]
        List of DBScan objects
    """
    limit_val = MAX_RECORDS_PER_PAGE_LIMIT if limit > MAX_RECORDS_PER_PAGE_LIMIT else limit
    query = db_connection.query(DBscan)

    if repository_id > 0:
        query = query.where(DBscan.repository_id == repository_id)

    scans = query.order_by(DBscan.id_).offset(skip).limit(limit_val).all()
    return scans


def get_scans_count(db_connection: Session, repository_id: int = -1) -> int:
    """
        Retrieve count of scan records optionally filtered by VCS provider
    :param db_connection:
        Session of the database connection
    :param repository_id:
        optional int filtering the repository for which to retrieve scans
    :return: total_count
        count of scans
    """
    query = db_connection.query(func.count(DBscan.id_))

    if repository_id > 0:
        query = query.where(DBscan.repository_id == repository_id)

    total_count = query.scalar()
    return total_count


def update_scan(db_connection: Session, scan_id: int, scan: scan_schema.ScanCreate) -> DBscan:
    db_scan = db_connection.query(DBscan).filter_by(id_=scan_id).first()
    db_scan.scan_type = scan.scan_type
    db_scan.last_scanned_commit = scan.last_scanned_commit
    db_scan.timestamp = scan.timestamp
    db_scan.increment_number = scan.increment_number
    db_scan.rule_pack = scan.rule_pack
    db_connection.commit()
    db_connection.refresh(db_scan)
    return db_scan


def create_scan(db_connection: Session, scan: scan_schema.ScanCreate) -> DBscan:
    # We only flag the previous ones if we are doing a base scan.
    # In the other cases they are simply marked as latest for incremental.
    if scan.scan_type == ScanType.BASE:
        query = update(DBscan)
        query = query.where(DBscan.repository_id == scan.repository_id)
        query = query.where(DBscan.rule_pack == scan.rule_pack)
        query = query.values(is_latest=False)
        db_connection.execute(query)

    db_scan = DBscan(
        scan_type=scan.scan_type,
        last_scanned_commit=scan.last_scanned_commit,
        repository_id=scan.repository_id,
        timestamp=scan.timestamp,
        increment_number=scan.increment_number,
        rule_pack=scan.rule_pack,
        is_latest=True,
    )
    db_connection.add(db_scan)
    db_connection.commit()
    db_connection.refresh(db_scan)
    return db_scan


def get_repository_findings_metadata_for_latest_scan(
    db_connection: Session, repository_id: int, scan_timestamp: datetime
) -> StatusStats:
    """
        Retrieves the finding metadata for latest scan of a repository from the database
    :param db_connection:
        Session of the database connection
    :param repository_id:
        repository id of the latest scan
    :param scan_timestamp:
        timestamp of the latest scan
    :return: findings_metadata
        findings_metadata containing the count for each status
    """
    scan_ids_latest_to_base = []
    scans = get_scans(db_connection=db_connection, repository_id=repository_id, limit=1000000)
    scans.sort(key=lambda x: x.timestamp, reverse=True)
    for scan in scans:
        if scan.timestamp <= scan_timestamp:
            scan_ids_latest_to_base.append(scan.id_)
            if scan.scan_type == ScanType.BASE:
                break

    findings_metadata = FindingStatus.init_statistics()
    if len(scan_ids_latest_to_base) > 0:
        findings_count_by_status = finding_crud.get_findings_count_by_status(
            db_connection,
            scan_ids=scan_ids_latest_to_base,
            finding_statuses=FindingStatus,
        )
        for finding in findings_count_by_status:
            finding_status: str = finding[1]
            count: int = finding[0]

            findings_metadata["total_findings_count"] += count
            if finding_status is None:
                findings_metadata[FindingStatus.NOT_ANALYZED.value.lower()] += count
            else:
                findings_metadata[finding_status.lower()] += count

    return findings_metadata


def delete_repository_findings_not_linked_to_any_scan(db_connection: Session, repository_id: int):
    """
        Delete findings for a given repository which are not linked to any scans
    :param db_connection:
        Session of the database connection
    :param repository_id:
        id of the repository
    """
    sub_query = db_connection.query(DBscanFinding.finding_id).distinct()
    query = db_connection.query(DBfinding)
    query = query.where(DBfinding.id_.not_in(sub_query))
    query = query.where(DBfinding.repository_id == repository_id)
    query.delete(synchronize_session=False)
    db_connection.commit()


def delete_scan(
    db_connection: Session,
    repository_id: int,
    scan_id: int,
    delete_related: bool = False,
):
    """
        Delete a scan object
    :param db_connection:
        Session of the database connection
    :param repository_id:
        repository_id for which findings will be deleted which are not linked to any scans
    :param scan_id:
        id of the scan to be deleted
    :param delete_related:
        if related records need to be deleted
    """
    if delete_related:
        scan_finding_crud.delete_scan_finding(db_connection, scan_id=scan_id)

    query = db_connection.query(DBscan)
    query = query.where(DBscan.id_ == scan_id)
    query.delete(synchronize_session=False)
    db_connection.commit()

    delete_repository_findings_not_linked_to_any_scan(db_connection, repository_id=repository_id)


def delete_scans_by_repository_id(db_connection: Session, repository_id: int):
    """
        Delete scans for a given repository
    :param db_connection:
        Session of the database connection
    :param repository_id:
        id of the repository
    """
    db_connection.query(DBscan).where(DBscan.repository_id == repository_id).delete(synchronize_session=False)
    db_connection.commit()


def delete_scans_by_vcs_instance_id(db_connection: Session, vcs_instance_id: int):
    """
        Delete scans for a given vcs instance
    :param db_connection:
        Session of the database connection
    :param vcs_instance_id:
        id of the vcs instance
    """
    query = db_connection.query(DBscan)
    query = query.where(DBscan.repository_id == DBrepository.id_)
    query = query.where(DBrepository.vcs_instance == DBVcsInstance.id_)
    query = query.where(DBVcsInstance.id_ == vcs_instance_id)
    query.delete(synchronize_session=False)
    db_connection.commit()

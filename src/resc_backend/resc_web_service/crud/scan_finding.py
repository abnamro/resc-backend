# Standard Library

# Third Party
from sqlalchemy.orm import Session

# First Party
from resc_backend.db.model import (
    DBfinding,
    DBrepository,
    DBscan,
    DBscanFinding,
    DBVcsInstance,
)


def create_scan_findings(db_connection: Session, scan_findings: list[DBscanFinding]) -> int:
    if len(scan_findings) < 1:
        # Function is called with an empty list of findings
        return 0

    # load existing scan findings for this scan into the session
    scan_id = scan_findings[0].scan_id
    _ = db_connection.query(DBscanFinding).where(DBscanFinding.scan_id == scan_id).all()

    # merge the new scan findings into the session, ignoring duplicates
    for scan_finding in scan_findings:
        db_connection.merge(scan_finding)

    db_connection.commit()

    return len(scan_findings)


def get_scan_findings(db_connection: Session, finding_id: int) -> list[DBscanFinding]:
    scan_findings = db_connection.query(DBscanFinding)
    scan_findings = scan_findings.where(DBscanFinding.finding_id == finding_id).all()
    return scan_findings


def delete_scan_finding(db_connection: Session, finding_id: int = None, scan_id: int = None):
    """
        Delete scan findings when finding id or scan id provided
    :param db_connection:
        Session of the database connection
    :param finding_id:
        optional, id of the finding
    :param scan_id:
        optional, id of the scan
    """
    if finding_id or scan_id:
        query = db_connection.query(DBscanFinding)
        if finding_id:
            query = query.where(DBscanFinding.finding_id == finding_id)
        if scan_id:
            query = query.where(DBscanFinding.scan_id == scan_id)
        query.delete(synchronize_session=False)
        db_connection.commit()


def delete_scan_finding_by_repository_id(db_connection: Session, repository_id: int):
    """
        Delete scan findings for a given repository
    :param db_connection:
        Session of the database connection
    :param repository_id:
        id of the repository
    """
    db_connection.query(DBscanFinding).where(
        DBscanFinding.scan_id == DBscan.id_,
        DBscanFinding.finding_id == DBfinding.id_,
        DBscan.repository_id == DBfinding.repository_id,
        DBscan.repository_id == repository_id,
    ).delete(synchronize_session=False)
    db_connection.commit()


def delete_scan_finding_by_vcs_instance_id(db_connection: Session, vcs_instance_id: int):
    """
        Delete scan findings for a given vcs instance
    :param db_connection:
        Session of the database connection
    :param vcs_instance_id:
        id of the vcs instance
    """
    db_connection.query(DBscanFinding).where(
        DBscanFinding.scan_id == DBscan.id_,
        DBscanFinding.finding_id == DBfinding.id_,
        DBscan.repository_id == DBrepository.id_,
        DBrepository.vcs_instance == DBVcsInstance.id_,
        DBVcsInstance.id_ == vcs_instance_id,
    ).delete(synchronize_session=False)
    db_connection.commit()

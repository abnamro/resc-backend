# Standard Library
import logging
from typing import Annotated

# Third Party
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import StringConstraints
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

# First Party
from resc_backend.constants import (
    CACHE_NAMESPACE_FINDING,
    CACHE_NAMESPACE_RULE,
    CACHE_NAMESPACE_RULE_PACK,
    DEFAULT_RECORDS_PER_PAGE_LIMIT,
    ERROR_MESSAGE_500,
    ERROR_MESSAGE_503,
    RWS_ROUTE_DETECTED_RULES,
    RWS_ROUTE_FINDINGS,
    RWS_ROUTE_SCANS,
    SCANS_TAG,
)
from resc_backend.db.model import DBfinding, DBscan, DBscanFinding
from resc_backend.resc_web_service.cache_manager import CacheManager
from resc_backend.resc_web_service.crud import audit as audit_crud
from resc_backend.resc_web_service.crud import finding as finding_crud
from resc_backend.resc_web_service.crud import repository as repository_crud
from resc_backend.resc_web_service.crud import rule as rule_crud
from resc_backend.resc_web_service.crud import scan as scan_crud
from resc_backend.resc_web_service.crud import scan_finding as scan_finding_crud
from resc_backend.resc_web_service.dependencies import get_db_connection
from resc_backend.resc_web_service.filters import FindingsFilter
from resc_backend.resc_web_service.helpers.resc_swagger_models import Model400, Model404
from resc_backend.resc_web_service.schema import finding as finding_schema
from resc_backend.resc_web_service.schema import scan as scan_schema
from resc_backend.resc_web_service.schema.finding_status import FindingStatus
from resc_backend.resc_web_service.schema.pagination_model import PaginationModel
from resc_backend.resc_web_service.schema.scan_type import ScanType

router = APIRouter(prefix=f"{RWS_ROUTE_SCANS}", tags=[SCANS_TAG])
logger = logging.getLogger(__name__)


@router.get(
    "",
    response_model=PaginationModel[scan_schema.ScanRead],
    summary="Get scans",
    status_code=status.HTTP_200_OK,
    responses={
        200: {"description": "Retrieve all the scan objects"},
        500: {"description": ERROR_MESSAGE_500},
        503: {"description": ERROR_MESSAGE_503},
    },
)
def get_all_scans(
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=DEFAULT_RECORDS_PER_PAGE_LIMIT, ge=1),
    db_connection: Session = Depends(get_db_connection),
) -> PaginationModel[scan_schema.ScanRead]:
    """
        Retrieve all scan objects paginated

    - **db_connection**: Session of the database connection
    - **skip**: Integer amount of records to skip to support pagination
    - **limit**: Integer amount of records to return, to support pagination
    - **return**: [ScanRead]
        The output will contain a PaginationModel containing the list of ScanRead type objects,
        or an empty list if no scan was found
    """
    scans = scan_crud.get_scans(db_connection, skip=skip, limit=limit)

    total_scans = scan_crud.get_scans_count(db_connection)

    return PaginationModel[scan_schema.ScanRead](data=scans, total=total_scans, limit=limit, skip=skip)


@router.post(
    "",
    response_model=scan_schema.ScanRead,
    summary="Create a scan",
    status_code=status.HTTP_201_CREATED,
    responses={
        201: {"description": "Create a new scan"},
        400: {"model": Model400, "description": "Error creating a new scan"},
        404: {"model": Model404, "description": "Repository not found"},
        500: {"description": ERROR_MESSAGE_500},
        503: {"description": ERROR_MESSAGE_503},
    },
)
def create_scan(scan: scan_schema.ScanCreate, db_connection: Session = Depends(get_db_connection)):
    """
        Create a scan with all the information

    - **db_connection**: Session of the database connection
    - **scan_type**: scan type, supported values are BASE or INCREMENTAL
    - **last_scanned_commit**: last scanned commit hash
    - **timestamp**: creation timestamp
    - **increment_number**: scan increment number
    - **rule_pack**: rule pack version
    - **repository_id**: repository id
    """
    # First we check that the repo actually exists.
    repository = repository_crud.get_repository(db_connection=db_connection, repository_id=scan.repository_id)
    if repository is None:
        raise HTTPException(status_code=404, detail="Repository not found")

    # We check that the repo is NOT deleted.
    # We just scanned it, therefore it exists!
    if repository.deleted_at is not None:
        logger.warning(f"Repository {repository.id_} was marked as deleted, undeleting it.")
        repository_crud.undelete_repository(db_connection, repository_ids=[repository.id_])
        finding_ids = finding_crud.get_finding_for_repository(
            db_connection, repository_ids=[repository.id_], status=FindingStatus.NOT_ACCESSIBLE, not_status=None
        )
        audit_crud.revert_last_audit(db_connection, finding_ids=finding_ids, status=FindingStatus.NOT_ACCESSIBLE)

    # Determine the increment number if needed and not supplied
    if scan.scan_type == ScanType.INCREMENTAL and (not scan.increment_number or scan.increment_number <= 0):
        last_scan = scan_crud.get_latest_scan_for_repository(
            db_connection=db_connection, repository_id=scan.repository_id
        )
        new_increment = last_scan.increment_number + 1
        scan.increment_number = new_increment

    try:
        created_scan = scan_crud.create_scan(db_connection=db_connection, scan=scan)
    except IntegrityError as err:
        logger.debug(f"Error creating new scan object: {err}")
        raise HTTPException(status_code=400, detail="Error creating new scan object") from err
    return created_scan


@router.get(
    "/{scan_id}",
    response_model=scan_schema.ScanRead,
    summary="Fetch a scan by ID",
    status_code=status.HTTP_200_OK,
    responses={
        200: {"description": "Retrieve scan <scan_id>"},
        404: {"model": Model404, "description": "Scan <scan_id> not found"},
        500: {"description": ERROR_MESSAGE_500},
        503: {"description": ERROR_MESSAGE_503},
    },
)
def read_scan(scan_id: int, db_connection: Session = Depends(get_db_connection)):
    """
        Read a scan by ID

    - **db_connection**: Session of the database connection
    - **scan_id**: ID of the scan for which details need to be fetched
    """
    db_scan = scan_crud.get_scan(db_connection, scan_id=scan_id)
    if db_scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return db_scan


@router.put(
    "/{scan_id}",
    response_model=scan_schema.ScanRead,
    summary="Update an existing scan",
    status_code=status.HTTP_200_OK,
    responses={
        200: {"description": "Update scan <scan_id>"},
        404: {"model": Model404, "description": "Scan <scan_id> not found"},
        500: {"description": ERROR_MESSAGE_500},
        503: {"description": ERROR_MESSAGE_503},
    },
)
def update_scan(
    scan_id: int,
    scan: scan_schema.ScanCreate,
    db_connection: Session = Depends(get_db_connection),
):
    """
        Update an existing scan

    - **db_connection**: Session of the database connection
    - **scan_type**: scan type, supported values are BASE or INCREMENTAL
    - **last_scanned_commit**: last scanned commit
    - **timestamp**: scan timestamp
    - **increment_number**: scan increment number
    - **rule_pack**: rule pack version
    - **repository_id**: repository id

    """
    db_scan = scan_crud.get_scan(db_connection, scan_id=scan_id)
    if db_scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan_crud.update_scan(db_connection=db_connection, scan_id=scan_id, scan=scan)


@router.delete(
    "/{scan_id}",
    summary="Delete a scan",
    status_code=status.HTTP_200_OK,
    responses={
        200: {"description": "Delete scan <scan_id>"},
        404: {"model": Model404, "description": "Scan <scan_id> not found"},
        500: {"description": ERROR_MESSAGE_500},
        503: {"description": ERROR_MESSAGE_503},
    },
)
def delete_scan(scan_id: int, db_connection: Session = Depends(get_db_connection)):
    """
        Delete a scan object

    - **db_connection**: Session of the database connection
    - **scan_id**: ID of the scan to delete
    - **return**: The output will contain a success or error message based on the success of the deletion
    """
    db_scan = scan_crud.get_scan(db_connection, scan_id=scan_id)
    if db_scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    scan_crud.delete_scan(
        db_connection,
        repository_id=db_scan.repository_id,
        scan_id=scan_id,
        delete_related=True,
    )
    return {"ok": True}


@router.post(
    f"/{{scan_id}}{RWS_ROUTE_FINDINGS}",
    response_model=int,
    summary="Create scan findings",
    status_code=status.HTTP_201_CREATED,
    responses={
        201: {"description": "Create findings and their associated scan_findings for scan <scan_id>"},
        500: {"description": ERROR_MESSAGE_500},
        503: {"description": ERROR_MESSAGE_503},
    },
)
async def create_scan_findings(
    scan_id: int,
    findings: list[finding_schema.FindingCreate],
    db_connection: Session = Depends(get_db_connection),
) -> int:
    """
        Creates findings and their associated scan_findings for a given scan

    - **db_connection**: Session of the database connection
    - **scan_id**:  Id of the scan for which findings need to be inserted
    - **file_path**: file path
    - **line_number**: Line number
    - **column_start**: Column start
    - **column_end**: Column end
    - **commit_id**: commit hash
    - **commit_message**: Commit message
    - **commit_timestamp**: Commit timestamp
    - **author**: Author name
    - **email**: Email of the author
    - **status**: Status of the finding, Valid values are NOT_ANALYZED, NOT_ACCESSIBLE,
                  CLARIFICATION_REQUIRED, FALSE_POSITIVE, TRUE_POSITIVE, OUTDATED
    - **comment**: Comment
    - **event_sent_on**: event sent timestamp
    - **rule_name**: rule name
    - **repository_id**: repository id of the finding
    - **return**: [FindingRead]
        The output will contain a PaginationModel containing the list of FindingRead type objects,
        or an empty list if no scan was found
    """

    db_scan: DBscan = scan_crud.get_scan(db_connection, scan_id=scan_id)
    if db_scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    # 1. Fetch rules with scan_as_dir
    rules_scan_as_dir: list[str] = rule_crud.get_scan_as_dir_rules_by_scan_id(
        db_connection=db_connection, scan_id=scan_id
    )
    logger.debug(f"rules as directory: {', '.join(rules_scan_as_dir)}")

    # 2. split findings into 2 category: scan_as_dir and normal.
    findings_as_repo = []
    findings_as_dir = []
    for finding in findings:
        (findings_as_dir if finding.rule_name in rules_scan_as_dir else findings_as_repo).append(finding)
    logger.debug(f"number of findings scan as directory: {len(findings_as_dir)}")
    logger.debug(f"number of findings scan as repo: {len(findings_as_repo)}")

    # 3. Process normal as previously done.
    created_findings: list[DBfinding] = finding_crud.create_findings(
        db_connection=db_connection, findings=findings_as_repo
    )
    # 4. Process scan_as_dir with updates.
    created_dir_findings: list[DBfinding] = finding_crud.create_or_update_findings(
        db_connection=db_connection, findings=findings_as_dir
    )

    created_findings.extend(created_dir_findings)
    # 5. Add link between findings and scan
    scan_findings: list[DBscanFinding] = []
    for finding in created_findings:
        scan_finding = DBscanFinding(finding_id=finding.id_, scan_id=scan_id)
        scan_findings.append(scan_finding)

    # 6. merge.
    _ = scan_finding_crud.create_scan_findings(db_connection=db_connection, scan_findings=scan_findings)

    # 7. Mark old scan_as_dir findings as outdated.
    findings_to_audit: list[int] = finding_crud.get_findings_from_repo_of_scan_as_dir(
        db_connection=db_connection, scan=db_scan
    )
    audit_crud.create_automated_audits(
        db_connection=db_connection, findings_ids=findings_to_audit, status=FindingStatus.OUTDATED
    )

    # 8. Mark findings which are no longer in rule pack (i.e. rule name not in current rule pack) as outdated
    old_findings_to_audit: list[int] = finding_crud.get_untriaged_finding_outdated_for_current_scan(
        db_connection=db_connection, scan=db_scan
    )
    audit_crud.create_automated_audits(
        db_connection=db_connection, findings_ids=old_findings_to_audit, status=FindingStatus.OUTDATED
    )

    created_findings_ids = [finding.id_ for finding in created_findings]
    # 9. Mark active findings as no longer outdated
    audit_crud.clear_outdated_no_longer_outdated(db_connection=db_connection, findings_ids=created_findings_ids)

    # Clear cache related to findings
    await CacheManager.clear_cache_by_namespace(namespace=CACHE_NAMESPACE_FINDING)
    await CacheManager.clear_cache_by_namespace(namespace=CACHE_NAMESPACE_RULE)
    await CacheManager.clear_cache_by_namespace(namespace=CACHE_NAMESPACE_RULE_PACK)

    return len(created_findings)


@router.get(
    f"/{{scan_id}}{RWS_ROUTE_FINDINGS}",
    response_model=PaginationModel[finding_schema.FindingRead],
    summary="Get scan findings associated with a scan ID",
    status_code=status.HTTP_200_OK,
    responses={
        200: {"description": "Retrieve findings associated with scan <scan_id>"},
        500: {"description": ERROR_MESSAGE_500},
        503: {"description": ERROR_MESSAGE_503},
    },
)
def get_scan_findings(
    scan_id: int,
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=DEFAULT_RECORDS_PER_PAGE_LIMIT, ge=1),
    rules: list[Annotated[str, StringConstraints(pattern=r"^[A-z0-9 .\-_%]*$")]] = Query(
        [], alias="rule", title="rule"
    ),
    statuses: list[FindingStatus] = Query([], alias="status", title="status"),
    db_connection: Session = Depends(get_db_connection),
) -> PaginationModel[finding_schema.FindingRead]:
    """
        Retrieve all finding objects paginated related to a scan_id

    - **db_connection**: Session of the database connection
    - **scan_id**: Id of the scan for which to retrieve the findings
    - **skip**: Integer amount of records to skip to support pagination
    - **limit**: Integer amount of records to return, to support pagination
    - **rules**: optional, filter on rule name. It is used as a string contains filter
    - **statuses**:  optional, filter on status of findings
    - **return**: [FindingRead]
        The output will contain a PaginationModel containing the list of FindingRead type objects,
        or an empty list if no scan was found
    """
    findings = finding_crud.get_scans_findings(
        db_connection,
        scan_ids=[scan_id],
        skip=skip,
        limit=limit,
        rules_filter=rules,
        statuses_filter=statuses,
    )

    findings_filter = FindingsFilter(scan_ids=[scan_id], rule_names=rules, finding_statuses=statuses)
    total_findings = finding_crud.get_total_findings_count(db_connection, findings_filter=findings_filter)

    return PaginationModel[finding_schema.FindingRead](data=findings, total=total_findings, limit=limit, skip=skip)


@router.get(
    f"{RWS_ROUTE_FINDINGS}/",
    response_model=PaginationModel[finding_schema.FindingRead],
    summary="Get scan findings",
    status_code=status.HTTP_200_OK,
    responses={
        200: {"description": "Retrieve findings associated with scan <scan_id>"},
        500: {"description": ERROR_MESSAGE_500},
        503: {"description": ERROR_MESSAGE_503},
    },
)
def get_scans_findings(
    scan_ids: list[int] = Query([], alias="scan_id", title="Scan ids"),
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=DEFAULT_RECORDS_PER_PAGE_LIMIT, ge=1),
    rules: list[Annotated[str, StringConstraints(pattern=r"^[A-z0-9 .\-_%]*$")]] = Query(
        [], alias="rule", title="rule"
    ),
    statuses: list[FindingStatus] | None = Query([], alias="status", title="status"),
    db_connection: Session = Depends(get_db_connection),
) -> PaginationModel[finding_schema.FindingRead]:
    """
        Retrieve all finding objects paginated related to a scan_id

    - **db_connection**: Session of the database connection
    - **scan_ids**: Optional, List of scan IDs for which findings to be retrieved
    - **skip**: Integer amount of records to skip to support pagination
    - **limit**: Integer amount of records to return, to support pagination
    - **rule**: optional, filter on rule name. It is used as a string contains filter
    - **statuses**:  optional, filter on status of findings
    - **return**: [FindingRead]
        The output will contain a PaginationModel containing the list of FindingRead type objects,
        or an empty list if no scan was found
    """
    findings = finding_crud.get_scans_findings(
        db_connection,
        scan_ids=scan_ids,
        skip=skip,
        limit=limit,
        rules_filter=rules,
        statuses_filter=statuses,
    )

    findings_filter = FindingsFilter(scan_ids=scan_ids, rule_names=rules, finding_statuses=statuses)
    total_findings = finding_crud.get_total_findings_count(db_connection, findings_filter=findings_filter)

    return PaginationModel[finding_schema.FindingRead](data=findings, total=total_findings, limit=limit, skip=skip)


@router.get(
    f"{RWS_ROUTE_DETECTED_RULES}/",
    response_model=list[str],
    summary="Get unique rules from scans",
    status_code=status.HTTP_200_OK,
    responses={
        200: {"description": "Retrieve all the unique rules associated with specified scans"},
        500: {"description": ERROR_MESSAGE_500},
        503: {"description": ERROR_MESSAGE_503},
    },
)
def get_distinct_rules_from_scans(
    scan_ids: list[int] = Query([], alias="scan_id", title="Scan ids"),
    db_connection: Session = Depends(get_db_connection),
) -> list[str]:
    """
        Retrieve all uniquely detected rules for given scans

    - **db_connection**: Session of the database connection
    - **scan_ids**: scan ids for which to retrieve the unique rules
    - **return**: List[str]
        The output will contain a list of strings of unique rules for given scan ids
    """
    return_rules = []
    if scan_ids:
        rules = finding_crud.get_distinct_rules_from_scans(db_connection, scan_ids=scan_ids)
        for rule in rules:
            return_rules.append(rule.rule_name)
    return return_rules

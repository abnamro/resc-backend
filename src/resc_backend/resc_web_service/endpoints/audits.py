# Standard Library
from datetime import datetime

# Third Party
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi_cache.decorator import cache
from sqlalchemy.orm import Session

# First Party
from resc_backend.constants import (
    CACHE_NAMESPACE_FINDING,
    DEFAULT_RECORDS_PER_PAGE_LIMIT,
    ERROR_MESSAGE_500,
    ERROR_MESSAGE_503,
    FINDINGS_TAG,
    REDIS_CACHE_EXPIRE,
    RWS_ROUTE_AUDITS,
)
from resc_backend.resc_web_service.crud import audit as audit_crud
from resc_backend.resc_web_service.dependencies import get_db_connection
from resc_backend.resc_web_service.schema.audit import AuditFinding
from resc_backend.resc_web_service.schema.finding_status import FindingStatus
from resc_backend.resc_web_service.schema.pagination_model import PaginationModel

router = APIRouter(prefix=f"{RWS_ROUTE_AUDITS}", tags=[FINDINGS_TAG])


@router.get(
    "",
    response_model=PaginationModel[AuditFinding],
    summary="Get audits",
    status_code=status.HTTP_200_OK,
    responses={
        200: {"description": "Retrieve all the past audits"},
        500: {"description": ERROR_MESSAGE_500},
        503: {"description": ERROR_MESSAGE_503},
    },
)
@cache(namespace=CACHE_NAMESPACE_FINDING, expire=REDIS_CACHE_EXPIRE)
def get_all_audits(
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=DEFAULT_RECORDS_PER_PAGE_LIMIT, ge=1),
    auditor: str | None = Query(None),
    fromDate: datetime | None = Query(None),
    toDate: datetime | None = Query(None), 
    status: list[FindingStatus] | None = Query(None),
    isLatest: bool | None = Query(None),
    db_connection: Session = Depends(get_db_connection),
) -> PaginationModel[AuditFinding]:
    """
        Retrieve all audits objects paginated

    - **db_connection**: Session of the database connection
    - **skip**: Integer amount of records to skip to support pagination
    - **limit**: Integer amount of records to return, to support pagination
    - **auditor**: String to filter which auditor to audit.
    - **fromDate**: DateTime to filter from which we look at (oldest)
    - **toDate**: DateTime to filter to which we look at (youngest)
    - **status**: Finding status to filter on
    - **isLatest**: Whether to only consider latest audits.
    - **return**: [AuditFinding]
        The output will contain a PaginationModel containing the list of AuditFinding type objects,
        or an empty list if no audits was found
    """
    audits = audit_crud.get_audits(db_connection, skip=skip, limit=limit, auditor=auditor, fromDate=fromDate, toDate=toDate, status=status, isLatest=isLatest)

    total_audits = audit_crud.get_total_audits_count(db_connection, auditor=auditor, fromDate=fromDate, toDate=toDate, status=status, isLatest=isLatest)

    return PaginationModel[AuditFinding](data=audits, total=total_audits, limit=limit, skip=skip)


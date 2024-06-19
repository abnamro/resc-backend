# Standard Library
import logging
from datetime import datetime

# Third Party
from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi_cache.decorator import cache
from sqlalchemy.orm import Session

# First Party
from resc_backend.constants import (
    CACHE_NAMESPACE_FINDING,
    CACHE_NAMESPACE_RULE,
    ERROR_MESSAGE_500,
    ERROR_MESSAGE_503,
    REDIS_CACHE_EXPIRE,
    RULES_TAG,
    RWS_ROUTE_DETECTED_RULES,
    RWS_ROUTE_FINDING_STATUS_COUNT,
    RWS_ROUTE_RULES,
)
from resc_backend.resc_web_service.crud import finding as finding_crud
from resc_backend.resc_web_service.crud import rule as rule_crud
from resc_backend.resc_web_service.dependencies import get_db_connection
from resc_backend.resc_web_service.schema.finding_status import FindingStatus
from resc_backend.resc_web_service.schema.rule import RuleRead
from resc_backend.resc_web_service.schema.rule_count_model import RuleFindingCountModel
from resc_backend.resc_web_service.helpers.resc_swagger_models import Model404, Model422
from resc_backend.resc_web_service.schema.status_count import StatusCount
from resc_backend.resc_web_service.schema.vcs_provider import VCSProviders

router = APIRouter(tags=[RULES_TAG])

logger = logging.getLogger(__name__)


@router.get(
    f"{RWS_ROUTE_DETECTED_RULES}",
    response_model=list[str],
    summary="Get unique rules from findings",
    status_code=status.HTTP_200_OK,
    responses={
        200: {"description": "Retrieve all the unique detected rules across all the findings"},
        500: {"description": ERROR_MESSAGE_500},
        503: {"description": ERROR_MESSAGE_503},
    },
)
@cache(namespace=CACHE_NAMESPACE_RULE, expire=REDIS_CACHE_EXPIRE)
def get_distinct_rules_from_findings(
    finding_statuses: list[FindingStatus] = Query(None, alias="findingstatus", title="FindingStatuses"),
    vcs_providers: list[VCSProviders] = Query(None, alias="vcsprovider", title="VCSProviders"),
    project_name: str | None = Query("", pattern=r"^[A-z0-9 .\-_%]*$"),
    repository_name: str | None = Query("", pattern=r"^[A-z0-9 .\-_%]*$"),
    start_date_time: datetime | None = Query(None),
    end_date_time: datetime | None = Query(None),
    rule_pack_versions: list[str] | None = Query(None, alias="rule_pack_version", title="RulePackVersion"),
    db_connection: Session = Depends(get_db_connection),
) -> list[str]:
    """
        Retrieve all uniquely detected rules across all findings in the database

    - **db_connection**: Session of the database connection
    - **finding_statuses**: Optional, filter on supported finding statuses
    - **vcs_providers**: Optional, filter on supported vcs provider types
    - **project_name**: Optional, filter on project name. It is used as a full string match filter
    - **repository_name**: Optional, filter on repository name. It is used as a string contains filter
    - **start_date_time**: Optional, filter on start date
    - **end_date_time**: Optional, filter on end date
    - **rule_pack_version**: Optional, filter on rule pack version
    - **return**: List[str] The output will contain a list of strings of unique rules in the findings table
    """
    return finding_crud.get_distinct_rule_names_from_findings(
        db_connection,
        finding_statuses=finding_statuses,
        vcs_providers=vcs_providers,
        project_name=project_name,
        repository_name=repository_name,
        start_date_time=start_date_time,
        end_date_time=end_date_time,
        rule_pack_versions=rule_pack_versions,
    )


@router.get(
    f"{RWS_ROUTE_RULES}",
    response_model=RuleRead,
    summary="Get unique rule from rule pack",
    status_code=status.HTTP_200_OK,
    responses={
        200: {"description": "Retrieve the rule data for a rule pack"},
        404: {"model": Model404, "description": "Scan <scan_id> not found"},
        422: {"model": Model422, "description": "RulePackVersion and RuleName required"},
        500: {"description": ERROR_MESSAGE_500},
        503: {"description": ERROR_MESSAGE_503},
    },
)
@cache(namespace=CACHE_NAMESPACE_RULE, expire=REDIS_CACHE_EXPIRE)
def get_distinct_rules_from_findings(
    rule_pack_version: str = Query(None, alias="rule_pack_version", title="RulePackVersion"),
    rule_name: str = Query(None, alias="rule_name", title="RuleName"),
    db_connection: Session = Depends(get_db_connection),
) -> RuleRead:
    """
        Retrieve the rule data from a rule_name and rule_pack

    - **db_connection**: Session of the database connection
    - **rule_pack_version**: filter on rule pack version
    - **rule_name**: filter on rule pack version
    - **return**: List[str] The output will contain a list of strings of unique rules in the findings table
    """
    if rule_pack_version is None:
        raise HTTPException(status_code=422, detail="rule_pack_version required")

    if rule_name is None:
        raise HTTPException(status_code=422, detail="rule_name required")

    db_rule = rule_crud.get_rule_by_rule_name_and_rule_pack_version(db_connection=db_connection,rule_name=rule_name,rule_pack_version=rule_pack_version)
    if db_rule == None:
        raise HTTPException(status_code=404, detail="Rule not found")

    return db_rule


@router.get(
    f"{RWS_ROUTE_RULES}{RWS_ROUTE_FINDING_STATUS_COUNT}",
    response_model=list[RuleFindingCountModel],
    summary="Get detected rules with counts per status",
    status_code=status.HTTP_200_OK,
    responses={
        200: {"description": "Retrieve all the detected rules with counts per status"},
        500: {"description": ERROR_MESSAGE_500},
        503: {"description": ERROR_MESSAGE_503},
    },
)
@cache(namespace=CACHE_NAMESPACE_FINDING, expire=REDIS_CACHE_EXPIRE)
def get_rules_finding_status_count(
    rule_pack_versions: list[str] | None = Query(None, alias="rule_pack_version", title="RulePackVersion"),
    rule_tags: list[str] | None = Query(None, alias="rule_tag", title="RuleTag"),
    db_connection: Session = Depends(get_db_connection),
) -> list[RuleFindingCountModel]:
    """
        Retrieve all detected rules with finding counts per supported status

    - **rule_pack_version**: Optional, filter on rule pack version
    - **rule_tag**: Optional, filter on rule tag
    - **db_connection**: Session of the database connection
    - **return**: List[str] The output will contain a list of strings of unique rules with counts per status
    """
    rule_finding_counts = finding_crud.get_rule_findings_count_by_status(
        db_connection, rule_pack_versions=rule_pack_versions, rule_tags=rule_tags
    )
    rule_findings_counts = []

    for rule_name, rule_counts in rule_finding_counts.items():
        rule_finding_count = RuleFindingCountModel(
            rule_name=rule_name, finding_count=rule_counts["total_findings_count"]
        )
        rule_finding_count.finding_statuses_count.append(
            StatusCount(status=FindingStatus.TRUE_POSITIVE.value, count=rule_counts["true_positive"])
        )
        rule_finding_count.finding_statuses_count.append(
            StatusCount(status=FindingStatus.FALSE_POSITIVE.value, count=rule_counts["false_positive"])
        )
        rule_finding_count.finding_statuses_count.append(
            StatusCount(status=FindingStatus.NOT_ANALYZED.value, count=rule_counts["not_analyzed"])
        )
        rule_finding_count.finding_statuses_count.append(
            StatusCount(status=FindingStatus.NOT_ACCESSIBLE.value, count=rule_counts["not_accessible"])
        )
        rule_finding_count.finding_statuses_count.append(
            StatusCount(
                status=FindingStatus.CLARIFICATION_REQUIRED.value,
                count=rule_counts["clarification_required"],
            )
        )
        rule_finding_count.finding_statuses_count.append(
            StatusCount(
                status=FindingStatus.OUTDATED.value,
                count=rule_counts["outdated"],
            )
        )
        rule_findings_counts.append(rule_finding_count)

    return rule_findings_counts

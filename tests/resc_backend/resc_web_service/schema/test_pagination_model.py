# Standard Library
from datetime import UTC, datetime

# Third Party
import pytest
from pydantic import ValidationError

# First Party
from resc_backend.db.model import DBfinding
from resc_backend.resc_web_service.schema.finding import FindingRead
from resc_backend.resc_web_service.schema.pagination_model import PaginationModel


def test_pagination_model_int():
    int_list = []
    for i in range(1, 6):
        int_list.append(i)

    total = 999
    limit = 50
    skip = 0

    paginated = PaginationModel[int](data=int_list, total=total, limit=limit, skip=skip)

    assert paginated.total == total
    assert paginated.limit == limit
    assert paginated.skip == skip
    assert len(paginated.data) == 5
    for i in range(len(paginated.data)):
        assert paginated.data[i] == i + 1


def test_pagination_model_invalid_data():
    str_list = []
    for i in range(1, 6):
        str_list.append(f"test{i}")

    total = -999
    limit = -50
    skip = -1
    with pytest.raises(ValidationError) as validation_error:
        PaginationModel[int](data=str_list, total=total, limit=limit, skip=skip)

    validation_errors = validation_error.value.errors()

    for i in range(0, 5):
        assert validation_errors[i]["loc"][0] == "data"
        assert validation_errors[i]["loc"][1] == i
        assert validation_errors[i]["msg"] == "Input should be a valid integer, unable to parse string as an integer"
        assert validation_errors[i]["type"] == "int_parsing"
    for i in range(5, 8):
        assert validation_errors[i]["msg"] == "Input should be greater than -1"
        assert validation_errors[i]["type"] == "greater_than"


def test_pagination_model_findings():
    findings = []
    for i in range(1, 6):
        finding = DBfinding(
            file_path=f"file_path_{i}",
            line_number=i,
            column_start=i,
            column_end=i,
            commit_id=f"commit_id_{i}",
            commit_message=f"commit_message_{i}",
            commit_timestamp=datetime.now(UTC),
            author=f"author_{i}",
            email=f"email_{i}",
            rule_name=f"rule_{i}",
            event_sent_on=datetime.now(UTC),
            repository_id=1,
        )
        finding.id_ = i
        findings.append(FindingRead.create_from_db_entities(finding, scan_ids=[]))

    total = 999
    limit = 50
    skip = 0

    paginated = PaginationModel[FindingRead](data=findings, total=total, limit=limit, skip=skip)

    assert paginated.total == total
    assert paginated.limit == limit
    assert paginated.skip == skip
    assert len(paginated.data) == 5
    for i in range(len(paginated.data)):
        assert paginated.data[i].id_ == i + 1

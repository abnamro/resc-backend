# Standard Library
import json
import unittest
from collections.abc import Generator
from datetime import UTC, datetime
from unittest.mock import ANY, call, patch

# Third Party
import pytest
from fastapi.testclient import TestClient
from fastapi_cache import FastAPICache
from fastapi_cache.backends.inmemory import InMemoryBackend

# First Party
from resc_backend.constants import (
    CACHE_NAMESPACE_FINDING,
    CACHE_PREFIX,
    REDIS_CACHE_EXPIRE,
    RWS_ROUTE_AUDIT,
    RWS_ROUTE_BY_RULE,
    RWS_ROUTE_COUNT_BY_TIME,
    RWS_ROUTE_FINDINGS,
    RWS_ROUTE_SUPPORTED_STATUSES,
    RWS_ROUTE_TOTAL_COUNT_BY_RULE,
    RWS_VERSION_PREFIX,
)
from resc_backend.db.model import DBaudit, DBfinding, DBscanFinding
from resc_backend.resc_web_service.api import app
from resc_backend.resc_web_service.cache_manager import CacheManager
from resc_backend.resc_web_service.dependencies import requires_auth, requires_no_auth
from resc_backend.resc_web_service.filters import FindingsFilter
from resc_backend.resc_web_service.schema.audit import AuditMultiple
from resc_backend.resc_web_service.schema.date_filter import DateFilter
from resc_backend.resc_web_service.schema.finding import (
    Finding,
    FindingBase,
    FindingCreate,
    FindingPatch,
    FindingRead,
)
from resc_backend.resc_web_service.schema.finding_status import FindingStatus


@pytest.fixture(autouse=True)
def _init_cache() -> Generator[ANY, ANY, None]:
    FastAPICache.init(
        InMemoryBackend(),
        prefix=CACHE_PREFIX,
        expire=REDIS_CACHE_EXPIRE,
        key_builder=CacheManager.request_key_builder,
        enable=True,
    )
    yield
    FastAPICache.reset()


class TestFindings(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)
        app.dependency_overrides[requires_auth] = requires_no_auth
        self.db_findings = []
        self.db_scan_findings = []
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
            self.db_findings.append(finding)
            self.db_findings[i - 1].id_ = i
            self.db_scan_findings.append(DBscanFinding(scan_id=i, finding_id=i))

        self.db_audits = []
        for i in range(1, 6):
            audit = DBaudit(
                finding_id=i,
                auditor=f"auditor {i}",
                status=FindingStatus.TRUE_POSITIVE.value,
                comment=f"comment {i}",
                timestamp=datetime.now(UTC),
                is_latest=True,
            )
            self.db_audits.append(audit)
            self.db_audits[i - 1].id_ = i

        self.enriched_findings = []
        for i in range(1, 6):
            self.enriched_findings.append(
                FindingRead(
                    id_=i,
                    scan_ids=[i],
                    repository_id=i,
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
                )
            )

    @staticmethod
    def assert_db_finding(data, finding: DBfinding, scan_findings: list[DBscanFinding]):
        assert data["file_path"] == finding.file_path
        assert data["line_number"] == finding.line_number
        assert data["column_start"] == finding.column_start
        assert data["column_end"] == finding.column_end
        assert data["commit_id"] == finding.commit_id
        assert data["commit_message"] == finding.commit_message
        assert datetime.fromisoformat(data["commit_timestamp"]) == finding.commit_timestamp
        assert data["author"] == finding.author
        assert data["email"] == finding.email
        assert data["rule_name"] == finding.rule_name
        assert data["scan_ids"] == [x.scan_id for x in scan_findings]
        assert data["repository_id"] == finding.repository_id
        assert data["id_"] == finding.id_
        assert finding.id_ == scan_findings[0].finding_id
        assert datetime.fromisoformat(data["event_sent_on"]) == finding.event_sent_on

    @staticmethod
    def assert_finding(data, finding: Finding):
        assert data["file_path"] == finding.file_path
        assert data["line_number"] == finding.line_number
        assert data["column_start"] == finding.column_start
        assert data["column_end"] == finding.column_end
        assert data["commit_id"] == finding.commit_id
        assert data["commit_message"] == finding.commit_message
        assert datetime.fromisoformat(data["commit_timestamp"]) == finding.commit_timestamp
        assert data["author"] == finding.author
        assert data["email"] == finding.email
        assert data["rule_name"] == finding.rule_name
        assert data["scan_ids"] == finding.scan_ids
        assert data["repository_id"] == finding.repository_id
        assert data["id_"] == finding.id_
        assert datetime.fromisoformat(data["event_sent_on"]) == finding.event_sent_on

    @staticmethod
    def cast_db_finding_to_finding_create(finding: DBfinding, scan_findings: list[DBscanFinding]):
        return FindingCreate(
            scan_ids=[x.scan_id for x in scan_findings],
            repository_id=finding.repository_id,
            file_path=finding.file_path,
            line_number=finding.line_number,
            column_start=finding.column_start,
            column_end=finding.column_end,
            commit_id=finding.commit_id,
            commit_message=finding.commit_message,
            commit_timestamp=finding.commit_timestamp,
            author=finding.author,
            email=finding.email,
            rule_name=finding.rule_name,
            event_sent_on=finding.event_sent_on,
        )

    @staticmethod
    def cast_db_finding_to_finding_base(finding: DBfinding, scan_findings: list[DBscanFinding]):
        return FindingBase(
            scan_id=[x.scan_id for x in scan_findings],
            file_path=finding.file_path,
            line_number=finding.line_number,
            column_start=finding.column_start,
            column_end=finding.column_end,
            commit_id=finding.commit_id,
            commit_message=finding.commit_message,
            commit_timestamp=finding.commit_timestamp,
            author=finding.author,
            email=finding.email,
            rule_name=finding.rule_name,
            event_sent_on=finding.event_sent_on,
        )

    @staticmethod
    def cast_db_finding_to_finding_patch(finding: DBfinding):
        return FindingPatch(event_sent_on=finding.event_sent_on)

    @staticmethod
    def create_json_body(finding: DBfinding, scan_findings: list[DBscanFinding]):
        return json.loads(TestFindings.cast_db_finding_to_finding_create(finding, scan_findings).model_dump_json())

    @staticmethod
    def create_json_body_multiple_audit(audit_multiple: AuditMultiple):
        return json.loads(audit_multiple.model_dump_json())

    @staticmethod
    def assert_cache(cached_response):
        assert FastAPICache.get_enable() is True
        assert FastAPICache.get_prefix() == CACHE_PREFIX
        assert FastAPICache.get_expire() == REDIS_CACHE_EXPIRE
        assert FastAPICache.get_key_builder() is not None
        assert FastAPICache.get_coder() is not None
        assert cached_response.headers.get("cache-control") is not None

    @patch("resc_backend.resc_web_service.crud.finding.get_finding")
    def test_get_findings_non_existing(self, get_finding):
        finding_id = 999
        get_finding.return_value = None
        with self.client as client:
            response = client.get(f"{RWS_VERSION_PREFIX}{RWS_ROUTE_FINDINGS}/{finding_id}")
            assert response.status_code == 404, response.text
            get_finding.assert_called_once_with(ANY, finding_id=finding_id)

            # Make the second request to retrieve response from cache
            cached_response = client.get(f"{RWS_VERSION_PREFIX}{RWS_ROUTE_FINDINGS}/{finding_id}")
            self.assert_cache(cached_response)
            assert response.json() == cached_response.json()

    @patch("resc_backend.resc_web_service.crud.finding.get_finding")
    @patch("resc_backend.resc_web_service.crud.scan_finding.get_scan_findings")
    def test_get_finding(self, get_scan_findings, get_finding):
        finding = self.enriched_findings[0]
        get_finding.return_value = finding
        db_scan_findings = [self.db_scan_findings[0]]
        get_scan_findings.return_value = db_scan_findings
        with self.client as client:
            response = client.get(f"{RWS_VERSION_PREFIX}{RWS_ROUTE_FINDINGS}/{finding.id_}")
            assert response.status_code == 200, response.text
            self.assert_finding(response.json(), finding)
            get_finding.assert_called_once_with(ANY, finding_id=finding.id_)
            get_scan_findings.assert_called_once_with(ANY, finding_id=finding.id_)

            # Make the second request to retrieve response from cache
            cached_response = client.get(f"{RWS_VERSION_PREFIX}{RWS_ROUTE_FINDINGS}/{finding.id_}")
            self.assert_cache(cached_response)
            assert response.json() == cached_response.json()

    @patch("resc_backend.resc_web_service.crud.finding.get_finding")
    @patch("resc_backend.resc_web_service.crud.finding.delete_finding")
    @patch("resc_backend.resc_web_service.cache_manager.CacheManager.clear_cache_by_namespace")
    def test_delete_findings(self, clear_cache_by_namespace, delete_finding, get_finding):
        db_finding = self.db_findings[0]
        get_finding.return_value = db_finding
        clear_cache_by_namespace.return_value = None
        response = self.client.delete(f"{RWS_VERSION_PREFIX}{RWS_ROUTE_FINDINGS}/{db_finding.id_}")
        assert response.status_code == 200, response.text
        get_finding.assert_called_once_with(ANY, finding_id=db_finding.id_)
        delete_finding.assert_called_once_with(ANY, finding_id=db_finding.id_, delete_related=True)
        clear_cache_by_namespace.assert_has_calls([call(namespace=CACHE_NAMESPACE_FINDING)])

    @patch("resc_backend.resc_web_service.crud.finding.get_finding")
    @patch("resc_backend.resc_web_service.crud.finding.delete_finding")
    def test_delete_findings_non_existing(self, delete_finding, get_finding):
        finding_id = 999
        get_finding.return_value = None
        response = self.client.delete(f"{RWS_VERSION_PREFIX}{RWS_ROUTE_FINDINGS}/{finding_id}")
        assert response.status_code == 404, response.text
        data = response.json()
        assert data["detail"] == "Finding not found"
        get_finding.assert_called_once_with(ANY, finding_id=finding_id)
        delete_finding.assert_not_called()

    @patch("resc_backend.resc_web_service.crud.finding.create_findings")
    @patch("resc_backend.resc_web_service.cache_manager.CacheManager.clear_cache_by_namespace")
    def test_post_findings(self, clear_cache_by_namespace, create_finding):
        db_finding = self.db_findings[0]
        db_scan_findings = [self.db_scan_findings[0]]
        create_finding.return_value = [self.db_findings[0]]
        clear_cache_by_namespace.return_value = None
        response = self.client.post(
            f"{RWS_VERSION_PREFIX}{RWS_ROUTE_FINDINGS}",
            json=[self.create_json_body(db_finding, db_scan_findings)],
        )
        assert response.status_code == 201
        assert response.text == "1"

        create_finding.assert_called_once_with(
            db_connection=ANY,
            findings=[self.cast_db_finding_to_finding_create(db_finding, db_scan_findings)],
        )
        clear_cache_by_namespace.assert_has_calls([call(namespace=CACHE_NAMESPACE_FINDING)])

    @patch("resc_backend.resc_web_service.crud.finding.create_findings")
    def test_post_findings_no_body(self, create_finding):
        response = self.client.post(f"{RWS_VERSION_PREFIX}{RWS_ROUTE_FINDINGS}")
        assert response.status_code == 422, response.text
        data = response.json()
        assert data["detail"][0]["loc"] == ["body"]
        assert data["detail"][0]["msg"] == "Field required"
        create_finding.assert_not_called()

    @patch("resc_backend.resc_web_service.crud.finding.create_findings")
    def test_post_findings_empty_body(self, create_finding):
        response = self.client.post(
            f"{RWS_VERSION_PREFIX}{RWS_ROUTE_FINDINGS}",
            json={},
        )
        assert response.status_code == 422, response.text
        data = response.json()
        assert data["detail"][0]["loc"] == ["body"]
        assert data["detail"][0]["msg"] == "Input should be a valid list"
        create_finding.assert_not_called()

    @patch("resc_backend.resc_web_service.crud.finding.get_finding")
    @patch("resc_backend.resc_web_service.crud.scan_finding.get_scan_findings")
    @patch("resc_backend.resc_web_service.crud.finding.patch_finding")
    @patch("resc_backend.resc_web_service.cache_manager.CacheManager.clear_cache_by_namespace")
    def test_patch_findings(self, clear_cache_by_namespace, patch_finding, get_scan_findings, get_finding):
        finding_id = 1
        db_finding = self.db_findings[0]
        db_finding.event_sent_on = datetime.now(UTC)
        db_scan_findings = [self.db_scan_findings[0]]
        clear_cache_by_namespace.return_value = None
        get_scan_findings.return_value = db_scan_findings
        patch_finding.return_value = db_finding
        get_finding.return_value = db_finding
        get_finding.return_value.id_ = finding_id
        response = self.client.patch(
            f"{RWS_VERSION_PREFIX}{RWS_ROUTE_FINDINGS}/{finding_id}",
            json=self.create_json_body(db_finding, db_scan_findings),
        )
        assert response.status_code == 200, response.text
        self.assert_db_finding(response.json(), db_finding, db_scan_findings)
        patch_finding.assert_called_once_with(
            ANY,
            finding_id=db_finding.id_,
            finding_update=self.cast_db_finding_to_finding_patch(db_finding),
        )
        clear_cache_by_namespace.assert_has_calls([call(namespace=CACHE_NAMESPACE_FINDING)])

    @patch("resc_backend.resc_web_service.crud.finding.get_finding")
    @patch("resc_backend.resc_web_service.crud.finding.patch_finding")
    @patch("resc_backend.resc_web_service.cache_manager.CacheManager.clear_cache_by_namespace")
    def test_patch_event_sent_property_findings(self, clear_cache_by_namespace, patch_finding, get_finding):
        finding_id = 1
        db_finding = self.db_findings[1]
        get_finding.return_value = db_finding
        get_finding.return_value.id_ = finding_id
        expected_results = self.db_findings[1]
        expected_results.event_sent_on = "2022-07-21T11:15:06.160000"
        clear_cache_by_namespace.return_value = None
        patch_finding.return_value = db_finding
        update_body = {"event_sent_on": "2022-07-21T11:15:06.160000"}
        response = self.client.patch(
            f"{RWS_VERSION_PREFIX}{RWS_ROUTE_FINDINGS}/{finding_id}",
            content=json.dumps(update_body),
        )
        assert response.status_code == 200, response.text
        data = response.json()
        assert data["event_sent_on"] == expected_results.event_sent_on
        assert data["file_path"] == expected_results.file_path
        assert data["line_number"] == expected_results.line_number
        assert data["column_start"] == expected_results.column_start
        assert data["column_end"] == expected_results.column_end
        assert data["commit_id"] == expected_results.commit_id
        assert data["commit_message"] == expected_results.commit_message
        assert datetime.fromisoformat(data["commit_timestamp"]) == expected_results.commit_timestamp
        assert data["author"] == expected_results.author
        assert data["email"] == expected_results.email
        assert data["rule_name"] == expected_results.rule_name
        clear_cache_by_namespace.assert_has_calls([call(namespace=CACHE_NAMESPACE_FINDING)])

    @patch("resc_backend.resc_web_service.crud.finding.get_total_findings_count")
    @patch("resc_backend.resc_web_service.crud.finding.get_findings")
    def test_get_multiple_findings(self, get_findings, get_findings_count):
        number_of_findings = 3
        get_findings.return_value = self.enriched_findings[:number_of_findings]
        get_findings_count.return_value = len(self.enriched_findings[:number_of_findings])
        with self.client as client:
            response = client.get(
                f"{RWS_VERSION_PREFIX}{RWS_ROUTE_FINDINGS}",
                params={"skip": 0, "limit": 5},
            )
            assert response.status_code == 200, response.text
            data = response.json()
            assert len(data["data"]) == number_of_findings
            for i in range(number_of_findings - 1):
                self.assert_finding(data["data"][i], self.enriched_findings[i])
            assert data["total"] == number_of_findings
            assert data["limit"] == 5
            assert data["skip"] == 0

            # Make the second request to retrieve response from cache
            cached_response = client.get(
                f"{RWS_VERSION_PREFIX}{RWS_ROUTE_FINDINGS}",
                params={"skip": 0, "limit": 5},
            )
            self.assert_cache(cached_response)
            assert response.json() == cached_response.json()

    @patch("resc_backend.resc_web_service.crud.finding.get_findings")
    def test_get_multiple_findings_with_negative_skip(self, get_findings):
        with self.client as client:
            response = client.get(
                f"{RWS_VERSION_PREFIX}{RWS_ROUTE_FINDINGS}",
                params={"skip": -1, "limit": 5},
            )
            assert response.status_code == 422, response.text
            data = response.json()
            assert data["detail"][0]["loc"] == ["query", "skip"]
            assert data["detail"][0]["msg"] == "Input should be greater than or equal to 0"
            get_findings.assert_not_called()

            # Make the second request to retrieve response from cache
            cached_response = client.get(
                f"{RWS_VERSION_PREFIX}{RWS_ROUTE_FINDINGS}",
                params={"skip": -1, "limit": 5},
            )
            self.assert_cache(cached_response)
            assert response.json() == cached_response.json()

    @patch("resc_backend.resc_web_service.crud.finding.get_findings")
    def test_get_multiple_findings_with_negative_limit(self, get_findings):
        with self.client as client:
            response = client.get(
                f"{RWS_VERSION_PREFIX}{RWS_ROUTE_FINDINGS}",
                params={"skip": 0, "limit": -1},
            )
            assert response.status_code == 422, response.text
            data = response.json()
            assert data["detail"][0]["loc"] == ["query", "limit"]
            assert data["detail"][0]["msg"] == "Input should be greater than or equal to 1"
            get_findings.assert_not_called()

            # Make the second request to retrieve response from cache
            cached_response = client.get(
                f"{RWS_VERSION_PREFIX}{RWS_ROUTE_FINDINGS}",
                params={"skip": 0, "limit": -1},
            )
            self.assert_cache(cached_response)
            assert response.json() == cached_response.json()

    @patch("resc_backend.resc_web_service.crud.finding.get_total_findings_count")
    def test_get_total_findings_count_by_rule_invalid(self, get_total_findings_count):
        rule_name = "rule_name"
        count = 0
        get_total_findings_count.return_value = count
        with self.client as client:
            response = client.get(
                f"{RWS_VERSION_PREFIX}{RWS_ROUTE_FINDINGS}{RWS_ROUTE_TOTAL_COUNT_BY_RULE}/{rule_name}"
            )
            assert response.status_code == 200, response.text
            assert response.text == str(count)
            get_total_findings_count.assert_called_once_with(
                ANY, findings_filter=FindingsFilter(rule_names=[rule_name])
            )

            # Make the second request to retrieve response from cache
            cached_response = client.get(
                f"{RWS_VERSION_PREFIX}{RWS_ROUTE_FINDINGS}{RWS_ROUTE_TOTAL_COUNT_BY_RULE}/{rule_name}"
            )
            self.assert_cache(cached_response)
            assert response.json() == cached_response.json()

    @patch("resc_backend.resc_web_service.crud.finding.get_total_findings_count")
    def get_total_findings_count_by_rule(self, get_total_findings_count):
        rule_name = "rule_name"
        count = 5
        get_total_findings_count.return_value = count
        with self.client as client:
            response = client.get(
                f"{RWS_VERSION_PREFIX}{RWS_ROUTE_FINDINGS}{RWS_ROUTE_TOTAL_COUNT_BY_RULE}/{rule_name}"
            )
            assert response.status_code == 200, response.text
            assert response.text == str(count)
            get_total_findings_count.assert_called_once_with(db_connection=ANY, rule_name=rule_name)

            # Make the second request to retrieve response from cache
            cached_response = client.get(
                f"{RWS_VERSION_PREFIX}{RWS_ROUTE_FINDINGS}{RWS_ROUTE_TOTAL_COUNT_BY_RULE}/{rule_name}"
            )
            self.assert_cache(cached_response)
            assert response.json() == cached_response.json()

    @patch("resc_backend.resc_web_service.crud.finding.get_total_findings_count")
    @patch("resc_backend.resc_web_service.crud.finding.get_findings_by_rule")
    def test_get_multiple_findings_by_rule_none(self, get_findings_by_rule, get_findings_count):
        rule_name = "rule_name"
        get_findings_by_rule.return_value = []
        get_findings_count.return_value = 0
        with self.client as client:
            response = client.get(
                f"{RWS_VERSION_PREFIX}{RWS_ROUTE_FINDINGS}{RWS_ROUTE_BY_RULE}/{rule_name}",
                params={"skip": 0, "limit": 5},
            )
            assert response.status_code == 200, response.text
            data = response.json()
            assert data["data"] == get_findings_by_rule.return_value
            assert data["total"] == 0
            assert data["limit"] == 5
            assert data["skip"] == 0
            get_findings_by_rule.assert_called_once_with(
                ANY, skip=0, limit=5, rule_name=rule_name, include_deleted_repositories=False
            )

            # Make the second request to retrieve response from cache
            cached_response = client.get(
                f"{RWS_VERSION_PREFIX}{RWS_ROUTE_FINDINGS}{RWS_ROUTE_BY_RULE}/{rule_name}",
                params={"skip": 0, "limit": 5},
            )
            self.assert_cache(cached_response)
            assert response.json() == cached_response.json()

    @patch("resc_backend.resc_web_service.crud.finding.get_total_findings_count")
    @patch("resc_backend.resc_web_service.crud.finding.get_findings_by_rule")
    def test_get_multiple_findings_by_rule_multiple(self, get_findings_by_rule, get_findings_count):
        rule_name = "rule_name"
        get_findings_by_rule.return_value = self.enriched_findings[:2]
        get_findings_count.return_value = len(self.enriched_findings[:2])
        with self.client as client:
            response = client.get(
                f"{RWS_VERSION_PREFIX}{RWS_ROUTE_FINDINGS}{RWS_ROUTE_BY_RULE}/{rule_name}",
                params={"skip": 0, "limit": 5},
            )
            assert response.status_code == 200, response.text
            data = response.json()
            assert len(data["data"]) == 2
            self.assert_finding(data["data"][0], self.enriched_findings[0])
            self.assert_finding(data["data"][1], self.enriched_findings[1])
            assert data["total"] == 2
            assert data["limit"] == 5
            assert data["skip"] == 0
            get_findings_by_rule.assert_called_once_with(
                ANY, skip=0, limit=5, rule_name=rule_name, include_deleted_repositories=False
            )

            # Make the second request to retrieve response from cache
            cached_response = client.get(
                f"{RWS_VERSION_PREFIX}{RWS_ROUTE_FINDINGS}{RWS_ROUTE_BY_RULE}/{rule_name}",
                params={"skip": 0, "limit": 5},
            )
            self.assert_cache(cached_response)
            assert response.json() == cached_response.json()

    @patch("resc_backend.resc_web_service.crud.finding.get_total_findings_count")
    @patch("resc_backend.resc_web_service.crud.finding.get_findings_by_rule")
    def test_get_multiple_findings_by_rule_single(self, get_findings_by_rule, get_findings_count):
        rule_name = "rule_name"
        get_findings_by_rule.return_value = self.enriched_findings[:1]
        get_findings_count.return_value = len(self.enriched_findings[:1])
        with self.client as client:
            response = client.get(
                f"{RWS_VERSION_PREFIX}{RWS_ROUTE_FINDINGS}{RWS_ROUTE_BY_RULE}/{rule_name}",
                params={"skip": 0, "limit": 5},
            )
            assert response.status_code == 200, response.text
            data = response.json()
            assert len(data["data"]) == 1
            self.assert_finding(data["data"][0], self.enriched_findings[0])
            assert data["total"] == 1
            assert data["limit"] == 5
            assert data["skip"] == 0
            get_findings_by_rule.assert_called_once_with(
                ANY, skip=0, limit=5, rule_name=rule_name, include_deleted_repositories=False
            )

            # Make the second request to retrieve response from cache
            cached_response = client.get(
                f"{RWS_VERSION_PREFIX}{RWS_ROUTE_FINDINGS}{RWS_ROUTE_BY_RULE}/{rule_name}",
                params={"skip": 0, "limit": 5},
            )
            self.assert_cache(cached_response)
            assert response.json() == cached_response.json()

    @patch("resc_backend.resc_web_service.crud.finding.get_findings_by_rule")
    def test_get_multiple_findings_by_rule_with_negative_skip(self, get_findings_by_rule):
        rule_name = "rule_name"
        with self.client as client:
            response = client.get(
                f"{RWS_VERSION_PREFIX}{RWS_ROUTE_FINDINGS}{RWS_ROUTE_BY_RULE}/{rule_name}",
                params={"skip": -1, "limit": 5},
            )
            assert response.status_code == 422, response.text
            data = response.json()
            assert data["detail"][0]["loc"] == ["query", "skip"]
            assert data["detail"][0]["msg"] == "Input should be greater than or equal to 0"
            get_findings_by_rule.assert_not_called()

            # Make the second request to retrieve response from cache
            cached_response = client.get(
                f"{RWS_VERSION_PREFIX}{RWS_ROUTE_FINDINGS}{RWS_ROUTE_BY_RULE}/{rule_name}",
                params={"skip": -1, "limit": 5},
            )
            self.assert_cache(cached_response)
            assert response.json() == cached_response.json()

    @patch("resc_backend.resc_web_service.crud.finding.get_findings_by_rule")
    def test_get_multiple_findings_by_rule_with_negative_limit(self, get_findings_by_rule):
        rule_name = "rule_name"
        with self.client as client:
            response = client.get(
                f"{RWS_VERSION_PREFIX}{RWS_ROUTE_FINDINGS}{RWS_ROUTE_BY_RULE}/{rule_name}",
                params={"skip": 0, "limit": -1},
            )
            assert response.status_code == 422, response.text
            data = response.json()
            assert data["detail"][0]["loc"] == ["query", "limit"]
            assert data["detail"][0]["msg"] == "Input should be greater than or equal to 1"
            get_findings_by_rule.assert_not_called()

            # Make the second request to retrieve response from cache
            cached_response = client.get(
                f"{RWS_VERSION_PREFIX}{RWS_ROUTE_FINDINGS}{RWS_ROUTE_BY_RULE}/{rule_name}",
                params={"skip": 0, "limit": -1},
            )
            self.assert_cache(cached_response)
            assert response.json() == cached_response.json()

    @patch("resc_backend.resc_web_service.crud.finding.count_findings")
    @patch("resc_backend.resc_web_service.crud.audit.create_audits")
    @patch("resc_backend.resc_web_service.cache_manager.CacheManager.clear_cache_by_namespace")
    def test_audit_findings(self, clear_cache_by_namespace, create_audits, count_findings):
        audit_multiple = AuditMultiple(
            finding_ids=[1, 2],
            status=FindingStatus.FALSE_POSITIVE.value,
            comment="Hello World!",
        )
        count_findings.return_value = 2
        create_audits.return_value = [1, 2]
        clear_cache_by_namespace.return_value = None
        response = self.client.post(
            f"{RWS_VERSION_PREFIX}{RWS_ROUTE_FINDINGS}{RWS_ROUTE_AUDIT}/",
            json=self.create_json_body_multiple_audit(audit_multiple),
        )
        assert response.status_code == 201, response.text
        count_findings.assert_called_once_with(ANY, finding_ids={1, 2})
        create_audits.assert_called_once_with(
            db_connection=ANY,
            finding_ids={1, 2},
            auditor="Anonymous",
            status=audit_multiple.status,
            comment=audit_multiple.comment,
        )
        clear_cache_by_namespace.assert_called_once_with(namespace=CACHE_NAMESPACE_FINDING)

    @patch("resc_backend.resc_web_service.crud.finding.count_findings")
    @patch("resc_backend.resc_web_service.crud.audit.create_audits")
    def test_audit_findings_non_existing(self, create_audits, count_findings):
        audit_multiple = AuditMultiple(
            finding_ids=[1, 2],
            status=FindingStatus.FALSE_POSITIVE.value,
            comment="Hello World!",
        )
        count_findings.return_value = 0
        response = self.client.post(
            f"{RWS_VERSION_PREFIX}{RWS_ROUTE_FINDINGS}{RWS_ROUTE_AUDIT}/",
            json=self.create_json_body_multiple_audit(audit_multiple),
        )
        assert response.status_code == 404, response.text
        count_findings.assert_called_once_with(ANY, finding_ids={1, 2})
        create_audits.assert_not_called()

    def test_get_supported_statuses(self):
        with self.client as client:
            response = client.get(f"{RWS_VERSION_PREFIX}{RWS_ROUTE_FINDINGS}{RWS_ROUTE_SUPPORTED_STATUSES}/")
            assert response.status_code == 200, response.text
            data = response.json()
            assert data[0] == "NOT_ANALYZED"
            assert data[1] == "NOT_ACCESSIBLE"
            assert data[2] == "CLARIFICATION_REQUIRED"
            assert data[3] == "FALSE_POSITIVE"
            assert data[4] == "TRUE_POSITIVE"
            assert data[5] == "OUTDATED"
            assert len(data) == 6

            # Make the second request to retrieve response from cache
            cached_response = client.get(f"{RWS_VERSION_PREFIX}{RWS_ROUTE_FINDINGS}{RWS_ROUTE_SUPPORTED_STATUSES}/")
            self.assert_cache(cached_response)
            assert response.json() == cached_response.json()

    @patch("resc_backend.resc_web_service.crud.finding.get_findings_count_by_time")
    @patch("resc_backend.resc_web_service.crud.finding.get_findings_count_by_time_total")
    def test_get_count_by_time_month(self, get_findings_count_by_time_total, get_findings_count_by_time):
        get_findings_count_by_time_total.return_value = 2
        get_findings_count_by_time.return_value = [(2021, 10, 100), (2022, 12, 200)]
        response = self.client.get(
            f"{RWS_VERSION_PREFIX}{RWS_ROUTE_FINDINGS}{RWS_ROUTE_COUNT_BY_TIME}/{DateFilter.MONTH.value}"
        )
        assert response.status_code == 200, response.text
        data = response.json()
        assert len(data["data"]) == 2
        assert data["data"][0]["date_lable"] == "2021-10"
        assert data["data"][0]["finding_count"] == 100
        assert data["data"][1]["date_lable"] == "2022-12"
        assert data["data"][1]["finding_count"] == 200
        assert data["total"] == 2
        assert data["limit"] == 100
        assert data["skip"] == 0

    @patch("resc_backend.resc_web_service.crud.finding.get_findings_count_by_time")
    @patch("resc_backend.resc_web_service.crud.finding.get_findings_count_by_time_total")
    def test_get_count_by_time_week(self, get_findings_count_by_time_total, get_findings_count_by_time):
        get_findings_count_by_time_total.return_value = 2
        get_findings_count_by_time.return_value = [(2021, 40, 100), (2022, 42, 200)]
        response = self.client.get(
            f"{RWS_VERSION_PREFIX}{RWS_ROUTE_FINDINGS}{RWS_ROUTE_COUNT_BY_TIME}/{DateFilter.WEEK.value}"
        )
        assert response.status_code == 200, response.text
        data = response.json()
        assert len(data["data"]) == 2
        assert data["data"][0]["date_lable"] == "2021-W40"
        assert data["data"][0]["finding_count"] == 100
        assert data["data"][1]["date_lable"] == "2022-W42"
        assert data["data"][1]["finding_count"] == 200
        assert data["total"] == 2
        assert data["limit"] == 100
        assert data["skip"] == 0

    @patch("resc_backend.resc_web_service.crud.finding.get_findings_count_by_time")
    @patch("resc_backend.resc_web_service.crud.finding.get_findings_count_by_time_total")
    def test_get_count_by_time_day(self, get_findings_count_by_time_total, get_findings_count_by_time):
        get_findings_count_by_time_total.return_value = 2
        get_findings_count_by_time.return_value = [
            (2021, 10, 1, 100),
            (2022, 12, 2, 200),
        ]
        response = self.client.get(
            f"{RWS_VERSION_PREFIX}{RWS_ROUTE_FINDINGS}{RWS_ROUTE_COUNT_BY_TIME}/{DateFilter.DAY.value}"
        )
        assert response.status_code == 200, response.text
        data = response.json()
        assert len(data["data"]) == 2
        assert data["data"][0]["date_lable"] == "2021-10-1"
        assert data["data"][0]["finding_count"] == 100
        assert data["data"][1]["date_lable"] == "2022-12-2"
        assert data["data"][1]["finding_count"] == 200
        assert data["total"] == 2
        assert data["limit"] == 100
        assert data["skip"] == 0

    @patch("resc_backend.resc_web_service.crud.audit.get_finding_audits_count")
    @patch("resc_backend.resc_web_service.crud.audit.get_finding_audits")
    def test_get_finding_audits(self, get_finding_audits, get_finding_audits_count):
        get_finding_audits.return_value = self.db_audits[:1]
        get_finding_audits_count.return_value = len(self.db_audits[:1])
        with self.client as client:
            response = client.get(
                f"{RWS_VERSION_PREFIX}{RWS_ROUTE_FINDINGS}/1{RWS_ROUTE_AUDIT}",
                params={"skip": 0, "limit": 5},
            )
            assert response.status_code == 200, response.text
            data = response.json()
            assert len(data["data"]) == 1
            assert data["data"][0]["id_"] == self.db_audits[0].id_
            assert data["data"][0]["comment"] == self.db_audits[0].comment
            assert data["data"][0]["auditor"] == self.db_audits[0].auditor
            assert datetime.fromisoformat(data["data"][0]["timestamp"]) == self.db_audits[0].timestamp
            assert data["total"] == 1
            assert data["limit"] == 5
            assert data["skip"] == 0
            get_finding_audits.assert_called_once_with(ANY, skip=0, limit=5, finding_id=1)

            # Make the second request to retrieve response from cache
            cached_response = client.get(
                f"{RWS_VERSION_PREFIX}{RWS_ROUTE_FINDINGS}/1{RWS_ROUTE_AUDIT}",
                params={"skip": 0, "limit": 5},
            )
            self.assert_cache(cached_response)
            assert response.json() == cached_response.json()

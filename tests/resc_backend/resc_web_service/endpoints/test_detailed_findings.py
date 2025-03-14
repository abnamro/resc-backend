# Standard Library
import unittest
from collections.abc import Generator
from datetime import UTC, datetime
from unittest.mock import ANY, patch
from urllib.parse import quote, urlencode

# Third Party
import pytest
from fastapi.testclient import TestClient
from fastapi_cache import FastAPICache
from fastapi_cache.backends.inmemory import InMemoryBackend

# First Party
from resc_backend.constants import (
    CACHE_PREFIX,
    REDIS_CACHE_EXPIRE,
    RWS_ROUTE_DETAILED_FINDINGS,
    RWS_VERSION_PREFIX,
)
from resc_backend.resc_web_service.api import app
from resc_backend.resc_web_service.cache_manager import CacheManager
from resc_backend.resc_web_service.dependencies import requires_auth, requires_no_auth
from resc_backend.resc_web_service.filters import FindingsFilter
from resc_backend.resc_web_service.schema.detailed_finding import DetailedFindingRead
from resc_backend.resc_web_service.schema.finding_status import FindingStatus
from resc_backend.resc_web_service.schema.vcs_provider import VCSProviders


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


class TestDetailedFindings(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)
        app.dependency_overrides[requires_auth] = requires_no_auth
        self.detailed_findings = []
        for i in range(1, 6):
            self.detailed_findings.append(
                DetailedFindingRead(
                    id_=i,
                    file_path=f"file_path_{i}",
                    line_number=i,
                    column_start=i,
                    column_end=i,
                    commit_id=f"commit_id_{i}",
                    commit_message=f"commit_message_{i}",
                    commit_timestamp=datetime.now(UTC),
                    author=f"author_{i}",
                    email=f"email_{i}",
                    rule_name=f"rule_name_{i}",
                    rule_pack=f"{i}",
                    project_key=f"_{i}",
                    repository_name=f"_{i}",
                    repository_url=f"http://fake.repo.com/_{i}",
                    timestamp=datetime(year=1970, month=1, day=i),
                    vcs_provider="AZURE_DEVOPS",
                    last_scanned_commit=f"_{i}",
                    commit_url=f"_{i}",
                    event_sent_on=datetime(year=1970, month=1, day=i),
                    scan_id=i,
                    is_dir_scan=False,
                )
            )

    @staticmethod
    def assert_detailed_finding(data, detailed_finding: DetailedFindingRead):
        assert data["file_path"] == detailed_finding.file_path
        assert data["line_number"] == detailed_finding.line_number
        assert data["column_start"] == detailed_finding.column_start
        assert data["column_end"] == detailed_finding.column_end
        assert data["commit_id"] == detailed_finding.commit_id
        assert data["commit_message"] == detailed_finding.commit_message
        assert datetime.fromisoformat(data["commit_timestamp"]) == detailed_finding.commit_timestamp
        assert data["author"] == detailed_finding.author
        assert data["email"] == detailed_finding.email
        assert data["rule_name"] == detailed_finding.rule_name
        assert data["rule_pack"] == detailed_finding.rule_pack
        assert data["scan_id"] == detailed_finding.scan_id
        assert data["id_"] == detailed_finding.id_
        assert data["project_key"] == detailed_finding.project_key
        assert data["repository_name"] == detailed_finding.repository_name
        assert data["repository_url"] == str(detailed_finding.repository_url)
        assert datetime.fromisoformat(data["timestamp"]) == detailed_finding.timestamp
        assert data["vcs_provider"] == detailed_finding.vcs_provider
        assert data["last_scanned_commit"] == detailed_finding.last_scanned_commit
        assert data["commit_url"] == detailed_finding.commit_url
        assert data["is_dir_scan"] is False
        assert datetime.fromisoformat(data["event_sent_on"]) == detailed_finding.event_sent_on

    @staticmethod
    def assert_cache(cached_response):
        assert FastAPICache.get_enable() is True
        assert FastAPICache.get_prefix() == CACHE_PREFIX
        assert FastAPICache.get_expire() == REDIS_CACHE_EXPIRE
        assert FastAPICache.get_key_builder() is not None
        assert FastAPICache.get_coder() is not None
        assert cached_response.headers.get("cache-control") is not None

    @patch("resc_backend.resc_web_service.crud.detailed_finding.get_detailed_finding")
    def test_get_detailed_finding_non_existing(self, get_finding):
        finding_id = 999
        get_finding.return_value = None
        response = self.client.get(f"{RWS_VERSION_PREFIX}{RWS_ROUTE_DETAILED_FINDINGS}/{finding_id}")
        assert response.status_code == 404, response.text
        get_finding.assert_called_once_with(ANY, finding_id=finding_id)

    @patch("resc_backend.resc_web_service.crud.detailed_finding.get_detailed_finding")
    def test_get_finding(self, get_finding):
        detailed_finding = self.detailed_findings[0]
        get_finding.return_value = detailed_finding
        response = self.client.get(f"{RWS_VERSION_PREFIX}{RWS_ROUTE_DETAILED_FINDINGS}/{detailed_finding.id_}")
        assert response.status_code == 200, response.text
        self.assert_detailed_finding(response.json(), detailed_finding)
        get_finding.assert_called_once_with(ANY, finding_id=detailed_finding.id_)

    @patch("resc_backend.resc_web_service.crud.detailed_finding.get_detailed_findings_count")
    @patch("resc_backend.resc_web_service.crud.detailed_finding.get_detailed_findings")
    def test_get_multiple_findings(self, get_findings, get_findings_count):
        number_of_findings = 3
        get_findings.return_value = self.detailed_findings[:number_of_findings]
        get_findings_count.return_value = len(self.detailed_findings[:number_of_findings])
        with self.client as client:
            response = client.get(
                f"{RWS_VERSION_PREFIX}{RWS_ROUTE_DETAILED_FINDINGS}",
                params={"skip": 0, "limit": 5},
            )
            assert response.status_code == 200, response.text
            data = response.json()
            assert len(data["data"]) == number_of_findings
            for i in range(number_of_findings - 1):
                self.assert_detailed_finding(data["data"][i], self.detailed_findings[i])
            assert data["total"] == number_of_findings
            assert data["limit"] == 5
            assert data["skip"] == 0

            # Make the second request to retrieve response from cache
            cached_response = client.get(
                f"{RWS_VERSION_PREFIX}{RWS_ROUTE_DETAILED_FINDINGS}",
                params={"skip": 0, "limit": 5},
            )
            self.assert_cache(cached_response)
            assert response.json() == cached_response.json()

    @patch("resc_backend.resc_web_service.crud.detailed_finding.get_detailed_findings")
    def test_get_multiple_findings_with_negative_skip(self, get_findings):
        with self.client as client:
            response = client.get(
                f"{RWS_VERSION_PREFIX}{RWS_ROUTE_DETAILED_FINDINGS}",
                params={"skip": -1, "limit": 5},
            )
            assert response.status_code == 422, response.text
            data = response.json()
            assert data["detail"][0]["loc"] == ["query", "skip"]
            assert data["detail"][0]["msg"] == "Input should be greater than or equal to 0"
            get_findings.assert_not_called()

            # Make the second request to retrieve response from cache
            cached_response = client.get(
                f"{RWS_VERSION_PREFIX}{RWS_ROUTE_DETAILED_FINDINGS}",
                params={"skip": -1, "limit": 5},
            )
            self.assert_cache(cached_response)
            assert response.json() == cached_response.json()

    @patch("resc_backend.resc_web_service.crud.detailed_finding.get_detailed_findings")
    def test_get_multiple_findings_with_negative_limit(self, get_findings):
        with self.client as client:
            response = client.get(
                f"{RWS_VERSION_PREFIX}{RWS_ROUTE_DETAILED_FINDINGS}",
                params={"skip": 0, "limit": -1},
            )
            assert response.status_code == 422, response.text
            data = response.json()
            assert data["detail"][0]["loc"] == ["query", "limit"]
            assert data["detail"][0]["msg"] == "Input should be greater than or equal to 1"
            get_findings.assert_not_called()

            # Make the second request to retrieve response from cache
            cached_response = client.get(
                f"{RWS_VERSION_PREFIX}{RWS_ROUTE_DETAILED_FINDINGS}",
                params={"skip": 0, "limit": -1},
            )
            self.assert_cache(cached_response)
            assert response.json() == cached_response.json()

    @patch("resc_backend.resc_web_service.crud.detailed_finding.get_detailed_findings_count")
    @patch("resc_backend.resc_web_service.crud.detailed_finding.get_detailed_findings")
    def test_get_detailed_findings_by_rule(self, get_detailed_findings, get_total_findings_count):
        rule_name = "['rule_name']"
        count = 0
        get_total_findings_count.return_value = count
        get_detailed_findings.return_value = []
        with self.client as client:
            response = client.get(
                f"{RWS_VERSION_PREFIX}{RWS_ROUTE_DETAILED_FINDINGS}?skip=0&limit=1&query_string=rule_names={rule_name}"
            )
            assert response.status_code == 200, response.text
            data = response.json()
            assert len(data["data"]) == 0
            assert data["total"] == 0
            get_total_findings_count.assert_called_once_with(
                ANY, findings_filter=FindingsFilter(rule_names=["rule_name"])
            )
            get_detailed_findings.assert_called_once_with(
                ANY,
                findings_filter=FindingsFilter(rule_names=["rule_name"]),
                skip=0,
                limit=1,
            )

            # Make the second request to retrieve response from cache
            cached_response = client.get(
                f"{RWS_VERSION_PREFIX}{RWS_ROUTE_DETAILED_FINDINGS}?skip=0&limit=1&query_string=rule_names={rule_name}"
            )
            self.assert_cache(cached_response)
            assert response.json() == cached_response.json()

    @patch("resc_backend.resc_web_service.crud.detailed_finding.get_detailed_findings_count")
    @patch("resc_backend.resc_web_service.crud.detailed_finding.get_detailed_findings")
    def test_get_detailed_findings_by_rule_pack_versions(self, get_detailed_findings, get_total_findings_count):
        rule_pack_versions = "['2']"
        count = 0
        get_total_findings_count.return_value = count
        get_detailed_findings.return_value = []
        with self.client as client:
            response = client.get(
                f"{RWS_VERSION_PREFIX}{RWS_ROUTE_DETAILED_FINDINGS}"
                f"?skip=0&limit=1&query_string=rule_pack_versions={rule_pack_versions}"
            )
            assert response.status_code == 200, response.text
            data = response.json()
            assert len(data["data"]) == 0
            assert data["total"] == 0
            get_total_findings_count.assert_called_once_with(
                ANY, findings_filter=FindingsFilter(rule_pack_versions=["2"])
            )
            get_detailed_findings.assert_called_once_with(
                ANY,
                findings_filter=FindingsFilter(rule_pack_versions=["2"]),
                skip=0,
                limit=1,
            )

            # Make the second request to retrieve response from cache
            cached_response = client.get(
                f"{RWS_VERSION_PREFIX}{RWS_ROUTE_DETAILED_FINDINGS}"
                f"?skip=0&limit=1&query_string=rule_pack_versions={rule_pack_versions}"
            )
            self.assert_cache(cached_response)
            assert response.json() == cached_response.json()

    @patch("resc_backend.resc_web_service.crud.detailed_finding.get_detailed_findings_count")
    @patch("resc_backend.resc_web_service.crud.detailed_finding.get_detailed_findings")
    def test_get_detailed_findings_by_vcs_provider(self, get_detailed_findings, get_total_findings_count):
        vcs_provider = "['BITBUCKET']"
        count = 0
        get_total_findings_count.return_value = count
        get_detailed_findings.return_value = []
        with self.client as client:
            response = client.get(
                f"{RWS_VERSION_PREFIX}{RWS_ROUTE_DETAILED_FINDINGS}"
                f"?skip=0&limit=1&query_string=vcs_providers={vcs_provider}"
            )
            assert response.status_code == 200, response.text
            data = response.json()
            assert len(data["data"]) == 0
            assert data["total"] == 0
            get_total_findings_count.assert_called_once_with(
                ANY,
                findings_filter=FindingsFilter(vcs_providers=[VCSProviders.BITBUCKET]),
            )
            get_detailed_findings.assert_called_once_with(
                ANY,
                findings_filter=FindingsFilter(vcs_providers=[VCSProviders.BITBUCKET]),
                skip=0,
                limit=1,
            )

            # Make the second request to retrieve response from cache
            cached_response = client.get(
                f"{RWS_VERSION_PREFIX}{RWS_ROUTE_DETAILED_FINDINGS}"
                f"?skip=0&limit=1&query_string=vcs_providers={vcs_provider}"
            )
            self.assert_cache(cached_response)
            assert response.json() == cached_response.json()

    @patch("resc_backend.resc_web_service.crud.detailed_finding.get_detailed_findings_count")
    @patch("resc_backend.resc_web_service.crud.detailed_finding.get_detailed_findings")
    def test_get_detailed_findings_by_start_date_range(self, get_detailed_findings, get_total_findings_count):
        start_date_time = "1970-11-11T00:00:00"
        count = 0
        get_total_findings_count.return_value = count
        get_detailed_findings.return_value = []
        with self.client as client:
            response = client.get(
                f"{RWS_VERSION_PREFIX}{RWS_ROUTE_DETAILED_FINDINGS}"
                f"?skip=0&limit=1&query_string=start_date_time={start_date_time}"
            )
            assert response.status_code == 200, response.text
            data = response.json()
            assert len(data["data"]) == 0
            assert data["total"] == 0
            get_total_findings_count.assert_called_once_with(
                ANY,
                findings_filter=FindingsFilter(start_date_time=datetime.strptime(start_date_time, "%Y-%m-%dT%H:%M:%S")),
            )
            get_detailed_findings.assert_called_once_with(
                ANY,
                findings_filter=FindingsFilter(start_date_time=datetime.strptime(start_date_time, "%Y-%m-%dT%H:%M:%S")),
                skip=0,
                limit=1,
            )

            # Make the second request to retrieve response from cache
            cached_response = client.get(
                f"{RWS_VERSION_PREFIX}{RWS_ROUTE_DETAILED_FINDINGS}"
                f"?skip=0&limit=1&query_string=start_date_time={start_date_time}"
            )
            self.assert_cache(cached_response)
            assert response.json() == cached_response.json()

    @patch("resc_backend.resc_web_service.crud.detailed_finding.get_detailed_findings_count")
    @patch("resc_backend.resc_web_service.crud.detailed_finding.get_detailed_findings")
    def test_get_detailed_findings_by_end_date_range(self, get_detailed_findings, get_total_findings_count):
        end_date_time = "1970-11-11T00:00:00"
        count = 0
        get_total_findings_count.return_value = count
        get_detailed_findings.return_value = []
        with self.client as client:
            response = client.get(
                f"{RWS_VERSION_PREFIX}{RWS_ROUTE_DETAILED_FINDINGS}"
                f"?skip=0&limit=1&query_string=end_date_time={end_date_time}"
            )
            assert response.status_code == 200, response.text
            data = response.json()
            assert len(data["data"]) == 0
            assert data["total"] == 0
            get_total_findings_count.assert_called_once_with(
                ANY,
                findings_filter=FindingsFilter(end_date_time=datetime.strptime(end_date_time, "%Y-%m-%dT%H:%M:%S")),
            )
            get_detailed_findings.assert_called_once_with(
                ANY,
                findings_filter=FindingsFilter(end_date_time=datetime.strptime(end_date_time, "%Y-%m-%dT%H:%M:%S")),
                skip=0,
                limit=1,
            )

            # Make the second request to retrieve response from cache
            cached_response = client.get(
                f"{RWS_VERSION_PREFIX}{RWS_ROUTE_DETAILED_FINDINGS}"
                f"?skip=0&limit=1&query_string=end_date_time={end_date_time}"
            )
            self.assert_cache(cached_response)
            assert response.json() == cached_response.json()

    @patch("resc_backend.resc_web_service.crud.detailed_finding.get_detailed_findings_count")
    @patch("resc_backend.resc_web_service.crud.detailed_finding.get_detailed_findings")
    def test_get_detailed_findings_by_all_filters(self, get_detailed_findings, get_total_findings_count):
        scan_ids: list[int] = [1, 2]
        vcs_providers: list[str] = [
            VCSProviders.AZURE_DEVOPS.value,
            VCSProviders.BITBUCKET.value,
        ]
        finding_statuses: list[str] = [FindingStatus.NOT_ANALYZED.value]
        rule_names: list[str] = ["rule1", "rule2"]
        rule_pack_versions: list[str] = ["2"]
        all_params = {
            "vcs_providers": vcs_providers,
            "finding_statuses": finding_statuses,
            "start_date_time": "1970-11-11T00:00:00",
            "end_date_time": "1970-11-11T00:00:01",
            "project_name": "project_name",
            "scan_ids": scan_ids,
            "repository_name": "repository_name",
            "rule_names": rule_names,
            "rule_pack_versions": rule_pack_versions,
        }

        all_params_url_encoded = quote(urlencode(all_params))

        count = 0
        get_total_findings_count.return_value = count
        get_detailed_findings.return_value = []
        with self.client as client:
            response = client.get(
                f"{RWS_VERSION_PREFIX}{RWS_ROUTE_DETAILED_FINDINGS}"
                f"?skip=0&limit=1&query_string={all_params_url_encoded}"
            )
            assert response.status_code == 200, response.text
            data = response.json()
            assert len(data["data"]) == 0
            assert data["total"] == 0
            get_total_findings_count.assert_called_once_with(ANY, findings_filter=FindingsFilter(**all_params))
            get_detailed_findings.assert_called_once_with(
                ANY, findings_filter=FindingsFilter(**all_params), skip=0, limit=1
            )

            # Make the second request to retrieve response from cache
            cached_response = client.get(
                f"{RWS_VERSION_PREFIX}{RWS_ROUTE_DETAILED_FINDINGS}"
                f"?skip=0&limit=1&query_string={all_params_url_encoded}"
            )
            self.assert_cache(cached_response)
            assert response.json() == cached_response.json()

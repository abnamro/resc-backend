# Standard Library
import unittest
from collections.abc import Generator
from datetime import UTC, datetime
from unittest.mock import ANY, patch

# Third Party
import pytest
from fastapi.testclient import TestClient
from fastapi_cache import FastAPICache
from fastapi_cache.backends.inmemory import InMemoryBackend

# First Party
from resc_backend.constants import (
    CACHE_PREFIX,
    REDIS_CACHE_EXPIRE,
    RWS_ROUTE_AUDITS,
    RWS_VERSION_PREFIX,
)
from resc_backend.resc_web_service.api import app
from resc_backend.resc_web_service.cache_manager import CacheManager
from resc_backend.resc_web_service.dependencies import requires_auth, requires_no_auth
from resc_backend.resc_web_service.schema.audit import AuditFinding
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


class TestDetailedFindings(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)
        app.dependency_overrides[requires_auth] = requires_no_auth
        self.audits = []
        for i in range(1, 6):
            self.audits.append(
                AuditFinding(
                    audit_id=i,
                    status=FindingStatus.FALSE_POSITIVE,
                    auditor="admin@example.com",
                    comment="False positive",
                    timestamp=datetime.now(UTC),
                    is_latest=False,
                    finding_id=i,
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
                    project_key=f"_{i}",
                    repository_name=f"_{i}",
                    repository_url=f"http://fake.repo.com/_{i}",
                    vcs_provider="AZURE_DEVOPS",
                    last_scanned_commit=f"_{i}",
                    commit_url=f"_{i}",
                    is_dir_scan=False,
                )
            )

    @staticmethod
    def assert_audit_finding(data, audit_finding: AuditFinding):
        assert data["file_path"] == audit_finding.file_path
        assert data["line_number"] == audit_finding.line_number
        assert data["column_start"] == audit_finding.column_start
        assert data["column_end"] == audit_finding.column_end
        assert data["commit_id"] == audit_finding.commit_id
        assert data["commit_message"] == audit_finding.commit_message
        assert datetime.fromisoformat(data["commit_timestamp"]) == audit_finding.commit_timestamp
        assert data["author"] == audit_finding.author
        assert data["email"] == audit_finding.email
        assert data["rule_name"] == audit_finding.rule_name
        assert data["rule_pack"] == audit_finding.rule_pack
        assert data["scan_id"] == audit_finding.scan_id
        assert data["id_"] == audit_finding.id_
        assert data["project_key"] == audit_finding.project_key
        assert data["repository_name"] == audit_finding.repository_name
        assert data["repository_url"] == str(audit_finding.repository_url)
        assert datetime.fromisoformat(data["timestamp"]) == audit_finding.timestamp
        assert data["vcs_provider"] == audit_finding.vcs_provider
        assert data["last_scanned_commit"] == audit_finding.last_scanned_commit
        assert data["commit_url"] == audit_finding.commit_url
        assert data["is_dir_scan"] is False
        assert datetime.fromisoformat(data["event_sent_on"]) == audit_finding.event_sent_on

    @patch("resc_backend.resc_web_service.crud.audit.get_audits")
    @patch("resc_backend.resc_web_service.crud.audit.get_total_audits_count")
    def test_get_audits(self, get_total_audits_count, get_audits):
        get_audits.return_value = []
        get_total_audits_count.return_value = 0
        response = self.client.get(f"{RWS_VERSION_PREFIX}{RWS_ROUTE_AUDITS}")
        assert response.status_code == 200, response.text
        get_audits.assert_called_once()
        get_total_audits_count.assert_called_once()

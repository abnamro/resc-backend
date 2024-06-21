# Standard Library
import html
from datetime import UTC, datetime

# Third Party
from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    String,
    text,
)

# First Party
from resc_backend.constants import AUDIT_AUTOMATED_AUDITOR, AUDIT_AUTOMATED_COMMENT
from resc_backend.db.model import Base
from resc_backend.resc_web_service.schema.finding_status import FindingStatus


class DBaudit(Base):
    __tablename__ = "audit"
    id_ = Column("id", Integer, primary_key=True)
    finding_id = Column(Integer, ForeignKey("finding.id"), nullable=False)
    status = Column(
        Enum(FindingStatus),
        default=FindingStatus.NOT_ANALYZED.value,
        server_default=text("NOT_ANALYZED"),
        nullable=False,
    )
    auditor = Column(String(200))
    comment = Column(String(255), nullable=True)
    timestamp = Column(DateTime, nullable=False, default=datetime.now(UTC))
    is_latest = Column(Boolean, nullable=False, default=False, server_default=text("0"))

    def __init__(
        self, finding_id: int, status: str, auditor: str, comment: str | None, timestamp: datetime, is_latest: bool
    ):
        sanitized_comment = html.escape(comment) if comment else comment
        self.finding_id = finding_id
        self.status = status
        self.auditor = auditor
        self.comment = sanitized_comment
        self.timestamp = timestamp
        self.is_latest = is_latest

    @staticmethod
    def create_automated(
        finding_id: int,
        status: str,
    ):
        db_audit = DBaudit(
            finding_id=finding_id,
            status=status,
            comment=AUDIT_AUTOMATED_COMMENT,
            auditor=AUDIT_AUTOMATED_AUDITOR,
            timestamp=datetime.now(UTC),
            is_latest=True,
        )
        return db_audit

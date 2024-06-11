# Standard Library
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
from resc_backend.constants import BASE_SCAN
from resc_backend.db.model import Base
from resc_backend.db.model.rule_pack import DBrulePack
from resc_backend.resc_web_service.schema.scan_type import ScanType

REPOSITORY_ID = "repository.id"


class DBscan(Base):
    __tablename__ = "scan"
    id_ = Column("id", Integer, primary_key=True)
    repository_id = Column(Integer, ForeignKey(REPOSITORY_ID))
    rule_pack = Column(String(100), ForeignKey(DBrulePack.version), nullable=False)
    scan_type = Column(Enum(ScanType), default=ScanType.BASE, server_default=BASE_SCAN, nullable=False)
    last_scanned_commit = Column(String(100), nullable=False)
    timestamp = Column(DateTime, nullable=False, default=datetime.now(UTC))
    increment_number = Column(Integer, server_default=text("0"), default=0, nullable=False)
    is_latest = Column(Boolean, nullable=False, default=False, server_default=text("0"))

    def __init__(
        self,
        repository_id: int,
        scan_type: ScanType,
        last_scanned_commit: str,
        timestamp: datetime,
        increment_number: int,
        rule_pack: str,
        is_latest: bool,
    ):
        self.repository_id = repository_id
        self.scan_type = scan_type
        self.last_scanned_commit = last_scanned_commit
        self.timestamp = timestamp
        self.increment_number = increment_number
        self.rule_pack = rule_pack
        self.is_latest = is_latest

    @staticmethod
    def create_from_metadata(
        timestamp: datetime,
        scan_type: ScanType,
        last_scanned_commit: str,
        increment_number: int,
        rule_pack: str,
        repository_id: int,
        is_latest: bool,
    ):
        db_scan = DBscan(
            timestamp=timestamp,
            scan_type=scan_type,
            last_scanned_commit=last_scanned_commit,
            increment_number=increment_number,
            rule_pack=rule_pack,
            repository_id=repository_id,
            is_latest=is_latest,
        )
        return db_scan

"""populate is_latest in Scan and Audit

Revision ID: 92408b065681
Revises: 26cf7ab95d3a
Create Date: 2024-03-22 16:00:07.771214

"""

from enum import Enum
from alembic import op
from sqlalchemy import func, Table, table, column, select, update
from itertools import islice

# revision identifiers, used by Alembic.
revision = "92408b065681"
down_revision = "26cf7ab95d3a"
branch_labels = None
depends_on = None


TABLE_REPOSITORY = "repository"
TABLE_VCS_INSTANCE = "vcs_instance"
TABLE_FINDING = "finding"
TABLE_SCAN = "scan"
TABLE_RULE_ALLOW_LIST = "rule_allow_list"
TABLE_RULE_PACK = "rule_pack"
TABLE_RULES = "rules"
TABLE_SCAN_FINDING = "scan_finding"
TABLE_AUDIT = "audit"
TABLE_TAG = "tag"
TABLE_RULE_TAG = "rule_tag"

# Those are already defined as constants,
# however it is bad practice to mix migration code and production code
# as renaming things can have a dramatic impact. For this reason we define the constants directly here.
BASE_SCAN = "BASE"
INCREMENTAL_SCAN = "INCREMENTAL"


class ScanType(str, Enum):
    BASE = BASE_SCAN
    INCREMENTAL = INCREMENTAL_SCAN


def upgrade():
    fix_audits()
    fix_scans()


def downgrade():
    # why bother?
    pass


def fix_audits():
    """Assign is_latest to true to the latest audits."""
    conn = op.get_bind()

    audit: Table = table(
        TABLE_AUDIT, column("id"), column("is_latest"), column("finding_id")
    )

    # Create a sub query with group by on finding.
    max_audit_subquery = select(
        audit.c.finding_id, func.max(audit.c.id).label("audit_id")
    )
    max_audit_subquery = max_audit_subquery.group_by(audit.c.finding_id)
    max_audit_subquery = max_audit_subquery.subquery()

    # Select the id from previously selected tupples.
    latest_audits_query = select(audit.c.id)
    latest_audits_query = latest_audits_query.join(
        max_audit_subquery, max_audit_subquery.c.audit_id == audit.c.id
    )
    latest_audits = conn.execute(latest_audits_query).scalars().all()

    # Iterate over those ids by chunk.
    # This is necessary because SQL tends to crash when you do IN with more than 1000 values.
    # source: trust me bro.
    iterator = iter(latest_audits)
    while chunk := list(islice(iterator, 100)):
        query = update(audit)
        query = query.where(audit.c.id.in_(chunk))
        query = query.values(is_latest=True)
        conn.execute(query)


def fix_scans():
    """Assign is_latest to true to the latest scans (Base + incremental) per ruleset."""
    conn = op.get_bind()

    rule_packs: Table = table(TABLE_RULE_PACK, column("version"))

    scan: Table = table(
        TABLE_SCAN,
        column("id"),
        column("repository_id"),
        column("rule_pack"),
        column("scan_type"),
        column("is_latest"),
    )

    # select the rule packs.
    # This gives us all the versions : 1.0.0, 1.0.1 etc...
    query = select(rule_packs.c.version)
    rulepacks = conn.execute(query).scalars().all()

    # For EACH rule pack, we apply the modification.
    # We do this because the latest scans need to be defined PER rule pack.
    for rulepack in rulepacks:
        max_base_scan_subquery = select(
            scan.c.repository_id, func.max(scan.c.id).label("latest_base_scan_id")
        )
        max_base_scan_subquery = max_base_scan_subquery.where(
            scan.c.scan_type == ScanType.BASE, scan.c.rule_pack == rulepack
        )
        max_base_scan_subquery = max_base_scan_subquery.group_by(scan.c.repository_id)
        max_base_scan_subquery = max_base_scan_subquery.subquery()

        # We select the scan ids matching those needing to be updated for that rulepack
        latest_scans_query = select(scan.c.id)
        latest_scans_query = latest_scans_query.join(
            max_base_scan_subquery,
            scan.c.repository_id == max_base_scan_subquery.c.repository_id,
        )
        latest_scans_query = latest_scans_query.where(
            scan.c.id >= max_base_scan_subquery.c.latest_base_scan_id,
            scan.c.rule_pack == rulepack,
        )
        latest_scans = conn.execute(latest_scans_query).scalars().all()

        # Iterate over those ids by chunk.
        # This is necessary because SQL tends to crash when you do IN with more than 1000 values.
        # source: trust me bro.
        iterator = iter(latest_scans)
        while chunk := list(islice(iterator, 100)):
            query = update(scan)
            query = query.where(scan.c.id.in_(chunk))
            query = query.values(is_latest=True)
            conn.execute(query)

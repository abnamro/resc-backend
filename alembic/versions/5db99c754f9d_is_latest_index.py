"""is_latest-index

Revision ID: 5db99c754f9d
Revises: d9e5073bee35
Create Date: 2024-06-20 10:07:51.531398

"""
from alembic import op


# revision identifiers, used by Alembic.
revision = '5db99c754f9d'
down_revision = 'd9e5073bee35'
branch_labels = None
depends_on = None


def upgrade():
    op.create_index("nci_audit_is_latest", "audit", ["is_latest", "finding_id", "status"])
    op.create_index("nci_scan_is_latest", "scan", ["is_latest", "rule_pack", "timestamp", "repository_id", "scan_type"])

def downgrade():
    op.drop_index("nci_audit_is_latest", "audit")
    op.drop_index("nci_scan_is_latest", "scan")

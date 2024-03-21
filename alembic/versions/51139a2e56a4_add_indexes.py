"""add indexes

Revision ID: 51139a2e56a4
Revises: 93b9238ea4ba
Create Date: 2024-03-12 14:40:03.626628

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '51139a2e56a4'
down_revision = '93b9238ea4ba'
branch_labels = None
depends_on = None


def upgrade():
    op.create_index("nci_finding_event_sender", "finding", ["event_sent_on", "author", "column_end", "column_start", "commit_id", "commit_timestamp", "email", "file_path", "line_number", "repository_id", "rule_name"])
    op.create_index("nci_scan_rule_pack_repo_id", "scan", ["rule_pack", "repository_id", "scan_type"])

def downgrade():
    op.create_drop("nci_scan_rule_pack_repo_id", "scan", ["rule_pack", "repository_id", "scan_type"])
    op.create_drop("nci_finding_event_sender", "finding", ["event_sent_on", "author", "column_end", "column_start", "commit_id", "commit_timestamp", "email", "file_path", "line_number", "repository_id", "rule_name"])

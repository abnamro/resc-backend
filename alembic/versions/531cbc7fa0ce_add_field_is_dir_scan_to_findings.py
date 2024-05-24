"""add_field_is_dir_scan_to_findings

Revision ID: 531cbc7fa0ce
Revises: 6c6d15b4cb06
Create Date: 2024-05-23 08:40:17.524425

"""

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "531cbc7fa0ce"
down_revision = "6c6d15b4cb06"
branch_labels = None
depends_on = None


IS_DIR_SCAN = "is_dir_scan"
FINDING = "finding"


def upgrade():
    op.add_column(FINDING, sa.Column(IS_DIR_SCAN, sa.Boolean(), nullable=False, server_default=sa.text("0")))


def downgrade():
    op.drop_column(FINDING, IS_DIR_SCAN)

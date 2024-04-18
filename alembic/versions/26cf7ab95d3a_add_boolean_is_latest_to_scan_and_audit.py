"""add boolean is_latest to Scan and Audit

Revision ID: 26cf7ab95d3a
Revises: 38bccf177626
Create Date: 2024-03-21 12:13:30.889287

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '26cf7ab95d3a'
down_revision = '38bccf177626'
branch_labels = None
depends_on = None

IS_LATEST = 'is_latest'

REPOSITORY = 'repository'
VCS_INSTANCE = 'vcs_instance'
FINDING = 'finding'
SCAN = 'scan'
RULE_ALLOW_LIST = 'rule_allow_list'
RULE_PACK = 'rule_pack'
RULES = 'rules'
SCAN_FINDING = 'scan_finding'
AUDIT = 'audit'
TAG = 'tag'
RULE_TAG = 'rule_tag'


def upgrade():
    op.add_column(AUDIT, sa.Column(IS_LATEST, sa.Boolean(), nullable=False, server_default=sa.text('0')))
    op.add_column(SCAN, sa.Column(IS_LATEST, sa.Boolean(), nullable=False, server_default=sa.text('0')))


def downgrade():
    op.drop_column(AUDIT, IS_LATEST)
    op.drop_column(SCAN, IS_LATEST)

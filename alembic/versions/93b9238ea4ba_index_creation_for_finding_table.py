"""Index creation for finding table

Revision ID: 93b9238ea4ba
Revises: 70fd7051e03a
Create Date: 2024-02-22 13:31:42.801639

"""
from alembic import op


# revision identifiers, used by Alembic.
revision = '93b9238ea4ba'
down_revision = '70fd7051e03a'
branch_labels = None
depends_on = None


def upgrade():
    op.create_index("ik_rule_name_repository_id", "finding", ["rule_name","repository_id"])


def downgrade():
    op.create_drop("ik_rule_name_repository_id", "finding", ["rule_name","repository_id"])

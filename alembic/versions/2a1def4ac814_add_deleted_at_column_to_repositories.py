"""Add deleted_at column to repositories

Revision ID: 2a1def4ac814
Revises: 5db99c754f9d
Create Date: 2024-06-25 10:54:00.294094

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '2a1def4ac814'
down_revision = '5db99c754f9d'
branch_labels = None
depends_on = None

TABLE_REPOSITORY = "repository"
DELETED_AT = "deleted_at"

# We will need to add index later...

def upgrade():
    op.add_column(TABLE_REPOSITORY, sa.Column(DELETED_AT, sa.DateTime(), nullable=True))


def downgrade():
    op.drop_column(TABLE_REPOSITORY, DELETED_AT)

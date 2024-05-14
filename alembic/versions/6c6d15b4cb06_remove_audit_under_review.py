"""remove-audit-under-review

Revision ID: 6c6d15b4cb06
Revises: 92408b065681
Create Date: 2024-05-14 15:05:36.849877

"""
from alembic import op
from sqlalchemy import Table, table, column, delete

TABLE_AUDIT = "audit"
UNDER_REVIEW = "UNDER_REVIEW"

# revision identifiers, used by Alembic.
revision = '6c6d15b4cb06'
down_revision = '92408b065681'
branch_labels = None
depends_on = None


def upgrade():
    """Assign is_latest to true to the latest audits."""
    conn = op.get_bind()

    audit: Table = table(
        TABLE_AUDIT, column("id"), column("status")
    )

    # Create a sub query with group by on finding.
    delete_query = delete(audit).where(audit.c.status == UNDER_REVIEW)
    result = conn.execute(delete_query)
    print(result.rowcount + " row deleted")

def downgrade():
    pass
    # There is no comming back

"""add comment filed from rule

Revision ID: d9e5073bee35
Revises: 531cbc7fa0ce
Create Date: 2024-06-13 16:19:29.196419

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'd9e5073bee35'
down_revision = '531cbc7fa0ce'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('rules', sa.Column('comment', sa.String(length=2000), nullable=True))
    op.alter_column('rules', 'description',
                    existing_type=sa.String(length=2000), type_=sa.String(length=4000),
                    existing_nullable=False, nullable=True)


def downgrade():
    op.drop_column('rules', 'comment')
    op.alter_column('rules', 'description',
                    existing_type=sa.String(length=4000), type_=sa.String(length=2000),
                    existing_nullable=True, nullable=True)
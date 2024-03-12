"""fix FK

Revision ID: 38bccf177626
Revises: 51139a2e56a4
Create Date: 2024-03-12 14:48:27.332829

"""
import logging
import sys

from alembic import op
import sqlalchemy as sa

from sqlalchemy.engine import Inspector

# revision identifiers, used by Alembic.
revision = '38bccf177626'
down_revision = '51139a2e56a4'
branch_labels = None
depends_on = None

# Logger
logger = logging.getLogger()

repository = 'repository'
vcs_instance = 'vcs_instance'
finding = 'finding'
scan = 'scan'
rule_allow_list = 'rule_allow_list'
rule_pack = 'rule_pack'
rules = 'rules'
scan_finding = 'scan_finding'
audit = 'audit'
tag = 'tag'
rule_tag = 'rule_tag'


def upgrade():
    inspector = Inspector.from_engine(op.get_bind())

    op.drop_constraint('fk_finding_repository_id', finding, type_='foreignkey')
    op.drop_constraint('fk_scan_repository_id', scan, type_='foreignkey')
    op.drop_constraint(get_foreign_key_name(inspector, repository, vcs_instance), repository, type_='foreignkey')
    op.drop_constraint(get_foreign_key_name(inspector, rule_pack, rule_allow_list), rule_pack, type_='foreignkey')
    op.drop_constraint(get_foreign_key_name(inspector, rules, rule_allow_list), rules, type_='foreignkey')
    op.drop_constraint(get_foreign_key_name(inspector, rules, rule_pack), rules, type_='foreignkey')
    op.drop_constraint(get_foreign_key_name(inspector, scan, rule_tag), scan, type_='foreignkey')
    op.drop_constraint(get_foreign_key_name(inspector, scan_finding, finding), scan_finding, type_='foreignkey')
    op.drop_constraint(get_foreign_key_name(inspector, scan_finding, scan), scan_finding, type_='foreignkey')
    op.drop_constraint(get_foreign_key_name(inspector, rule_tag, rules), rule_tag, type_='foreignkey')
    op.drop_constraint(get_foreign_key_name(inspector, rule_tag, tag), rule_tag, type_='foreignkey')
    
    op.create_foreign_key('fk_'+ finding + '_' + repository, finding, repository, ['repository_id'], ['id'], ondelete='CASCADE', onupdate='CASCADE')
    op.create_foreign_key('fk_' + scan + '_' + repository, scan, repository, ['repository_id'], ['id'], ondelete='CASCADE', onupdate='CASCADE')
    op.create_foreign_key('fk_' + repository + '_' + vcs_instance, repository, vcs_instance, ['vcs_instance'], ['id'], ondelete='CASCADE', onupdate='CASCADE')
    op.create_foreign_key('fk_' + rule_pack + '_' + rule_allow_list, rule_pack, rule_allow_list, ['global_allow_list'], ['id'], ondelete='CASCADE', onupdate='CASCADE')
    op.create_foreign_key('fk_' + rules + '_' + rule_allow_list, rules, rule_allow_list, ['allow_list'], ['id'], ondelete='CASCADE', onupdate='CASCADE')
    op.create_foreign_key('fk_' + rules + '_' + rule_pack, rules, rule_pack, ['rule_pack'], ['version'], ondelete='CASCADE', onupdate='CASCADE')
    op.create_foreign_key('fk_' + scan + '_' + rule_pack, scan, rule_pack, ['rule_pack'], ['version'], ondelete='CASCADE', onupdate='CASCADE')
    op.create_foreign_key('fk_' + scan_finding + '_' + finding, scan_finding, finding, ['finding_id'], ['id'], ondelete='CASCADE', onupdate='CASCADE')
    op.create_foreign_key('fk_' + scan_finding + '_' + scan, scan_finding, scan, ['scan_id'], ['id'], ondelete='CASCADE', onupdate='CASCADE')
    op.create_foreign_key('fk_' + rule_tag + '_' + rules, rule_tag, rules, ['rule_id'], ['id'], ondelete='CASCADE', onupdate='CASCADE')
    op.create_foreign_key('fk_' + rule_tag + '_' + tag, rule_tag, tag, ['tag_id'], ['id'], ondelete='CASCADE', onupdate='CASCADE')


def downgrade():
    # why bother?
    pass

def get_foreign_key_name(inspector: Inspector, table_name: str, reference_table: str):
    foreign_keys = inspector.get_foreign_keys(table_name=table_name)
    for foreign_key in foreign_keys:
        if foreign_key["referred_table"] == reference_table:
            return foreign_key["name"]
    logger.error(f"Unable to find foreign key name for {table_name} referencing {reference_table}")
    sys.exit(-1)

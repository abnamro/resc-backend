# Standard Library
import logging

# Third Party
from packaging.version import Version
from sqlalchemy import case, func, literal_column, update
from sqlalchemy.orm import Session
from sqlalchemy.orm.query import Query

# First Party
from resc_backend.constants import (
    DEFAULT_RECORDS_PER_PAGE_LIMIT,
    MAX_RECORDS_PER_PAGE_LIMIT,
)
from resc_backend.db.model import DBrule, DBrulePack, DBruleTag, DBscanFinding, DBtag
from resc_backend.resc_web_service.crud.finding import query_untriaged_findings_for_rule_pack
from resc_backend.resc_web_service.schema import rule_pack as rule_pack_schema

logger = logging.getLogger(__name__)


def get_rule_pack(db_connection: Session, version: str | None) -> rule_pack_schema.RulePackRead:
    """
        Get active rule pack from database
    :param db_connection:
        Session of the database connection
    :param version:
        optional, version of the rule pack to be fetched else latest rule pack version will be fetched
    :return: RulePackRead
        The output returns RulePackRead type object
    """
    query = db_connection.query(DBrulePack)
    if version:
        query = query.where(DBrulePack.version == version)
    else:
        logger.debug("rule pack version not specified, fetching currently active one")
        query = query.where(DBrulePack.active == True)  # noqa: E712
    rule_pack = query.first()
    return rule_pack


def create_rule_pack_version(db_connection: Session, rule_pack: rule_pack_schema.RulePackCreate):
    """
        Create rule pack version in database
    :param db_connection:
        Session of the database connection
    :param rule_pack:
        RulePackCreate object to be created
    """
    db_rule_pack = DBrulePack(
        version=rule_pack.version,
        global_allow_list=rule_pack.global_allow_list,
        active=rule_pack.active,
    )
    db_connection.add(db_rule_pack)
    db_connection.commit()
    db_connection.refresh(db_rule_pack)
    return db_rule_pack


def get_newest_rule_pack(db_connection: Session) -> rule_pack_schema.RulePackRead:
    """
        Fetch the newest rule pack from database
    :param db_connection:
        Session of the database connection
    :return: RulePackRead
        The output returns RulePackRead type object
    """
    rule_packs = db_connection.query(DBrulePack).all()
    newest_rule_pack = None
    if rule_packs:
        newest_rule_pack: rule_pack_schema.RulePackRead = rule_packs[0]
        for rule_pack in rule_packs[1:]:
            if Version(rule_pack.version) > Version(newest_rule_pack.version):
                newest_rule_pack = rule_pack
    return newest_rule_pack


def get_rule_packs(
    db_connection: Session,
    version: str = None,
    active: bool = None,
    skip: int = 0,
    limit: int = DEFAULT_RECORDS_PER_PAGE_LIMIT,
) -> list[DBrulePack]:
    """
        Retrieve rule packs from database
    :param db_connection:
        Session of the database connection
    :param version:
        optional, filter on rule pack version
    :param active:
        optional, filter on active rule pack
    :param skip:
        integer amount of records to skip, to support pagination
    :param limit:
        integer amount of records to return, to support pagination
    :return: [RulePackRead]
        The output will contain a PaginationModel containing the list of RulePackRead type objects,
        or an empty list if no rule pack was found
    """
    limit_val = MAX_RECORDS_PER_PAGE_LIMIT if limit > MAX_RECORDS_PER_PAGE_LIMIT else limit

    outdated_stmt = db_connection.query(
        case((func.count(DBscanFinding.finding_id) == 0, literal_column("'1'")), else_=literal_column("'0'"))
    )
    outdated_stmt = query_untriaged_findings_for_rule_pack(outdated_stmt, DBrulePack.version)
    outdated_stmt = outdated_stmt.label("outdated")

    query: Query = db_connection.query(
        DBrulePack.version, DBrulePack.active, DBrulePack.created, DBrulePack.global_allow_list, outdated_stmt
    )
    if version:
        query = query.where(DBrulePack.version == version)
    if active is not None:
        query = query.where(DBrulePack.active == active)
    rule_packs = query.order_by(DBrulePack.version.desc()).offset(skip).limit(limit_val).all()
    return rule_packs


def get_current_active_rule_pack(
    db_connection: Session,
) -> DBrulePack | None:
    """
        Return the currently active rule_pack, if any.
    :param db_connection:
        Session of the database connection
    :return: DBRulePack
        returns the DBRulePack containing the active rule pack
    """
    query = db_connection.query(DBrulePack)
    active_rule_pack = query.where(DBrulePack.active == 1).one()
    return active_rule_pack


def get_rule_packs_tags(db_connection: Session, versions: list) -> list[str]:
    """
        Retrieve rule packs tags for versions from database
    :param db_connection:
        Session of the database connection
    :param versions:
        optional, filter on rule pack version
    :return: [str]
        The output will contain the list of str that are the tags, or an empty list.
    """

    query: Query = db_connection.query(DBtag.name)
    query = query.join(DBruleTag, DBruleTag.tag_id == DBtag.id_)
    query = query.join(DBrule, DBrule.id_ == DBruleTag.rule_id)
    query = query.where(DBrule.rule_pack.in_(versions))
    rule_packs_tags = query.distinct().all()
    rule_packs_tags = [t for (t,) in rule_packs_tags]
    return rule_packs_tags


def get_total_rule_packs_count(db_connection: Session, version: str = None, active: bool = None) -> int:
    """
        Retrieve total count of rule packs from database
    :param db_connection:
        Session of the database connection
    :param version:
        optional, filter on rule pack version
    :param active:
        optional, filter on active rule pack
    :return: int
        The output contains total count of rule packs
    """
    total_count_query = db_connection.query(func.count(DBrulePack.version))
    if version:
        total_count_query = total_count_query.where(DBrulePack.version == version)
    if active is not None:
        total_count_query = total_count_query.where(DBrulePack.active == active)

    total_count = total_count_query.scalar()
    return total_count


def make_older_rule_packs_to_inactive(latest_rule_pack_version: str, db_connection: Session):
    """
        Make older rule packs to inactive
    :param latest_rule_pack_version:
        latest rule pack version
    :param db_connection:
        Session of the database connection
    """
    db_connection.execute(update(DBrulePack).where(DBrulePack.version != latest_rule_pack_version).values(active=False))
    db_connection.commit()

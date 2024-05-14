# Standard Library

# Third Party
from sqlalchemy.orm import Session
from sqlalchemy.orm.query import Query

# First Party
from resc_backend.db.model import DBrule, DBruleTag, DBtag


def create_rule_tag(db_connection: Session, rule_id: int, tags: list[str]) -> list[DBruleTag]:
    """
    Create rule tag entries, linking / creating tag names to a rule
    :param db_connection:
        Session of the database connection
    :param rule_id:
        ID of the rule to link the tags to
    :param tags:
        List of string type containing tags to link to the rule
    :return: [DBruleTag]
        The output will contain a list of DBruleTag objects
    """
    db_tags = create_tags_if_not_exists(db_connection, tags)

    db_rule_tags = []
    for db_tag in db_tags:
        db_rule_tag = DBruleTag(rule_id=rule_id, tag_id=db_tag.id_)
        db_rule_tags.append(db_rule_tag)

    if db_rule_tags:
        db_connection.add_all(db_rule_tags)
        db_connection.flush()
        db_connection.commit()
    return db_rule_tags


def create_tags_if_not_exists(db_connection: Session, tags: list[str]) -> list[DBtag]:
    """
    Create tags if they don't exist or select existing
    :param db_connection:
        Session of the database connection
    :param tags:
        List of string type containing tags to create if they don't exist
    :return: [DBtag]
        The output will contain a list of tag objects
    """
    # Query the database to see if the tags objects exists
    db_tags = db_connection.query(DBtag).filter(DBtag.name.in_(tags)).all()
    if db_tags is not None:
        if len(db_tags) == len(tags):
            # all tags are in the db no need to create them
            return db_tags
        tags_known = [x.name for x in db_tags]
        tags_to_create = [tag for tag in tags if tag not in tags_known]
        # Created the tags not known
        created_tags = create_tags(db_connection, tags_to_create)
        db_tags.extend(created_tags)
    else:
        # None of the tags are known, create them all
        db_tags = create_tags(db_connection, tags)

    return db_tags


def create_tags(db_connection: Session, tags: list[str]) -> list[DBtag]:
    """
    Create tags
    :param db_connection:
        Session of the database connection
    :param tags:
        List of string type containing tags to create
    :return: [DBtag]
        The output will contain a list of tag objects
    """
    db_create_tags = []
    for tag_name in tags:
        db_create_tag = DBtag(name=tag_name)
        db_create_tags.append(db_create_tag)

    if db_create_tags:
        db_connection.add_all(db_create_tags)
        db_connection.flush()
        db_connection.commit()
    return db_create_tags


def get_rule_tag_names_by_rule_pack_version(db_connection: Session, rule_pack_version: str):
    """
    Get rule names and there tags based on the rule pack version
    :param db_connection:
        Session of the database connection
    :param rule_pack_version:
        Version of the rule pack for which to retrieve the rule tags
    :return: [rule.rule_name, tag.name]
        The output will contain a list of each rule and tag occurrence in the rule_pack
    """
    query: Query = db_connection.query(DBrule.rule_name, DBtag.name)
    query = query.join(DBruleTag, DBruleTag.tag_id == DBtag.id_)
    query = query.join(DBrule, DBrule.id_ == DBruleTag.rule_id)
    query = query.where(DBrule.rule_pack == rule_pack_version)
    return query.all()

# Standard Library
import logging
import os
import re

# Third Party
from fastapi import File, HTTPException

# First Party
from resc_backend.constants import (
    ALLOWED_EXTENSION,
    TOML_CUSTOM_DELIMITER,
)
from resc_backend.resc_web_service.schema.rule import Rule
from resc_backend.resc_web_service.schema.rule_allow_list import RuleAllowList

FILE_NAME_REGEX = r"^[a-zA-Z0-9-_]+$"

logger = logging.getLogger(__name__)


def create_allow_list_dictionary(allow_list: RuleAllowList) -> dict:
    """
        Create a dictionary for allow list when an RuleAllowList object is supplied
    :param allow_list:
        RuleAllowList object
    :return: AllowList dictionary
        The output will contain a dictionary of AllowList
    """
    allow_list_dict = {}
    if allow_list:
        if allow_list.description:
            allow_list_dict["description"] = allow_list.description
        if allow_list.regexes:
            allow_list_dict["regexes"] = allow_list.regexes
        if allow_list.paths:
            allow_list_dict["paths"] = allow_list.paths
        if allow_list.commits:
            allow_list_dict["commits"] = allow_list.commits
        if allow_list.stop_words:
            allow_list_dict["stop_words"] = allow_list.stop_words
    return allow_list_dict


def create_rule_dictionary(rule: Rule, allow_list_dict: dict, tags: str) -> dict:
    """
        Create a dictionary for rule when Rule object and RuleAllowList dict are supplied
    :param rule:
        Rule object
    :param allow_list_dict:
        Allow list dictionary
    :param tags:
        String of tags of the rule
    :return: Rule dictionary
        The output will contain a dictionary of Rule
    """
    rule_dict = {}
    if rule.rule_name:
        rule_dict["id"] = rule.rule_name
    if rule.rule_description:
        rule_dict["description"] = rule.rule_description
    if tags:
        rule_dict["tags"] = tags
    if rule.entropy:
        rule_dict["entropy"] = rule.entropy
    if rule.secret_group:
        rule_dict["secret_group"] = rule.secret_group
    if rule.regex:
        rule_dict["regex"] = rule.regex
    if rule.path:
        rule_dict["path"] = rule.path
    if rule.keywords:
        rule_dict["keywords"] = rule.keywords
    if allow_list_dict:
        rule_dict["allow_list"] = allow_list_dict
    if rule.comment:
        rule_dict["comment"] = rule.comment
    return rule_dict


def create_toml_dictionary(
    rule_pack_version: str,
    rules: list[str],
    global_allow_list: list[str],
    rule_tag_names,
) -> dict:
    """
        Create a dictionary for gitleaks toml rule for specified rule pack version, rules and global allow list
    :param rule_pack_version:
        Rule pack version
    :param rules:
        Rule list
    :param global_allow_list:
        Global Allow list
    :param rule_tag_names:
        List of rule names and tags
    :return: toml dictionary
        The output will contain a dictionary for gitleaks toml rule
    """
    rule_list = []
    for rule in rules:
        allow_list_dict = create_allow_list_dictionary(rule)
        tags_list = [x.name for x in rule_tag_names if x.rule_name == rule.rule_name]
        tags = None
        if len(tags_list) >= 1:
            tags = ",".join(tags_list)
        rule_dict = create_rule_dictionary(rule, allow_list_dict, tags)
        rule_list.append(rule_dict)

    global_allow_list_dict = create_allow_list_dictionary(global_allow_list)

    rule_toml_dict = {"title": "gitleaks config"}
    if rule_pack_version:
        rule_toml_dict["version"] = rule_pack_version
    if rule_list:
        rule_toml_dict["rules"] = rule_list
    if global_allow_list_dict:
        rule_toml_dict["allowlist"] = global_allow_list_dict
    return rule_toml_dict


def get_mapped_global_allow_list_obj(toml_rule_dictionary: dict) -> RuleAllowList:
    """
        Get global allow list object from toml rule dictionary
    :param toml_rule_dictionary:
        TOML rule dictionary
    :return: RuleAllowList
        The output will contain an object of RuleAllowList
    """
    global_allow_list_obj = None
    if "allowlist" in toml_rule_dictionary:
        global_allow_list = toml_rule_dictionary.get("allowlist")
        global_allow_list_obj = map_dictionary_to_rule_allow_list_object(global_allow_list)
    else:
        logger.info("No global allow list is present in the toml file!")
    return global_allow_list_obj


def map_dictionary_to_rule_allow_list_object(
    allow_list_dictionary: dict,
) -> RuleAllowList:
    """
        Convert allow list dictionary to RuleAllowList object
    :param allow_list_dictionary:
        AllowList dictionary
    :return: RuleAllowList
        The output will contain an object of RuleAllowList
    """
    rule_allow_list = None
    if allow_list_dictionary:
        description = allow_list_dictionary["description"] if "description" in allow_list_dictionary else None
        regexes = None
        paths = None
        commits = None
        stopwords = None

        if "regexes" in allow_list_dictionary:
            regexes = ""
            regexes_array = allow_list_dictionary["regexes"]
            for index, regex in enumerate(regexes_array):
                if index + 1 < len(regexes_array):
                    regexes += regex + TOML_CUSTOM_DELIMITER
                else:
                    regexes += regex

        if "paths" in allow_list_dictionary:
            paths = ""
            paths_array = allow_list_dictionary["paths"]
            for index, path in enumerate(paths_array):
                if index + 1 < len(paths_array):
                    paths += path + TOML_CUSTOM_DELIMITER
                else:
                    paths += path

        if "commits" in allow_list_dictionary:
            commits_array = allow_list_dictionary["commits"]
            commits = ",".join(commits_array)

        if "stopwords" in allow_list_dictionary:
            stopword_array = allow_list_dictionary["stopwords"]
            stopwords = ",".join(stopword_array)

        rule_allow_list = RuleAllowList(
            description=description,
            regexes=regexes,
            paths=paths,
            commits=commits,
            stop_words=stopwords,
        )
    return rule_allow_list


def validate_uploaded_file_and_read_content(rule_file: File) -> str:
    """
       Validate the uploaded file and read content
    :param rule_file:
        File uploaded
    :return: content
        Return file content
    """
    file_name = os.path.splitext(rule_file.filename)[0]

    # File name validation
    is_valid_file_name = bool(re.match(FILE_NAME_REGEX, file_name))
    if not is_valid_file_name:
        raise HTTPException(500, detail=f"Invalid characters in File name - {file_name}")

    # File name max length validation
    if len(file_name) > 255:
        raise HTTPException(500, detail="File name value exceeds maximum length of 255 characters")

    # File extension validation
    if rule_file.content_type != "application/octet-stream" or not rule_file.filename.lower().endswith(
        ALLOWED_EXTENSION
    ):
        raise HTTPException(500, detail="Invalid document type, only TOML file is supported")

    # File size validation
    max_size: int = 1000000
    content = rule_file.file.read()
    file_size = len(content)
    if file_size > max_size:
        raise HTTPException(500, detail="File size exceeds the maximum limit 1 MB")

    toml_content = str(content, "utf-8")
    return toml_content

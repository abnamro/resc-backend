# Third Party
import tomlkit
from tomlkit import aot, comment, document, nl, table
from tomlkit.items import AoT, Array, String, StringType, Table
from tomlkit.toml_document import TOMLDocument

# First Party
from resc_backend.constants import (
    TEMP_RULE_FILE,
    TOML_CUSTOM_DELIMITER,
)


def create_toml_rule_file(parsed_toml_dictionary: dict):
    """
        Create a TOML file from a dictionary
    :param parsed_toml_dictionary:
        TOML dictionary
    :return: toml_file
        Returns toml file
    """
    doc = create_toml_document(parsed_toml_dictionary)
    return write_toml_document(doc, TEMP_RULE_FILE)


def create_toml_document(parsed_toml_dictionary: dict) -> TOMLDocument:
    """
        Create a TOML document from a dictionary
    :param parsed_toml_dictionary:
        TOML dictionary
    :return: TOMLDocument
        Returns toml document in memory
    """
    doc = document()
    doc.add(comment("This is a gitleaks configuration file."))
    doc.add(comment("Rules and allowlists are defined within this file."))
    doc.add(comment("Rules instruct gitleaks on what should be considered a secret."))
    doc.add(comment("Allowlists instruct gitleaks on what is allowed, i.e. not a secret."))
    doc.add(nl())

    if "title" in parsed_toml_dictionary:
        doc.add("title", parsed_toml_dictionary["title"])
    doc.add(nl())
    if "version" in parsed_toml_dictionary:
        doc.add("version", parsed_toml_dictionary["version"])
    doc.add(nl())

    # Global allow list table
    global_allow_list_table = create_allow_list_toml_table(input_dictionary=parsed_toml_dictionary, key="allowlist")
    if global_allow_list_table:
        doc.add("allowlist", global_allow_list_table)
        doc.add(nl())

    # Rules table
    rule_array_table = create_rule_array_toml_table(rule_dictionary=parsed_toml_dictionary)
    doc.add("rules", rule_array_table)
    return doc


def write_toml_document(doc: TOMLDocument, destination: str = TEMP_RULE_FILE):
    """
        Write a TOML document to a TOML file
    :param doc:
        TOMLDocument document
    :param destination:
        file name of the returned document
    :return: toml_file
        Returns toml file
    """
    toml_string = tomlkit.dumps(doc)
    with open(destination, "w", encoding="utf-8") as toml_file:
        toml_file.write(toml_string)
        toml_file.close()
    return toml_file


def get_multiline_array_for_toml_file(input_dictionary: dict, key: str, string_type: str, delimiter: str) -> Array:
    """
        Create multiline toml array for the input dictionary value
    :param input_dictionary:
        Input dictionary
    :param key:
        key of Input dictionary
    :param string_type:
        Multi Line Literal or Single Line Basic
    :param delimiter:
        TOML_CUSTOM_DELIMITER or ","
    :return: tomlkit.array
        The output will return a toml array
    """
    multiline_array = tomlkit.array()
    array_from_db = input_dictionary[key].split(delimiter)
    for value_str in array_from_db:
        multiline_array.append(String.from_raw(String.from_raw(value_str), string_type))
        multiline_array.multiline(True)
    return multiline_array


def create_allow_list_toml_table(input_dictionary: dict, key: str) -> Table:
    """
        Create a TOML table for rule allow list
    :param input_dictionary:
        AllowList dictionary
     :param key:
        Key in AllowList dictionary
    :return: table
        Returns allow list TOML table
    """
    allow_list_table = None
    if key in input_dictionary:
        allow_list_table = table()
        allow_list_dict = input_dictionary[key]
        if "description" in allow_list_dict:
            allow_list_table.add("description", allow_list_dict["description"])
        if "paths" in allow_list_dict:
            multiline_path_array = get_multiline_array_for_toml_file(
                input_dictionary=allow_list_dict,
                key="paths",
                string_type=StringType.MLL,
                delimiter=TOML_CUSTOM_DELIMITER,
            )
            allow_list_table.add("paths", multiline_path_array)
        if "regexes" in allow_list_dict:
            multiline_regex_array = get_multiline_array_for_toml_file(
                input_dictionary=allow_list_dict,
                key="regexes",
                string_type=StringType.MLL,
                delimiter=TOML_CUSTOM_DELIMITER,
            )
            allow_list_table.add("regexes", multiline_regex_array)
        if "commits" in allow_list_dict:
            multiline_commit_array = get_multiline_array_for_toml_file(
                input_dictionary=allow_list_dict,
                key="commits",
                string_type=StringType.SLB,
                delimiter=",",
            )
            allow_list_table.add("commits", multiline_commit_array)
        if "stop_words" in allow_list_dict:
            multiline_stopword_array = get_multiline_array_for_toml_file(
                input_dictionary=allow_list_dict,
                key="stop_words",
                string_type=StringType.SLB,
                delimiter=",",
            )
            allow_list_table.add("stopwords", multiline_stopword_array)
    return allow_list_table


def create_rule_array_toml_table(rule_dictionary: dict) -> AoT:
    """
       Create an array of table for rule list
    :param rule_dictionary:
        Rule dictionary
    :return: table
        Return an array of table
    """

    # Rule Table
    rule_array_table = aot()
    if "rules" in rule_dictionary:
        for rule_dict in rule_dictionary["rules"]:
            rule_table = table()
            if "id" in rule_dict:
                rule_table.add("id", rule_dict["id"])
            if "description" in rule_dict:
                rule_table.add("description", rule_dict["description"])
            if "entropy" in rule_dict:
                rule_table.add("entropy", rule_dict["entropy"])
            if "secret_group" in rule_dict:
                rule_table.add("secretGroup", rule_dict["secret_group"])
            if "regex" in rule_dict:
                rule_table.add("regex", String.from_raw(rule_dict["regex"], StringType.MLL))
            if "path" in rule_dict:
                rule_table.add("path", String.from_raw(rule_dict["path"], StringType.MLL))
            if "tags" in rule_dict:
                multiline_tag_array = get_multiline_array_for_toml_file(
                    input_dictionary=rule_dict,
                    key="tags",
                    string_type=StringType.SLB,
                    delimiter=",",
                )
                rule_table.add("tags", multiline_tag_array)
            if "keywords" in rule_dict:
                multiline_keyword_array = get_multiline_array_for_toml_file(
                    input_dictionary=rule_dict,
                    key="keywords",
                    string_type=StringType.SLB,
                    delimiter=",",
                )
                rule_table.add("keywords", multiline_keyword_array)
            if "comment" in rule_dict:
                rule_table.add("comment", rule_dict["comment"])

            # Rule Allow List Table
            if "allow_list" in rule_dict:
                allow_list_table = create_allow_list_toml_table(input_dictionary=rule_dict, key="allow_list")
                rule_table.append("allowlist", allow_list_table)

            rule_array_table.append(rule_table)
    return rule_array_table

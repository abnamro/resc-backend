# Standard Library
from functools import reduce


def _remapper0(val):
    return val[0]


def _remapper1(val):
    return val[1]


def remap_dict_keys(input_dict: dict, transformation_map: list):
    new_keys = list(map(_remapper1, transformation_map))
    for old_key, new_key in transformation_map:
        create_nested_dictionary(input_dict, new_key, get_value_from_nested_dictionary(input_dict, *old_key))

    new_keys_mapped = list(map(_remapper0, new_keys))
    output_dict = {k: v for k, v in input_dict.items() if k in new_keys_mapped}

    return output_dict


def create_nested_dictionary(dictionary, keys, value):
    for key in keys[:-1]:
        dictionary = dictionary.setdefault(key, {})
    if not isinstance(dictionary, dict):
        dictionary = {}
        dictionary = dictionary.setdefault(keys[-1], {})
    dictionary[keys[-1]] = value


def _reducer(d, key):
    return d.get(key) if d else None


def get_value_from_nested_dictionary(dictionary, *keys):
    return reduce(_reducer, keys, dictionary)


def delete_keys_from_nested_dict(dict_del, lst_keys):
    if not lst_keys:
        return
    if len(lst_keys) == 1:
        del dict_del[lst_keys[0]]
    else:
        for value in dict_del.values():
            if isinstance(value, dict):
                delete_keys_from_nested_dict(value, lst_keys[1:])

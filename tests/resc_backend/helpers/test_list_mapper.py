# First Party
from resc_backend.helpers.list_mapper import dict_of_list


def keyed(val: dict) -> str:
    return f"{val['a']}|{val['b']}"


def test_remap_dict_keys():
    input_list = [
        {"a": "x1", "b": "y1", "c": "z1"},
        {"a": "x2", "b": "y2", "c": "z2"},
        {"a": "x3", "b": "y3", "c": "z3"},
    ]
    expected_output_dict = {
        "x1|y1": {"a": "x1", "b": "y1", "c": "z1"},
        "x2|y2": {"a": "x2", "b": "y2", "c": "z2"},
        "x3|y3": {"a": "x3", "b": "y3", "c": "z3"},
    }
    output_dict = dict_of_list(keyed, input_list)
    assert output_dict == expected_output_dict

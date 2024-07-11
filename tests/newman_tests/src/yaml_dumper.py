EOL = "\n"
INDENT = "  "
BAR = "- "


def _fix_key(key:str) -> str:
    if key == 'schema_':
        return 'schema'
    if key == 'postman_id':
        return '_postman_id'
    return key

def _dump_dict(input_dict: dict[str, str | dict], key="") -> list[str]:
    rets = []
    for key_ in input_dict.keys():
        input_val = input_dict[key_]
        if isinstance(input_val, str):
            rets.extend(_dump_string(input_val, key_))
        if isinstance(input_val, int):
            rets.extend([_dump_number(input_val, key_)])

        if isinstance(input_val, list):
            rets.extend(_dump_array(input_val, key_))

        if isinstance(input_val, dict):
            rets.append(f"{key_}:")
            rets.extend(_dump_dict(input_val, key_))
    if key != "":
        return [f"{INDENT}{x}" for x in rets]

    return rets


def _dump_array(inputs: list, key: str) -> list[str]:
    if len(inputs) == 0:
        return [f"{key}: []"]

    ret = [f"{key}:"]
    for input_val in inputs:
        if isinstance(input_val, str) or isinstance(input_val, int):
            ret.extend([f"{INDENT}{INDENT}{BAR}{input_val}"])
        if isinstance(input_val, dict):
            rett = _dump_dict(input_val)
            zipp = [f"{INDENT}{INDENT}"] * len(rett)
            zipp[0] = f"{INDENT}{BAR}"
            ret.extend([y + x for x, y in zip(rett, zipp)])

    return ret


def _dump_string(input_val: str, key: str) -> list[str]:
    key = _fix_key(key)
    if EOL not in input_val:
        if len(input_val) == 0:
            return [f'{key}: ""']

        if input_val.startswith("{"):
            return [f"{key}: \"{input_val.replace('"', "\\\"")}\""]
        return [f"{key}: {input_val}"]

    ret = [f"{key}: |-"]
    ret.extend([f"{INDENT}{x}" for x in input_val.split(EOL)])

    return ret


def _dump_number(input_val: int, key: str) -> str:
    return f"{key}: {input_val}"


# Only use this one.
def dump_yaml(input_val) -> str:
    return EOL.join(_dump_dict(input_val, ""))


def self_test(expected, value):
    try:
        assert dump_yaml(value) == expected
        print("test passed. ✅")
    except AssertionError:
        print("test failed. ❌")
        print("expected:")
        print("-" * 10)
        print(expected)
        print("actual")
        print("+" * 10)
        print(dump_yaml(value))


if __name__ == "__main__":
    print("SELF TESTING YAML DUMPER")

    expected = """foo: 0
bar: hi"""
    self_test(expected, {"foo": 0, "bar": "hi"})

    expected = """foo: 0
bar:
  foo1: 1
  bar1: hi1"""
    self_test(expected, {"foo": 0, "bar": {"foo1": 1, "bar1": "hi1"}})

    expected = """foo: 0
bar:
  - 1: 1
  - 2: 2"""
    self_test(expected, {"foo": 0, "bar": [{"1": "1"}, {"2": "2"}]})

    expected = """foo: 0
bar:
  - something: hello
  - something2: |-
      something
      something"""
    self_test(expected, {"foo": 0, "bar": [{"something": "hello"}, {"something2": "something\nsomething"}]})

    expected = """foo: 0
bar:
  name: name
  codes:
      - 0
      - 1
      - 2"""
    self_test(expected, {"foo": 0, "bar": {"name": "name", "codes": [0, 1, 2]}})

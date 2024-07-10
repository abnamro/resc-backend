EOL = "\n"
INDENT = "  "
BAR = "- "

# def dump(input) -> str:
#     if isinstance(input, str):
#         return dump_string(key, input, indent, idx)
#     if isinstance(input, int):
#         return dump_number(key, input, indent, idx)
#     if isinstance(input, list):
#         return dump_array(key, input, indent, idx)
#     if isinstance(input, dict):
#         return dump_dict(key, input, indent, idx)

#     raise ValueError(f"Something is wrong with {input}")


def fix_key(key: str) -> str:
    if key == "postman_id":
        return "_postman_id"
    if key == "schema_":
        return "schema"
    return key


def dump_dict(input_dict: dict[str, str | dict], key="") -> list[str]:
    rets = []
    for key_ in input_dict.keys():
        input_val = input_dict[key_]
        if isinstance(input_val, str):
            rets.extend(dump_string(input_val, key_))
        if isinstance(input_val, int):
            rets.extend([dump_number(input_val, key_)])

        if isinstance(input_val, list):
            rets.extend(dump_array(input_val, key_))

        if isinstance(input_val, dict):
            rets.append(f"{key_}:")
            rets.extend(dump_dict(input_val, key_))
    if key != "":
        return [f"{INDENT}{x}" for x in rets]

    return rets


def dump_array(inputs: list, key: str) -> list[str]:
    if len(inputs) == 0:
        return [f"{key}: []"]

    ret = [f"{key}:"]
    for input_val in inputs:
        if isinstance(input_val, str) or isinstance(input_val, int):
            ret.extend([f"{INDENT}{INDENT}{BAR}{input_val}"])
        if isinstance(input_val, dict):
            rett = dump_dict(input_val)
            zipp = [f"{INDENT}{INDENT}"] * len(rett)
            zipp[0] = f"{INDENT}{BAR}"
            ret.extend([y + x for x, y in zip(rett, zipp)])

    return ret


def dump_string(input_val: str, key: str) -> list[str]:
    key = fix_key(key)
    if EOL not in input_val:
        if len(input_val) == 0:
            return [f'{key}: ""']

        if input_val.startswith("{"):
            return [f"{key}: \"{input_val.replace('"', "\\\"")}\""]
        return [f"{key}: {input_val}"]

    ret = [f"{key}: |-"]
    ret.extend([f"{INDENT}{x}" for x in input_val.split(EOL)])

    return ret


def dump_number(input_val: int, key: str) -> str:
    return f"{key}: {input_val}"


def dump_yaml(input_val) -> str:
    return EOL.join(dump_dict(input_val, ""))


if __name__ == "__main__":
    print(dump_yaml({"foo": 0, "bar": "hi"}))

    print("-" * 20)
    print(dump_yaml({"foo": 0, "bar": {"foo1": 1, "bar1": "hi1"}}))

    print("-" * 20)
    print(
        dump_yaml(
            {
                "foo": 0,
                "bar": [
                    {"1": "1"},
                    {"2": "2"},
                ],
            }
        )
    )
    print("-" * 20)
    print(
        dump_yaml(
            {
                "foo": 0,
                "bar": [
                    {"something": "hello"},
                    {"something2": "something\nsomething"},
                ],
            }
        )
    )

    print("-" * 20)
    print(dump_yaml({"foo": 0, "bar": {"name": "name", "codes": [0, 1, 2]}}))

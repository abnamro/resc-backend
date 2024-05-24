from collections.abc import Callable


def dict_of_list(fnction: Callable, data: list) -> dict:
    return dict(zip(map(fnction, data), data))

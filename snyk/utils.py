import json
import logging
from itertools import chain


def snake_to_camel(word):
    return lower_case_first_letter(
        "".join(x.capitalize() or "_" for x in word.split("_"))
    )


def lower_case_first_letter(word):
    return word[:1].lower() + word[1:] if word else ""


def flat_map(fn, *args):
    mapped = map(fn, *args)
    return list(chain(*mapped))


def format_package(pkg):
    return "{name}@{version}".format(name=pkg.name, version=pkg.version or "*")


def cleanup_path(path: str) -> str:
    """
    Strings '/' from the start and end of strings if present to ensure that a '//' doesn't
    occur in an API request due to copy/paste error
    """

    if path[0] == "/":
        path = path[1:]
    if path[-1] == "/":
        path = path.rstrip("/")

    # Ensure we remove "rest/" from next urls
    parts = path.split("/")
    if parts[0] == "rest":
        parts.pop(0)

    return "/".join(parts)


def load_test_data(test_dir: str, test_name: str) -> dict:
    """
    Returns the contents of a json file at location of:
    test_dir/test_name.json

    This is meant to keep large amounts of json needed for testing outside of
    the tests themselves and as the actual json responses from the API
    """
    test_file = f"{test_dir}/{test_name}.json"
    with open(test_file, "r") as the_file:
        data = the_file.read()
    return json.loads(data)

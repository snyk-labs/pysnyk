import re
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

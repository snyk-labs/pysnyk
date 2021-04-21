import re


def snake_to_camel(word):
    return lower_case_first_letter(
        "".join(x.capitalize() or "_" for x in word.split("_"))
    )


def lower_case_first_letter(word):
    return word[:1].lower() + word[1:] if word else ""

def camel_to_snake(s):
    return ''.join(['_'+c.lower() if c.isupper() else c for c in s]).lstrip('_')

def str2bool(string):
    return bool(str(string).lower() in ("yes", "true", "t", "1"))
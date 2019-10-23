import json
from pathlib import Path


def get_default_token_path():
    home = str(Path.home())
    default_token_path = "%s/.config/configstore/snyk.json" % home
    return default_token_path


def get_token(token_file_path):
    path = token_file_path

    try:
        with open(path, "r") as f:
            json_obj = json.load(f)
            token = json_obj["api"]
            return token
    except FileNotFoundError as fnfe:
        print("Snyk auth token not found at %s" % path)
        print("Run `snyk auth` (see https://github.com/snyk/snyk#installation) or manually create this file with your token.")
        raise fnfe
    except KeyError as ke:
        print("Snyk auth token file is not properly formed: %s" % path)
        print("Run `snyk auth` (see https://github.com/snyk/snyk#installation) or manually create this file with your token.")
        raise ke

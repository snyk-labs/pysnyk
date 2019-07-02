from pathlib import Path


def get_token(token_name):
    home = str(Path.home())
    path = "%s/.ssh/tokens/%s" % (home, token_name)
    with open(path) as f:
        read_data = f.read()
        return str.strip(read_data)

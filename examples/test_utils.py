import json
import tempfile

import pytest  # type: ignore

import utils


def test_get_token_fails_if_token_file_not_found():
    with pytest.raises(FileNotFoundError) as pytest_wrapped_exception:
        t = utils.get_token("/some/path/that/does/not/exist/snyk.json")
    assert pytest_wrapped_exception.type == FileNotFoundError
    assert pytest_wrapped_exception.value.args[1] == "No such file or directory"


def test_get_token_fails_if_token_file_cant_be_parsed():
    """Build a temp file with an invalid spec and make sure it fails"""

    obj_token_json = {"some-invalid-key": "test-token"}

    with tempfile.NamedTemporaryFile() as temp_token_file:
        with open(temp_token_file.name, "w") as temp_token_file_write:
            json.dump(obj_token_json, temp_token_file_write, indent=2)

        with pytest.raises(KeyError) as pytest_wrapped_exception:
            temp_filename = temp_token_file.name
            returned_token = utils.get_token(temp_filename)

        assert pytest_wrapped_exception.type == KeyError
        assert pytest_wrapped_exception.value.args[0] == "api"


def test_get_token_works_with_well_formed_token_file():
    obj_token_json = {"api": "test-token"}

    with tempfile.NamedTemporaryFile() as temp_token_file:
        with open(temp_token_file.name, "w") as temp_token_file_write:
            json.dump(obj_token_json, temp_token_file_write, indent=2)

        temp_filename = temp_token_file.name
        returned_token = utils.get_token(temp_filename)
        assert returned_token == "test-token"

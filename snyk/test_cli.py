import shutil
from unittest.mock import Mock

import delegator  # type: ignore
import pytest  # type: ignore

from .cli import SnykCLI
from .errors import SnykNotFoundError, SnykRunError
from .models import SnykCLIResult


class TestSnykCLI(object):
    @pytest.fixture
    def snyk(self, mocker):
        mocker.patch("shutil.which", return_value="/usr/bin/snyk")

    @pytest.fixture
    def cli(self, snyk):
        return SnykCLI()

    @pytest.fixture
    def cli_with_dir(self, snyk):
        return SnykCLI("/some/other/directory")

    def test_test_method(self, mocker, cli):
        mocker.patch("delegator.run", return_value=Mock(out="[]"))
        cli.test()
        delegator.run.assert_called_once_with("snyk test --json", cwd=".")

    def test_response(self, mocker, cli):
        mocker.patch("delegator.run", return_value=Mock(out="[]"))
        assert isinstance(cli.test(), SnykCLIResult)

    def test_response_raw(self, mocker, cli):
        mocker.patch("delegator.run", return_value=Mock(out="[]"))
        assert cli.test().raw == "[]"

    def test_monitor_method(self, mocker, cli):
        mocker.patch("delegator.run", return_value=Mock(out="[]"))
        cli.monitor()
        delegator.run.assert_called_once_with("snyk monitor --json", cwd=".")

    def test_passing_cwd(self, mocker, cli_with_dir):
        mocker.patch("delegator.run", return_value=Mock(out="[]"))
        cli_with_dir.test()
        delegator.run.assert_called_once_with(
            "snyk test --json", cwd="/some/other/directory"
        )

    def test_error(self, mocker, cli):
        mocker.patch("delegator.run", return_value=Mock(out="not a JSON document"))
        with pytest.raises(SnykRunError):
            cli.test()

    def test_no_snyk(self, mocker, cli):
        mocker.patch("shutil.which", return_value=None)
        with pytest.raises(SnykNotFoundError):
            cli.test()

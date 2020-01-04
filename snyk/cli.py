import json
import shutil
from typing import List, Optional

import attr
import delegator  # type: ignore

from .errors import SnykNotFoundError, SnykRunError
from .models import SnykCLIResult


def _check_for_snyk(func):
    def check(*args, **kwargs):
        if not shutil.which("snyk") is not None:
            raise SnykNotFoundError
        return func(*args, **kwargs)

    return check


@attr.s(auto_attribs=True)
class SnykCLI(object):
    directory: str = "."

    def _run(self, args):
        command = delegator.run(f"snyk {args}".strip(), cwd=self.directory)
        try:
            json.loads(command.out)
        except json.decoder.JSONDecodeError as e:
            raise SnykRunError(command.out) from e
        return SnykCLIResult(raw=command.out)

    @_check_for_snyk
    def test(self, args: List[str] = []):
        args_str = " ".join(args)
        return self._run(f"test --json {args_str}")

    @_check_for_snyk
    def monitor(self, args: List[str] = []):
        args_str = " ".join(args)
        return self._run(f"monitor --json {args_str}")

import pytest  # type: ignore

from snyk.client import SnykClient
from snyk.errors import SnykError
from snyk.managers import Manager
from snyk.models import Organization, Project


class TestManager(object):
    @pytest.fixture
    def client(self):
        return SnykClient("token")

    def test_factory(self, client):
        class NoManager(object):
            pass

        with pytest.raises(SnykError):
            Manager.factory(NoManager, client)

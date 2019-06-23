import pytest  # type: ignore

from snyk.models import *


class TestOrganization(object):
    @pytest.fixture
    def organization(self):
        pass

    def test_members(self, organization):
        pass

    def test_entitlements(self, organization):
        pass

    def test_licenses(self, organization):
        pass


class TestProject(object):
    @pytest.fixture
    def project(self):
        pass

    def test_delete(self, project):
        pass

    def test_issues(self, project):
        pass

    def test_settings(self, project):
        pass

    def test_ignores(self, project):
        pass

    def test_jira_issues(self, project):
        pass

    def test_dependency_graph(self, project):
        pass

    def test_dependencies(self, project):
        pass

    def test_licenses(self, project):
        pass

    def test_update_settings(self, project):
        pass

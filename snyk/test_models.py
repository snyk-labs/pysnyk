import re

import pytest  # type: ignore

from snyk.models import Organization, Project, Member
from snyk.client import SnykClient


class TestModels(object):
    @pytest.fixture
    def organization(self):
        org = Organization(
            name="My Other Org", id="a04d9cbd-ae6e-44af-b573-0556b0ad4bd2"
        )
        org.client = SnykClient("token")
        return org


class TestOrganization(TestModels):
    @pytest.fixture
    def members(self):
        return [
            {"id": "a", "username": "b", "name": "c", "email": "d", "role": "admin"}
        ]

    def test_empty_members(self, organization, requests_mock):
        matcher = re.compile("members$")
        requests_mock.get(matcher, json=[])
        assert [] == organization.members.all()

    def test_members(self, organization, requests_mock, members):
        matcher = re.compile("members$")
        requests_mock.get(matcher, json=members)
        assert 1 == len(organization.members.all())
        assert all(type(x) is Member for x in organization.members.all())
        assert "admin" == organization.members.first().role

    def test_empty_entitlements(self, organization, requests_mock):
        matcher = re.compile("entitlements$")
        requests_mock.get(matcher, json={})
        assert {} == organization.entitlements

    def test_entitlements(self, organization, requests_mock):
        matcher = re.compile("entitlements$")
        output = {"reports": True}
        requests_mock.get(matcher, json=output)
        assert output == organization.entitlements

    def test_empty_licenses(self, organization, requests_mock):
        matcher = re.compile("licenses$")
        requests_mock.post(matcher, json={})
        assert [] == organization.licenses


class TestProject(TestModels):
    @pytest.fixture
    def project(self, organization):
        return Project(
            name="atokeneduser/goof",
            id="6d5813be-7e6d-4ab8-80c2-1e3e2a454545",
            created="2018-10-29T09:50:54.014Z",
            origin="cli",
            type="npm",
            readOnly="false",
            testFrequency="daily",
            totalDependencies=438,
            issueCountsBySeverity={"low": 8, "high": 13, "medium": 15},
            lastTestedDate="2019-02-05T06:21:00.000Z",
            organization=organization,
        )

    def test_delete(self, project, requests_mock):
        requests_mock.delete(
            "https://snyk.io/api/v1/org/a04d9cbd-ae6e-44af-b573-0556b0ad4bd2/project/6d5813be-7e6d-4ab8-80c2-1e3e2a454545"
        )
        assert project.delete()

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

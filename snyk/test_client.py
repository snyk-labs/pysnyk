import re

import pytest  # type: ignore

from snyk import SnykClient
from snyk.__version__ import __version__
from snyk.errors import SnykError, SnykNotFoundError
from snyk.models import Organization, Project


class TestSnykClient(object):
    @pytest.fixture
    def client(self):
        return SnykClient("token")

    def test_default_api_url(self, client):
        assert client.api_url == "https://snyk.io/api/v1"

    def test_overriding_api_url(self):
        url = "https://notsnyk.io/api/v1"
        client = SnykClient("token", url)
        assert client.api_url == url

    def test_token_added_to_headers(self, client):
        assert client.api_headers["Authorization"] == "token token"

    def test_user_agent_added_to_headers(self, client):
        assert client.api_headers["User-Agent"] == "pysnyk/%s" % __version__

    def test_overriding_user_agent(self):
        ua = "test"
        client = SnykClient("token", user_agent=ua)
        assert client.api_headers["User-Agent"] == ua

    def test_token_added_to_post_headers(self, client):
        assert client.api_post_headers["Authorization"] == "token token"

    def test_post_headers_use_correct_mimetype(self, client):
        assert client.api_post_headers["Content-Type"] == "application/json"

    def test_get_sends_request_to_snyk(self, requests_mock, client):
        requests_mock.get("https://snyk.io/api/v1/sample", text="pong")
        assert client.get("sample")

    def test_put_sends_request_to_snyk(self, requests_mock, client):
        requests_mock.put("https://snyk.io/api/v1/sample", text="pong")
        assert client.put("sample", {})

    def test_delete_sends_request_to_snyk(self, requests_mock, client):
        requests_mock.delete("https://snyk.io/api/v1/sample")
        assert client.delete("sample")

    def test_post_sends_request_to_snyk(self, requests_mock, client):
        requests_mock.post("https://snyk.io/api/v1/sample")
        assert client.post("sample", {})
        assert requests_mock.call_count == 1

    def test_post_raises_error(self, requests_mock, client):
        requests_mock.post("https://snyk.io/api/v1/sample", status_code=500, json={})
        with pytest.raises(SnykError):
            client.post("sample", {})
        assert requests_mock.call_count == 1

    def test_put_retries_and_raises_error(self, requests_mock, client):
        requests_mock.put("https://snyk.io/api/v1/sample", status_code=500, json={})
        client = SnykClient("token", tries=4, delay=0, backoff=2)
        with pytest.raises(SnykError):
            client.put("sample", {})
        assert requests_mock.call_count == 4

    def test_delete_retries_and_raises_error(self, requests_mock, client):
        requests_mock.delete("https://snyk.io/api/v1/sample", status_code=500, json={})
        client = SnykClient("token", tries=4, delay=0, backoff=2)
        with pytest.raises(SnykError):
            client.delete("sample")
        assert requests_mock.call_count == 4

    def test_get_retries_and_raises_error(self, requests_mock, client):
        requests_mock.get("https://snyk.io/api/v1/sample", status_code=500, json={})
        client = SnykClient("token", tries=4, delay=0, backoff=2)
        with pytest.raises(SnykError):
            client.get("sample")
        assert requests_mock.call_count == 4

    def test_post_retries_and_raises_error(self, requests_mock, client):
        requests_mock.post("https://snyk.io/api/v1/sample", status_code=500, json={})
        client = SnykClient("token", tries=4, delay=0, backoff=2)
        with pytest.raises(SnykError):
            client.post("sample", {})
        assert requests_mock.call_count == 4

    def test_put_raises_error(self, requests_mock, client):
        requests_mock.put("https://snyk.io/api/v1/sample", status_code=500, json={})
        with pytest.raises(SnykError):
            client.put("sample", {})
        assert requests_mock.call_count == 1

    def test_delete_raises_error(self, requests_mock, client):
        requests_mock.delete("https://snyk.io/api/v1/sample", status_code=500, json={})
        with pytest.raises(SnykError):
            client.delete("sample")
        assert requests_mock.call_count == 1

    def test_get_raises_error(self, requests_mock, client):
        requests_mock.get("https://snyk.io/api/v1/sample", status_code=500, json={})
        with pytest.raises(SnykError):
            client.get("sample")
        assert requests_mock.call_count == 1

    def test_empty_organizations(self, requests_mock, client):
        requests_mock.get("https://snyk.io/api/v1/orgs", json={})
        assert [] == client.organizations.all()

    @pytest.fixture
    def organizations(self):
        return {
            "orgs": [
                {
                    "name": "defaultOrg",
                    "id": "689ce7f9-7943-4a71-b704-2ba575f01089",
                    "group": None,
                    "slug": "default-org",
                    "url": "https://api.snyk.io/org/default-org",
                },
                {
                    "name": "My Other Org",
                    "id": "a04d9cbd-ae6e-44af-b573-0556b0ad4bd2",
                    "group": {
                        "name": "ACME Inc.",
                        "id": "a060a49f-636e-480f-9e14-38e773b2a97f",
                    },
                    "slug": "my-other-org",
                    "url": "https://api.snyk.io/org/my-other-org",
                },
            ]
        }

    @pytest.fixture
    def projects(self):
        return {
            "projects": [
                {
                    "name": "atokeneduser/goof",
                    "id": "6d5813be-7e6d-4ab8-80c2-1e3e2a454545",
                    "created": "2018-10-29T09:50:54.014Z",
                    "origin": "cli",
                    "type": "npm",
                    "readOnly": "false",
                    "isMonitored": "true",
                    "testFrequency": "daily",
                    "totalDependencies": 438,
                    "issueCountsBySeverity": {
                        "critical": 1,
                        "low": 8,
                        "high": 13,
                        "medium": 15,
                    },
                    "lastTestedDate": "2019-02-05T06:21:00.000Z",
                    "browseUrl": "https://app.snyk.io/org/pysnyk-test-org/project/6d5813be-7e6d-4ab8-80c2-1e3e2a454545",
                }
            ]
        }

    def test_loads_organizations(self, requests_mock, client, organizations):
        requests_mock.get("https://snyk.io/api/v1/orgs", json=organizations)
        assert len(client.organizations.all()) == 2

    def test_first_organizations(self, requests_mock, client, organizations):
        requests_mock.get("https://snyk.io/api/v1/orgs", json=organizations)
        org = client.organizations.first()
        assert "defaultOrg" == org.name

    def test_first_organizations_on_empty(self, requests_mock, client):
        requests_mock.get("https://snyk.io/api/v1/orgs", json={})
        with pytest.raises(SnykNotFoundError):
            client.organizations.first()

    def test_filter_organizations(self, requests_mock, client, organizations):
        requests_mock.get("https://snyk.io/api/v1/orgs", json=organizations)
        assert 1 == len(client.organizations.filter(name="defaultOrg"))

    def test_filter_organizations_empty(self, requests_mock, client, organizations):
        requests_mock.get("https://snyk.io/api/v1/orgs", json=organizations)
        assert [] == client.organizations.filter(name="not present")

    def test_loads_organization(self, requests_mock, client, organizations):
        key = organizations["orgs"][0]["id"]
        requests_mock.get("https://snyk.io/api/v1/orgs", json=organizations)
        org = client.organizations.get(key)
        assert "defaultOrg" == org.name

    def test_non_existent_organization(self, requests_mock, client, organizations):
        requests_mock.get("https://snyk.io/api/v1/orgs", json=organizations)
        with pytest.raises(SnykNotFoundError):
            client.organizations.get("not-present")

    def test_organization_type(self, requests_mock, client, organizations):
        requests_mock.get("https://snyk.io/api/v1/orgs", json=organizations)
        assert all(type(x) is Organization for x in client.organizations.all())

    def test_organization_attributes(self, requests_mock, client, organizations):
        requests_mock.get("https://snyk.io/api/v1/orgs", json=organizations)
        assert client.organizations.first().name == "defaultOrg"

    def test_organization_load_group(self, requests_mock, client, organizations):
        requests_mock.get("https://snyk.io/api/v1/orgs", json=organizations)
        assert client.organizations.all()[1].group.name == "ACME Inc."

    def test_empty_projects(self, requests_mock, client, organizations):
        requests_mock.get("https://snyk.io/api/v1/orgs", json=organizations)
        matcher = re.compile("projects$")
        requests_mock.get(matcher, json={})
        assert [] == client.projects.all()

    def test_projects(self, requests_mock, client, organizations, projects):
        requests_mock.get("https://snyk.io/api/v1/orgs", json=organizations)
        matcher = re.compile("projects$")
        requests_mock.get(matcher, json=projects)
        assert len(client.projects.all()) == 2
        assert all(type(x) is Project for x in client.projects.all())

    def test_project(self, requests_mock, client, organizations, projects):
        requests_mock.get("https://snyk.io/api/v1/orgs", json=organizations)
        matcher = re.compile("projects$")
        requests_mock.get(matcher, json=projects)
        assert (
            "atokeneduser/goof"
            == client.projects.get("6d5813be-7e6d-4ab8-80c2-1e3e2a454545").name
        )

    def test_non_existent_project(self, requests_mock, client, organizations, projects):
        requests_mock.get("https://snyk.io/api/v1/orgs", json=organizations)
        matcher = re.compile("projects$")
        requests_mock.get(matcher, json=projects)
        with pytest.raises(SnykNotFoundError):
            client.projects.get("not-present")

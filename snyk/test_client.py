import os
import re

import pytest  # type: ignore

from snyk import SnykClient
from snyk.__version__ import __version__
from snyk.errors import SnykError, SnykNotFoundError
from snyk.models import Organization, Project
from snyk.utils import load_test_data

TEST_DATA = os.path.join(os.path.dirname(__file__), "test_data")

REST_ORG = "39ddc762-b1b9-41ce-ab42-defbe4575bd6"
REST_URL = "https://api.snyk.io/rest"
REST_VERSION = "2022-02-16~experimental"

V3_ORG = "39ddc762-b1b9-41ce-ab42-defbe4575bd6"
V3_URL = "https://api.snyk.io/v3"
V3_VERSION = "2022-02-16~experimental"


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
        return load_test_data(TEST_DATA, "organizations")

    @pytest.fixture
    def projects(self):
        return load_test_data(TEST_DATA, "projects")

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

    @pytest.fixture
    def rest_client(self):
        return SnykClient(
            "token", version="2022-02-16~experimental", url="https://api.snyk.io/rest"
        )

    @pytest.fixture
    def v3_client(self):
        return SnykClient(
            "token", version="2022-02-16~experimental", url="https://api.snyk.io/v3"
        )

    @pytest.fixture
    def v3_groups(self):
        return load_test_data(TEST_DATA, "v3_groups")

    @pytest.fixture
    def v3_targets_page1(self):
        return load_test_data(TEST_DATA, "v3_targets_page1")

    @pytest.fixture
    def v3_targets_page2(self):
        return load_test_data(TEST_DATA, "v3_targets_page2")

    @pytest.fixture
    def v3_targets_page3(self):
        return load_test_data(TEST_DATA, "v3_targets_page3")

    @pytest.fixture
    def rest_groups(self):
        return load_test_data(TEST_DATA, "rest_groups")

    @pytest.fixture
    def rest_targets_page1(self):
        return load_test_data(TEST_DATA, "rest_targets_page1")

    @pytest.fixture
    def rest_targets_page2(self):
        return load_test_data(TEST_DATA, "rest_targets_page2")

    @pytest.fixture
    def rest_targets_page3(self):
        return load_test_data(TEST_DATA, "rest_targets_page3")

    def test_v3get(self, requests_mock, v3_client, v3_targets_page1):
        requests_mock.get(
            f"{V3_URL}/orgs/{V3_ORG}/targets?limit=10&version={V3_VERSION}",
            json=v3_targets_page1,
        )
        t_params = {"limit": 10}

        targets = v3_client.get(f"orgs/{V3_ORG}/targets", t_params).json()

        assert len(targets["data"]) == 10

    def test_get_v3_pages(
        self,
        requests_mock,
        v3_client,
        v3_targets_page1,
        v3_targets_page2,
        v3_targets_page3,
    ):
        requests_mock.get(
            f"{V3_URL}/orgs/{V3_ORG}/targets?limit=10&version={V3_VERSION}",
            json=v3_targets_page1,
        )
        requests_mock.get(
            f"{V3_URL}/orgs/{V3_ORG}/targets?limit=10&version={V3_VERSION}&excludeEmpty=true&starting_after=v1.eyJpZCI6IjMyODE4ODAifQ%3D%3D",
            json=v3_targets_page2,
        )
        requests_mock.get(
            f"{V3_URL}/orgs/{V3_ORG}/targets?limit=10&version={V3_VERSION}&excludeEmpty=true&starting_after=v1.eyJpZCI6IjI5MTk1NjgifQ%3D%3D",
            json=v3_targets_page3,
        )
        t_params = {"limit": 10}

        data = v3_client.get_v3_pages(f"orgs/{V3_ORG}/targets", t_params)

        assert len(data) == 30

    def test_rest_get(self, requests_mock, rest_client, rest_targets_page1):
        requests_mock.get(
            f"{REST_URL}/orgs/{REST_ORG}/targets?limit=10&version={REST_VERSION}",
            json=rest_targets_page1,
        )
        t_params = {"limit": 10}

        targets = rest_client.get(f"orgs/{REST_ORG}/targets", t_params).json()

        assert len(targets["data"]) == 10

    def test_get_rest_pages(
        self,
        requests_mock,
        rest_client,
        rest_targets_page1,
        rest_targets_page2,
        rest_targets_page3,
    ):
        requests_mock.get(
            f"{REST_URL}/orgs/{REST_ORG}/targets?limit=10&version={REST_VERSION}",
            json=rest_targets_page1,
        )
        requests_mock.get(
            f"{REST_URL}/orgs/{REST_ORG}/targets?limit=10&version={REST_VERSION}&excludeEmpty=true&starting_after=v1.eyJpZCI6IjMyODE4ODAifQ%3D%3D",
            json=rest_targets_page2,
        )
        requests_mock.get(
            f"{REST_URL}/orgs/{REST_ORG}/targets?limit=10&version={REST_VERSION}&excludeEmpty=true&starting_after=v1.eyJpZCI6IjI5MTk1NjgifQ%3D%3D",
            json=rest_targets_page3,
        )
        t_params = {"limit": 10}

        data = rest_client.get_rest_pages(f"orgs/{V3_ORG}/targets", t_params)

        assert len(data) == 30

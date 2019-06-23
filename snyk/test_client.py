import pytest  # type: ignore

from snyk import SnykClient
from snyk.errors import SnykError
from snyk.models import Organization


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

    def test_token_added_to_post_headers(self, client):
        assert client.api_post_headers["Authorization"] == "token token"

    def test_post_headers_use_correct_mimetype(self, client):
        assert client.api_post_headers["Content-Type"] == "application/json"

    def test_get_sends_request_to_snyk(self, requests_mock, client):
        requests_mock.get("https://snyk.io/api/v1/sample", text="pong")
        assert client._get("sample")

    def test_put_sends_request_to_snyk(self, requests_mock, client):
        requests_mock.put("https://snyk.io/api/v1/sample", text="pong")
        assert client._put("sample", {})

    def test_delete_sends_request_to_snyk(self, requests_mock, client):
        requests_mock.delete("https://snyk.io/api/v1/sample")
        assert client._delete("sample")

    def test_post_sends_request_to_snyk(self, requests_mock, client):
        requests_mock.post("https://snyk.io/api/v1/sample")
        assert client._post("sample", {})

    def test_post_raises_error(self, requests_mock, client):
        requests_mock.post("https://snyk.io/api/v1/sample", status_code=500, json={})
        with pytest.raises(SnykError):
            client._post("sample", {})

    def test_put_raises_error(self, requests_mock, client):
        requests_mock.put("https://snyk.io/api/v1/sample", status_code=500, json={})
        with pytest.raises(SnykError):
            client._put("sample", {})

    def test_delete_raises_error(self, requests_mock, client):
        requests_mock.delete("https://snyk.io/api/v1/sample", status_code=500, json={})
        with pytest.raises(SnykError):
            client._delete("sample")

    def test_get_raises_error(self, requests_mock, client):
        requests_mock.get("https://snyk.io/api/v1/sample", status_code=500, json={})
        with pytest.raises(SnykError):
            client._get("sample")

    def test_empty_organizations(self, requests_mock, client):
        requests_mock.get("https://snyk.io/api/v1/orgs", json={})
        assert [] == client.organizations

    @pytest.fixture
    def organizations(self):
        return {
            "orgs": [
                {
                    "name": "defaultOrg",
                    "id": "689ce7f9-7943-4a71-b704-2ba575f01089",
                    "group": None,
                },
                {
                    "name": "My Other Org",
                    "id": "a04d9cbd-ae6e-44af-b573-0556b0ad4bd2",
                    "group": {
                        "name": "ACME Inc.",
                        "id": "a060a49f-636e-480f-9e14-38e773b2a97f",
                    },
                },
            ]
        }

    def test_loads_organizations(self, requests_mock, client, organizations):
        requests_mock.get("https://snyk.io/api/v1/orgs", json=organizations)
        assert len(client.organizations) == 2

    def test_organization_type(self, requests_mock, client, organizations):
        requests_mock.get("https://snyk.io/api/v1/orgs", json=organizations)
        assert all(type(x) is Organization for x in client.organizations)

    def test_organization_attributes(self, requests_mock, client, organizations):
        requests_mock.get("https://snyk.io/api/v1/orgs", json=organizations)
        assert client.organizations[0].name == "defaultOrg"

    def test_organization_load_group(self, requests_mock, client, organizations):
        requests_mock.get("https://snyk.io/api/v1/orgs", json=organizations)
        assert client.organizations[1].group.name == "ACME Inc."

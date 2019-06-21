import pytest  # type: ignore

***REMOVED***


class TestSnykClient(object):
    @pytest.fixture
    def client(self):
        return SnykClient("token")

    def test_default_api_url(self, client):
        assert client.api_base_url == "https://snyk.io/api/v1/"

    def test_overriding_api_url(self):
        url = "https://notsnyk.io/api/v1/"
        client = SnykClient("token", url)
        assert client.api_base_url == url

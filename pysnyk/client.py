import json
from pathlib import Path
import requests
from typing import Any, Union, List, Dict

from .models import Organization, Member, Project
from .errors import SnykError


class SnykClient(object):
    def __init__(self, token: str, base_url: str = "https://snyk.io/api/v1/"):
        self.api_base_url = base_url
        self.api_headers = {"Authorization": "token %s" % token}

        self.post_api_headers = self.api_headers
        self.post_api_headers["Content-type"] = "application/json"

    def _requests_do_post_api_return_http_response(
        self, path: str, obj_json_post_body: Any
***REMOVED*** -> requests.Response:
        api_url = "%s/%s" % (self.api_base_url, path)
        resp = requests.post(
            api_url, json=obj_json_post_body, headers=self.post_api_headers
    ***REMOVED***
        if resp.status_code != requests.codes.ok:
            raise SnykError(resp.json())
        return resp

    def _requests_do_put_api_return_http_response(
        self, path: str, obj_json_post_body: Any
***REMOVED*** -> requests.Response:
        api_url = "%s/%s" % (self.api_base_url, path)
        resp = requests.put(
            api_url, json=obj_json_post_body, headers=self.post_api_headers
    ***REMOVED***
        if resp.status_code != requests.codes.ok:
            raise SnykError(resp.json())
        return resp

    def _requests_do_get_return_http_response(self, path: str) -> requests.Response:
        api_url = "%s/%s" % (self.api_base_url, path)
        resp = requests.get(api_url, headers=self.api_headers)
        if resp.status_code != requests.codes.ok:
            raise SnykError(resp.json())
        return resp

    def _requests_do_delete_return_http_response(self, path: str) -> requests.Response:
        api_url = "%s/%s" % (self.api_base_url, path)
        resp = requests.delete(api_url, headers=self.api_headers)
        if resp.status_code != requests.codes.ok:
            raise SnykError(resp.json())
        return resp

    ###########
    # API functions organized per Snyk API Structure
    ###########

    # Groups
    # https://snyk.docs.apiary.io/#reference/0/list-members-in-a-group/list-all-members-in-a-group
    def groups_members(self, group_id: str) -> Any:
        path = "org/%s/members" % group_id
        resp = self._requests_do_get_return_http_response(path)
        obj_json_response_content = resp.json()
        return obj_json_response_content

    # Organizations

    def organizations(self) -> List[Organization]:
        resp = self._requests_do_get_return_http_response("orgs")
        orgs = []
        if "orgs" in resp.json():
            for org_data in resp.json()["orgs"]:
                orgs.append(Organization.from_dict(org_data))
        return orgs

    # Integrations

    def integrations_import(
        self,
        org_id: str,
        integration_id: str,
        github_org: str,
        repo_name: str,
        manifest_files: List[str],
***REMOVED*** -> requests.Response:
        full_api_url = "%sorg/%s/integrations/%s/import" % (
            self.api_base_url,
            org_id,
            integration_id,
    ***REMOVED***

        post_body: Dict[str, Any] = {
            "target": {"owner": github_org, "name": repo_name, "branch": "master"}
        }

        if manifest_files is not None and len(manifest_files) > 0:
            files = []
            for f in manifest_files:
                f_obj = {"path": f}
                files.append(f_obj)

            post_body["files"] = files

        http_response = self._requests_do_post_api_return_http_response(
            full_api_url, post_body
    ***REMOVED***
        return http_response

    # Tests

    # Tests -> test maven
    # https://snyk.docs.apiary.io/#reference/test/maven/test-for-issues-in-a-public-package-by-group-id,-artifact-id-and-version
    def test_maven(
        self, package_group_id: str, package_artifact_id: str, version: str, org_id: str
***REMOVED*** -> Any:
        full_api_url = "%stest/maven/%s/%s/%s?org=%s" % (
            self.api_base_url,
            package_group_id,
            package_artifact_id,
            version,
            org_id,
    ***REMOVED***
        resp = requests.get(full_api_url, headers=self.api_headers)
        obj_json_response_content = resp.json()
        return obj_json_response_content

    # https://snyk.docs.apiary.io/#reference/test/rubygems/test-for-issues-in-a-public-gem-by-name-and-version
    def test_rubygem(self, gem_name: str, gem_version: str, org_id: str) -> Any:
        full_api_url = "%stest/rubygems/%s/%s?org=%s" % (
            self.api_base_url,
            gem_name,
            gem_version,
            org_id,
    ***REMOVED***
        resp = requests.get(full_api_url, headers=self.api_headers)
        obj_json_response_content = resp.json()
        return obj_json_response_content

    # https://snyk.docs.apiary.io/#reference/test/pip/test-for-issues-in-a-public-package-by-name-and-version
    def test_python_package(
        self, package_name: str, package_version: str, org_id: str
***REMOVED*** -> Any:
        full_api_url = "%stest/pip/%s/%s?org=%s" % (
            self.api_base_url,
            package_name,
            package_version,
            org_id,
    ***REMOVED***
        resp = requests.get(full_api_url, headers=self.api_headers)
        obj_json_response_content = resp.json()
        return obj_json_response_content

    # https://snyk.docs.apiary.io/#reference/test/npm/test-for-issues-in-a-public-package-by-name-and-version
    def test_npm_package(
        self, package_name: str, package_version: str, org_id: str
***REMOVED*** -> Any:
        full_api_url = "%stest/npm/%s/%s?org=%s" % (
            self.api_base_url,
            package_name,
            package_version,
            org_id,
    ***REMOVED***
        resp = requests.get(full_api_url, headers=self.api_headers)
        obj_json_response_content = resp.json()
        return obj_json_response_content

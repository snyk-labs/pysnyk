import json
from pathlib import Path
import requests
from typing import Any, Union, List, Dict

from .models import Organization, Member
from .errors import SnykError


class SnykClient(object):
    def __init__(self, token: str, base_url: str = "https://snyk.io/api/v1/"):
        self.api_base_url = base_url
        self.api_headers = {"Authorization": "token %s" % token}

        self.post_api_headers = self.api_headers
        self.post_api_headers["Content-type"] = "application/json"

    def _requests_do_post_api_return_json_object(
        self, api_url: str, obj_json_post_body: Any
***REMOVED*** -> Any:
        resp = requests.post(
            api_url, json=obj_json_post_body, headers=self.post_api_headers
    ***REMOVED***
        if resp.status_code != requests.codes.ok:
            raise SnykError(resp.json())
        return resp.json()

    def _requests_do_post_api_return_http_response(
        self, api_url: str, obj_json_post_body: Any
***REMOVED*** -> requests.Response:
        resp = requests.post(
            api_url, json=obj_json_post_body, headers=self.post_api_headers
    ***REMOVED***
        if resp.status_code != requests.codes.ok:
            raise SnykError(resp.json())
        return resp

    def _requests_do_put_api_return_http_response(
        self, api_url: str, obj_json_post_body: Any
***REMOVED*** -> requests.Response:
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

    def organizations_orgs(self) -> List[Organization]:
        resp = self._requests_do_get_return_http_response("orgs")
        orgs = []
        if "orgs" in resp.json():
            for org_data in resp.json()["orgs"]:
                orgs.append(Organization.from_dict(org_data))
        return orgs

    # https://snyk.docs.apiary.io/#reference/organisations/members-in-organisation/list-members
    def organizations_list_members(self, org_id: str) -> List[Member]:
        path = "org/%s/members" % org_id
        resp = self._requests_do_get_return_http_response(path)
        members = []
        for member_data in resp.json():
            members.append(Member.from_dict(member_data))
        return members

    # Projects

    # Projects -> List All Projects
    # https://snyk.docs.apiary.io/#reference/projects/all-projects/list-all-projects
    def projects_projects(self, org_id: str) -> Any:
        full_api_url = "%sorg/%s/projects" % (self.api_base_url, org_id)
        resp = requests.get(full_api_url, headers=self.api_headers)
        obj_json_response_content = resp.json()
        return obj_json_response_content

    # Projects -> Delete a Project
    # https://snyk.docs.apiary.io/#reference/projects/individual-project/delete-a-project
    def projects_delete(self, org_id: str, project_id: str) -> requests.Response:
        full_api_url = "%sorg/%s/project/%s" % (self.api_base_url, org_id, project_id)
        return requests.delete(full_api_url, headers=self.api_headers)

    # Projects -> List All Issues
    # https://snyk.docs.apiary.io/#reference/projects/project-issues
    # org_id works either like 'demo-applications' or the big hash
    def projects_project_issues(self, org_id: str, project_id: str) -> Any:
        full_api_url = "%sorg/%s/project/%s/issues" % (
            self.api_base_url,
            org_id,
            project_id,
    ***REMOVED***

        post_body = {
            "filters": {
                "severities": ["high", "medium", "low"],
                "types": ["vuln", "license"],
                "ignored": False,
                "patched": False,
            }
        }

        obj_json_response_content = self._requests_do_post_api_return_json_object(
            full_api_url, post_body
    ***REMOVED***

        return obj_json_response_content

    # https://snyk.docs.apiary.io/#reference/projects/project-ignores/list-all-ignores
    def projects_list_all_ignores(self, org_id: str, project_id: str) -> Any:
        full_api_url = "%sorg/%s/project/%s/ignores" % (
            self.api_base_url,
            org_id,
            project_id,
    ***REMOVED***
        resp = requests.get(full_api_url, headers=self.api_headers)
        obj_json_response_content = resp.json()
        return obj_json_response_content

    def projects_project_jira_issues_list_all_jira_issues(
        self, org_id: str, project_id: str
***REMOVED*** -> Any:
        full_api_url = "%sorg/%s/project/%s/jira-issues" % (
            self.api_base_url,
            org_id,
            project_id,
    ***REMOVED***
        resp = requests.get(full_api_url, headers=self.api_headers)
        obj_json_response_content = resp.json()
        # print_json(obj_json_response_content)
        return obj_json_response_content

    def projects_get_product_dependency_graph(
        self, org_id: str, project_id: str
***REMOVED*** -> Any:
        full_api_url = "%sorg/%s/project/%s/dep-graph" % (
            self.api_base_url,
            org_id,
            project_id,
    ***REMOVED***
        resp = requests.get(full_api_url, headers=self.api_headers)
        obj_json_response_content = resp.json()
        return obj_json_response_content

    def projects_update_project_settings(
        self, org_id: str, project_id: str, **kwargs: str
***REMOVED*** -> requests.Response:
        full_api_url = "%sorg/%s/project/%s/settings" % (
            self.api_base_url,
            org_id,
            project_id,
    ***REMOVED***

        post_body = {}

        if "pullRequestTestEnabled" in kwargs:
            post_body["pullRequestTestEnabled"] = kwargs["pullRequestTestEnabled"]

        if "pullRequestFailOnAnyVulns" in kwargs:
            post_body["pullRequestFailOnAnyVulns"] = kwargs["pullRequestFailOnAnyVulns"]

        if "pullRequestFailOnlyForHighSeverity" in kwargs:
            post_body["pullRequestFailOnlyForHighSeverity"] = kwargs[
                "pullRequestFailOnlyForHighSeverity"
            ]

        return self._requests_do_put_api_return_http_response(full_api_url, post_body)

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

    # Dependencies

    # Dependencies -> List All Dependencies
    # https://snyk.docs.apiary.io/#reference/dependencies/dependencies-by-organisation
    def dependencies_list_all_dependencies_by_project(
        self, org_id: str, project_id: str, page: int = 1
***REMOVED*** -> Any:
        results_per_page = 50
        full_api_url = (
            "%sorg/%s/dependencies?sortBy=dependency&order=asc&page=%s&perPage=%s"
            % (self.api_base_url, org_id, page, results_per_page)
    ***REMOVED***
        print(full_api_url)

        post_body = {"filters": {"projects": [project_id]}}

        obj_json_response_content = self._requests_do_post_api_return_json_object(
            full_api_url, post_body
    ***REMOVED***
        total = obj_json_response_content[
            "total"
        ]  # contains the total number of results (for pagination use)
        results = obj_json_response_content["results"]

        if total > (page * results_per_page):
            next_results = self.dependencies_list_all_dependencies_by_project(
                org_id, project_id, page + 1
        ***REMOVED***
            results.extend(next_results)
            return results
        return results

    # Licenses
    # List all licenses (in an org)
    # https://snyk.docs.apiary.io/#reference/licenses/licenses-by-organisation
    def licenses_list_all_licenses_by_org(
        self, org_id: str, project_id: Union[None, str] = None
***REMOVED*** -> Any:
        full_api_url = "%sorg/%s/licenses?sortBy=license&order=asc" % (
            self.api_base_url,
            org_id,
    ***REMOVED***

        post_body: Dict[str, Dict[str, List[str]]] = {"filters": {}}

        if project_id:
            post_body["filters"]["projects"] = [project_id]

        obj_json_response_content = self._requests_do_post_api_return_json_object(
            full_api_url, post_body
    ***REMOVED***
        return obj_json_response_content

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

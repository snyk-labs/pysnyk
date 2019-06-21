import requests
import json
from pathlib import Path


class SnykClient(object):
    def __init__(self, token, base_url="https://snyk.io/api/v1/"):
        self.snyk_api_base_url = base_url
        self.snyk_api_headers = {"Authorization": "token %s" % token}

    def _print_json(self, json_obj):
        print(json.dumps(json_obj, indent=4))

    def _requests_do_post_api_return_json_object(self, api_url, obj_json_post_body):
        snyk_post_api_headers = self.snyk_api_headers
        snyk_post_api_headers["Content-type"] = "application/json"

        resp = requests.post(
            api_url, json=obj_json_post_body, headers=self.snyk_api_headers
        )
        return resp.json()

    def _requests_do_post_api_return_http_response(self, api_url, obj_json_post_body):
        snyk_post_api_headers = self.snyk_api_headers
        snyk_post_api_headers["Content-type"] = "application/json"

        resp = requests.post(
            api_url, json=obj_json_post_body, headers=self.snyk_api_headers
        )
        return resp

    def _requests_do_put_api_return_http_response(self, api_url, obj_json_post_body):
        snyk_post_api_headers = self.snyk_api_headers
        snyk_post_api_headers["Content-type"] = "application/json"

        resp = requests.put(
            api_url, json=obj_json_post_body, headers=self.snyk_api_headers
        )
        return resp

    ###########
    # API functions organized per Snyk API Structure
    ###########

    # Groups
    # https://snyk.docs.apiary.io/#reference/0/list-members-in-a-group/list-all-members-in-a-group
    def snyk_groups_members(self, group_id):
        full_api_url = "%sorg/%s/members" % (self.snyk_api_base_url, group_id)
        resp = requests.get(full_api_url, headers=self.snyk_api_headers)
        obj_json_response_content = resp.json()
        return obj_json_response_content

    # Organizations

    # Organizations -> orgs
    # Lists all Organizations a User belongs to
    # Status: not working - something weird going on where I don't have the permissions to see my orgs
    def snyk_organizations_orgs(self):
        full_api_url = "%sorgs" % (self.snyk_api_base_url)

        print(full_api_url)
        # print(snyk_api_headers)
        # quit()

        print("calling api...")

        resp = requests.get(full_api_url, headers=self.snyk_api_headers)
        obj_json_response_content = resp.json()
        self._print_json(obj_json_response_content)

    # Organizations -> List Members
    # https://snyk.docs.apiary.io/#reference/organisations/members-in-organisation/list-members
    def snyk_organizations_list_members(self, org_id):
        full_api_url = "%sorg/%s/members" % (self.snyk_api_base_url, org_id)
        print(full_api_url)

        resp = requests.get(full_api_url, headers=self.snyk_api_headers)
        obj_json_response_content = resp.json()
        self._print_json(obj_json_response_content)

    # Projects

    # Projects -> List All Projects
    # https://snyk.docs.apiary.io/#reference/projects/all-projects/list-all-projects
    def snyk_projects_projects(self, org_id):
        full_api_url = "%sorg/%s/projects" % (self.snyk_api_base_url, org_id)
        resp = requests.get(full_api_url, headers=self.snyk_api_headers)
        obj_json_response_content = resp.json()
        return obj_json_response_content

    # Projects -> Delete a Project
    # https://snyk.docs.apiary.io/#reference/projects/individual-project/delete-a-project
    def snyk_projects_delete(self, org_id, project_id):
        full_api_url = "%sorg/%s/project/%s" % (
            self.snyk_api_base_url,
            org_id,
            project_id,
        )
        resp = requests.delete(full_api_url, headers=self.snyk_api_headers)
        return resp
        # obj_json_response_content = resp.json()
        # print_json(obj_json_response_content)
        # return obj_json_response_content

    # Projects -> List All Issues
    # https://snyk.docs.apiary.io/#reference/projects/project-issues
    # org_id works either like 'demo-applications' or the big hash
    def snyk_projects_project_issues(self, org_id, project_id):
        full_api_url = "%sorg/%s/project/%s/issues" % (
            self.snyk_api_base_url,
            org_id,
            project_id,
        )
        # print(full_api_url)

        post_body = {
            "filters": {
                "severities": ["high", "medium", "low"],
                "types": ["vuln", "license"],
                "ignored": False,
                "patched": False,
            }
        }

        # json_text = json.dumps(post_body, indent=4)
        # print(json_text)

        # raw_data = '{ "filters": { "severities": ["high","medium","low"], "types": ["vuln","license"], "ignored": false, "patched": false } }'

        obj_json_response_content = self._requests_do_post_api_return_json_object(
            full_api_url, post_body
        )
        # print_json_object(obj_json_response_content)

        json_text = json.dumps(obj_json_response_content, indent=4)

        # with open("response.json", "w") as text_file:
        #     text_file.write(json_text)

        # resp = requests.get(full_api_url, headers=snyk_api_headers)

        # print_json(obj_json_response_content)
        return obj_json_response_content

    # https://snyk.docs.apiary.io/#reference/projects/project-ignores/list-all-ignores
    def snyk_projects_list_all_ignores(self, org_id, project_id):
        full_api_url = "%sorg/%s/project/%s/ignores" % (
            self.snyk_api_base_url,
            org_id,
            project_id,
        )
        resp = requests.get(full_api_url, headers=self.snyk_api_headers)
        obj_json_response_content = resp.json()
        return obj_json_response_content

    def snyk_projects_project_jira_issues_list_all_jira_issues(
        self, org_id, project_id
    ):
        full_api_url = "%sorg/%s/project/%s/jira-issues" % (
            self.snyk_api_base_url,
            org_id,
            project_id,
        )
        resp = requests.get(full_api_url, headers=self.snyk_api_headers)
        obj_json_response_content = resp.json()
        # print_json(obj_json_response_content)
        return obj_json_response_content

    def snyk_projects_get_product_dependency_graph(self, org_id, project_id):
        full_api_url = "%sorg/%s/project/%s/dep-graph" % (
            self.snyk_api_base_url,
            org_id,
            project_id,
        )
        resp = requests.get(full_api_url, headers=self.snyk_api_headers)
        obj_json_response_content = resp.json()
        return obj_json_response_content

    def snyk_projects_update_project_settings(self, org_id, project_id, **kwargs):
        full_api_url = "%sorg/%s/project/%s/settings" % (
            self.snyk_api_base_url,
            org_id,
            project_id,
        )

        post_body = {}

        if "pullRequestTestEnabled" in kwargs:
            post_body["pullRequestTestEnabled"] = kwargs["pullRequestTestEnabled"]

        if "pullRequestFailOnAnyVulns" in kwargs:
            post_body["pullRequestFailOnAnyVulns"] = kwargs["pullRequestFailOnAnyVulns"]

        if "pullRequestFailOnlyForHighSeverity" in kwargs:
            post_body["pullRequestFailOnlyForHighSeverity"] = kwargs[
                "pullRequestFailOnlyForHighSeverity"
            ]

        http_response = self._requests_do_put_api_return_http_response(
            full_api_url, post_body
        )
        return http_response

    # Integrations
    def snyk_integrations_import(
        self, org_id, integration_id, github_org, repo_name, manifest_files
    ):
        full_api_url = "%sorg/%s/integrations/%s/import" % (
            self.snyk_api_base_url,
            org_id,
            integration_id,
        )

        post_body = {
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
        )
        return http_response

    # Dependencies

    # Dependencies -> List All Dependencies
    # https://snyk.docs.apiary.io/#reference/dependencies/dependencies-by-organisation
    def snyk_dependencies_list_all_dependencies_by_project(
        self, org_id, project_id, page=1
    ):
        results_per_page = 50
        full_api_url = (
            "%sorg/%s/dependencies?sortBy=dependency&order=asc&page=%s&perPage=%s"
            % (self.snyk_api_base_url, org_id, page, results_per_page)
        )
        print(full_api_url)

        post_body = {"filters": {"projects": [project_id]}}

        obj_json_response_content = self._requests_do_post_api_return_json_object(
            full_api_url, post_body
        )
        total = obj_json_response_content[
            "total"
        ]  # contains the total number of results (for pagination use)
        results = obj_json_response_content["results"]

        if total > (page * results_per_page):
            next_results = self.snyk_dependencies_list_all_dependencies_by_project(
                org_id, project_id, page + 1
            )
            results.extend(next_results)
            return results
        return results

    # Licenses
    # List all licenses (in an org)
    # https://snyk.docs.apiary.io/#reference/licenses/licenses-by-organisation
    def snyk_licenses_list_all_licenses_by_org(self, org_id, project_id=None):
        full_api_url = "%sorg/%s/licenses?sortBy=license&order=asc" % (
            self.snyk_api_base_url,
            org_id,
        )

        post_body = {"filters": {}}

        if project_id:
            post_body["filters"]["projects"] = [project_id]

        obj_json_response_content = self._requests_do_post_api_return_json_object(
            full_api_url, post_body
        )
        return obj_json_response_content

    # Tests

    # Tests -> test maven
    # https://snyk.docs.apiary.io/#reference/test/maven/test-for-issues-in-a-public-package-by-group-id,-artifact-id-and-version
    def snyk_test_maven(self, package_group_id, package_artifact_id, version, org_id):
        full_api_url = "%stest/maven/%s/%s/%s?org=%s" % (
            self.snyk_api_base_url,
            package_group_id,
            package_artifact_id,
            version,
            org_id,
        )
        resp = requests.get(full_api_url, headers=self.snyk_api_headers)
        obj_json_response_content = resp.json()
        return obj_json_response_content

    # https://snyk.docs.apiary.io/#reference/test/rubygems/test-for-issues-in-a-public-gem-by-name-and-version
    def snyk_test_rubygem(self, gem_name, gem_version, org_id):
        full_api_url = "%stest/rubygems/%s/%s?org=%s" % (
            self.snyk_api_base_url,
            gem_name,
            gem_version,
            org_id,
        )
        resp = requests.get(full_api_url, headers=self.snyk_api_headers)
        obj_json_response_content = resp.json()
        return obj_json_response_content

    # https://snyk.docs.apiary.io/#reference/test/pip/test-for-issues-in-a-public-package-by-name-and-version
    def snyk_test_python_package(self, package_name, package_version, org_id):
        full_api_url = "%stest/pip/%s/%s?org=%s" % (
            self.snyk_api_base_url,
            package_name,
            package_version,
            org_id,
        )
        resp = requests.get(full_api_url, headers=self.snyk_api_headers)
        obj_json_response_content = resp.json()
        return obj_json_response_content

    # https://snyk.docs.apiary.io/#reference/test/npm/test-for-issues-in-a-public-package-by-name-and-version
    def snyk_test_npm_package(self, package_name, package_version, org_id):
        full_api_url = "%stest/npm/%s/%s?org=%s" % (
            self.snyk_api_base_url,
            package_name,
            package_version,
            org_id,
        )
        resp = requests.get(full_api_url, headers=self.snyk_api_headers)
        obj_json_response_content = resp.json()
        return obj_json_response_content

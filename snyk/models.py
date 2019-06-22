from dataclasses import dataclass, field, InitVar
from typing import Optional, List, Dict, Any

import requests
from mashumaro import DataClassJSONMixin  # type: ignore


@dataclass
class Organization(DataClassJSONMixin):
    name: str
    id: str
    client: InitVar[Optional[Any]] = None  # type: ignore

    @property
    def projects(self) -> List["Project"]:
        path = "org/%s/projects" % self.id
        resp = self.client._get(path)
        projects = []
        if "projects" in resp.json():
            for project_data in resp.json()["projects"]:
                project_data["organization"] = self.to_dict()
                projects.append(Project.from_dict(project_data))
        for x in projects:
            x.organization = self
        return projects

    # https://snyk.docs.apiary.io/#reference/organisations/members-in-organisation/list-members
    @property
    def members(self) -> List["Member"]:
        path = "org/%s/members" % self.id
        resp = self.client._get(path)
        members = []
        for member_data in resp.json():
            members.append(Member.from_dict(member_data))
        return members

    # TODO: convert to objects
    # https://snyk.docs.apiary.io/#reference/licenses/licenses-by-organisation
    @property
    def licenses(self) -> requests.Response:
        path = "org/%s/licenses?sortBy=license&order=asc" % self.id
        post_body: Dict[str, Dict[str, List[str]]] = {"filters": {}}
        return self.client._post(path, post_body)

    # TODO: convert to objects
    # https://snyk.docs.apiary.io/#reference/test/maven/test-for-issues-in-a-public-package-by-group-id,-artifact-id-and-version
    def test_maven(
        self, package_group_id: str, package_artifact_id: str, version: str
    ) -> requests.Response:
        path = "test/maven/%s/%s/%s?org=%s" % (
            package_group_id,
            package_artifact_id,
            version,
            self.id,
        )
        return self.client._get(path)

    # TODO: convert to objects
    # https://snyk.docs.apiary.io/#reference/test/rubygems/test-for-issues-in-a-public-gem-by-name-and-version
    def test_rubygem(self, name: str, version: str) -> requests.Response:
        path = "test/rubygems/%s/%s?org=%s" % (name, version, self.id)
        return self.client._get(path)

    # TODO: convert to objects
    # https://snyk.docs.apiary.io/#reference/test/pip/test-for-issues-in-a-public-package-by-name-and-version
    def test_python(self, name: str, version: str) -> requests.Response:
        path = "test/pip/%s/%s?org=%s" % (name, version, self.id)
        return self.client._get(path)

    # TODO: convert to objects
    # https://snyk.docs.apiary.io/#reference/test/npm/test-for-issues-in-a-public-package-by-name-and-version
    def test_npm(self, name: str, version: str) -> requests.Response:
        path = "test/npm/%s/%s?org=%s" % (name, version, self.id)
        return self.client._get(path)


@dataclass
class Member(DataClassJSONMixin):
    id: str
    username: str
    name: str
    email: str
    role: str


@dataclass
class IssueCounts(DataClassJSONMixin):
    low: int
    high: int
    medium: int


@dataclass
class Vulnerability(DataClassJSONMixin):
    id: str
    url: str
    title: str
    type: str
    description: str
    # TODO decode reserved word
    # from is a reserved word in Python, this will need a custom decoder written based on
    # https://github.com/Fatal1ty/mashumaro/blob/master/examples/json_remapping.py
    # from: List[str]
    package: str
    version: str
    severity: str
    language: str
    packageManager: str
    semver: Any
    publicationTime: str
    isUpgradable: bool
    identifiers: Any
    credit: List[str]
    isPatch: Optional[bool] = False
    CVSSv3: Optional[str] = None
    cvssScore: Optional[str] = None
    upgradePath: Optional[List[str]] = None
    disclosureTime: Optional[str] = None


@dataclass
class Issue(DataClassJSONMixin):
    vulnerabilities: List[Vulnerability]
    licenses: List[Any]


@dataclass
class IssueSet(DataClassJSONMixin):
    ok: bool
    packageManager: str
    dependencyCount: int
    issues: Issue


@dataclass
class Project(DataClassJSONMixin):
    name: str
    organization: Organization
    id: str
    created: str
    origin: str
    type: str
    readOnly: bool
    testFrequency: str
    totalDependencies: int
    imageTag: str
    lastTestedDate: str
    issueCountsBySeverity: IssueCounts
    imageId: Optional[str] = None

    def delete(self) -> requests.Response:
        path = "org/%s/project/%s" % (self.organization.id, self.id)
        return self.organization.client._delete(path)

    # https://snyk.docs.apiary.io/#reference/projects/project-issues
    @property
    def issues(self) -> IssueSet:
        path = "org/%s/project/%s/issues" % (self.organization.id, self.id)
        post_body = {
            "filters": {
                "severities": ["high", "medium", "low"],
                "types": ["vuln", "license"],
                "ignored": False,
                "patched": False,
            }
        }
        resp = self.organization.client._post(path, post_body)
        return IssueSet.from_dict(resp.json())

    # TODO: convert to object
    # https://snyk.docs.apiary.io/#reference/projects/project-ignores/list-all-ignores
    @property
    def ignores(self) -> Any:
        path = "org/%s/project/%s/ignores" % (self.organization.id, self.id)
        resp = self.organization.client._get(path)
        return resp.json()

    # TODO: convert to objects
    @property
    def jira_issues(self) -> Any:
        path = "org/%s/project/%s/jira-issues" % (self.organization.id, self.id)
        resp = self.organization.client._get(path)
        return resp.json()

    # TODO: convert to objects
    @property
    def dependency_graph(self) -> Any:
        path = "org/%s/project/%s/dep-graph" % (self.organization.id, self.id)
        resp = self.organization.client._get(path)
        return resp.json()

    # TODO: move pagingation per page value to constant
    # TODO: convert to objects
    # https://snyk.docs.apiary.io/#reference/dependencies/dependencies-by-organisation
    def dependencies(self, page: int = 1) -> Any:
        results_per_page = 50
        path = "org/%s/dependencies?sortBy=dependency&order=asc&page=%s&perPage=%s" % (
            self.organization.id,
            page,
            results_per_page,
        )

        post_body = {"filters": {"projects": [self.id]}}

        resp = self.organization.client._post(path, post_body)
        obj_json_response_content = resp.json()

        total = obj_json_response_content[
            "total"
        ]  # contains the total number of results (for pagination use)
        results = obj_json_response_content["results"]

        if total > (page * results_per_page):
            next_results = self.dependencies(page + 1)
            results.extend(next_results)
            return results
        return results

    # TODO: convert to objects
    # https://snyk.docs.apiary.io/#reference/licenses/licenses-by-organisation
    def licenses(self) -> requests.Response:
        path = "org/%s/licenses?sortBy=license&order=asc" % self.organization.id
        post_body: Dict[str, Dict[str, List[str]]] = {
            "filters": {"projects": [self.id]}
        }
        return self.organization.client._post(path, post_body)

    def update_settings(self, **kwargs: str) -> requests.Response:
        path = "org/%s/project/%s/settings" % (self.organization.id, self.id)
        post_body = {}

        if "pullRequestTestEnabled" in kwargs:
            post_body["pullRequestTestEnabled"] = kwargs["pullRequestTestEnabled"]

        if "pullRequestFailOnAnyVulns" in kwargs:
            post_body["pullRequestFailOnAnyVulns"] = kwargs["pullRequestFailOnAnyVulns"]

        if "pullRequestFailOnlyForHighSeverity" in kwargs:
            post_body["pullRequestFailOnlyForHighSeverity"] = kwargs[
                "pullRequestFailOnlyForHighSeverity"
            ]

        return self.organization.client._put(path, post_body)

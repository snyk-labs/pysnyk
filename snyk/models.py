from dataclasses import dataclass, field, InitVar
from typing import Optional, List, Dict, Any, Union

import requests
from mashumaro import DataClassJSONMixin  # type: ignore

from .errors import SnykError, SnykNotImplementedError
from .managers import Manager
from .utils import snake_to_camel


@dataclass
class OrganizationGroup(DataClassJSONMixin):
    name: str
    id: str


@dataclass
class Organization(DataClassJSONMixin):
    name: str
    id: str
    group: Optional[OrganizationGroup] = None
    client: InitVar[Optional[Any]] = None  # type: ignore

    @property
    def projects(self) -> Manager:
        return Manager.factory(Project, self.client, self)

    @property
    def members(self) -> Manager:
        return Manager.factory(Member, self.client, self)

    @property
    def licenses(self) -> Manager:
        return Manager.factory(License, self.client, self)

    @property
    def entitlements(self) -> Dict[str, bool]:
        path = "org/%s/entitlements" % self.id
        resp = self.client.get(path)
        return resp.json()

    # https://snyk.docs.apiary.io/#reference/entitlements/a-specific-entitlement-by-organisation/get-an-organisation's-entitlement-value
    def entitlement(self, key: str) -> bool:
        raise SnykNotImplementedError

    # https://snyk.docs.apiary.io/#reference/users/user-organisation-notification-settings/modify-org-notification-settings
    # https://snyk.docs.apiary.io/#reference/users/user-organisation-notification-settings/get-org-notification-settings
    def notification_settings(self):
        raise SnykNotImplemented

    # https://snyk.docs.apiary.io/#reference/organisations/the-snyk-organisation-for-a-request/invite-users
    def invite(self, email: str, admin: bool = False):
        raise SnykNotImplementedError

    # TODO: convert to objects
    # https://snyk.docs.apiary.io/#reference/test/maven/test-for-issues-in-a-public-package-by-group-id,-artifact-id-and-version
    def test_maven(
        self, package_group_id: str, package_artifact_id: str, version: str
***REMOVED*** -> requests.Response:
        path = "test/maven/%s/%s/%s?org=%s" % (
            package_group_id,
            package_artifact_id,
            version,
            self.id,
    ***REMOVED***
        return self.client.get(path)

    # TODO: convert to objects
    # https://snyk.docs.apiary.io/#reference/test/rubygems/test-for-issues-in-a-public-gem-by-name-and-version
    def test_rubygem(self, name: str, version: str) -> requests.Response:
        path = "test/rubygems/%s/%s?org=%s" % (name, version, self.id)
        return self.client.get(path)

    # TODO: convert to objects
    # https://snyk.docs.apiary.io/#reference/test/pip/test-for-issues-in-a-public-package-by-name-and-version
    def test_python(self, name: str, version: str) -> requests.Response:
        path = "test/pip/%s/%s?org=%s" % (name, version, self.id)
        return self.client.get(path)

    # TODO: convert to objects
    # https://snyk.docs.apiary.io/#reference/test/npm/test-for-issues-in-a-public-package-by-name-and-version
    def test_npm(self, name: str, version: str) -> requests.Response:
        path = "test/npm/%s/%s?org=%s" % (name, version, self.id)
        return self.client.get(path)

    # https://snyk.docs.apiary.io/#reference/test/pip/test-requirements.txt-file
    def test_pip(self):
        raise SnykNotImplementedError

    # https://snyk.docs.apiary.io/#reference/test/sbt/test-sbt-file
    def test_sbt(self):
        raise SnykNotImplementedError

    # https://snyk.docs.apiary.io/#reference/test/gradle/test-gradle-file
    def test_gradle(self):
        raise SnykNotImplementedError


@dataclass
class LicenseDependency(DataClassJSONMixin):
    id: str
    name: str
    version: str
    packageManager: str


@dataclass
class LicenseProject(DataClassJSONMixin):
    id: str
    name: str


@dataclass
class License(DataClassJSONMixin):
    id: str
    dependencies: List[LicenseDependency]
    projects: List[LicenseProject]


@dataclass
class Member(DataClassJSONMixin):
    id: str
    username: str
    name: str
    email: str
    role: str

    # https://snyk.docs.apiary.io/#reference/organisations/manage-roles-in-organisation/update-a-member-in-the-organisation
    def update_role(self, role: str):
        raise SnykNotImplementedError

    # https://snyk.docs.apiary.io/#reference/organisations/manage-roles-in-organisation/remove-a-member-from-the-organisation
    def delete(self):
        raise SnykNotImplementedError


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
    # TODO: define type for license issue
    licenses: List[Any]


@dataclass
class IssueSet(DataClassJSONMixin):
    ok: bool
    packageManager: str
    dependencyCount: int
    issues: Issue


@dataclass
class DependencyGraphPackageInfo(DataClassJSONMixin):
    name: str
    version: str


@dataclass
class DependencyGraphPackage(DataClassJSONMixin):
    id: str
    info: DependencyGraphPackageInfo


@dataclass
class Node(DataClassJSONMixin):
    nodeId: str
    pkgId: str
    deps: List[Dict[str, str]]


@dataclass
class Graph(DataClassJSONMixin):
    rootNodeId: str
    nodes: List[Node]


@dataclass
class DependencyGraph(DataClassJSONMixin):
    schemaVersion: str
    pkgManager: Dict[str, str]
    pkgs: List[DependencyGraphPackage]
    graph: Graph


@dataclass
class DependencyLicense(DataClassJSONMixin):
    id: str
    title: str
    license: str


@dataclass
class DependencyProject(DataClassJSONMixin):
    name: str
    id: str


@dataclass
class Dependency(DataClassJSONMixin):
    id: str
    name: str
    version: str
    latestVersion: str
    latestVersionPublishedDate: str
    firstPublishedData: str
    isDeprecated: bool
    deprecatedVersions: List[str]
    licenses: List[DependencyLicense]
    dependenciesWithIssues: List[str]
    packageManager: str
    projects: List[DependencyProject]


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
    lastTestedDate: str
    issueCountsBySeverity: IssueCounts
    imageTag: Optional[str] = None
    imageId: Optional[str] = None

    def delete(self) -> bool:
        path = "org/%s/project/%s" % (self.organization.id, self.id)
        if self.organization.client.delete(path):
            return True
        else:
            raise SnykError

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
        resp = self.organization.client.post(path, post_body)
        return IssueSet.from_dict(resp.json())

    @property
    def settings(self) -> Dict[str, Any]:
        path = "org/%s/project/%s/settings" % (self.organization.id, self.id)
        resp = self.organization.client.get(path)
        return resp.json()

    # https://snyk.docs.apiary.io/#reference/projects/project-ignores/list-all-ignores
    @property
    def ignores(self) -> Dict[str, List[object]]:
        path = "org/%s/project/%s/ignores" % (self.organization.id, self.id)
        resp = self.organization.client.get(path)
        return resp.json()

    @property
    def jira_issues(self) -> Dict[str, List[object]]:
        path = "org/%s/project/%s/jira-issues" % (self.organization.id, self.id)
        resp = self.organization.client.get(path)
        return resp.json()

    @property
    def dependency_graph(self) -> DependencyGraph:
        path = "org/%s/project/%s/dep-graph" % (self.organization.id, self.id)
        resp = self.organization.client.get(path)
        dependency_data = resp.json()
        return DependencyGraph.from_dict(dependency_data)

    # https://snyk.docs.apiary.io/#reference/dependencies/dependencies-by-organisation
    @property
    def dependencies(self) -> Manager:
        return Manager.factory(Dependency, self.client, self)

    # https://snyk.docs.apiary.io/#reference/licenses/licenses-by-organisation
    @property
    def licenses(self) -> Manager:
        return Manager.factory(License, self.client, self)

    def update_settings(self, **kwargs: str) -> bool:
        path = "org/%s/project/%s/settings" % (self.organization.id, self.id)
        post_body = {}

        settings = [
            "pull_request_test_enabled",
            "pull_request_fail_on_vuln",
            "pull_request_fail_only_fo-high_severity",
        ]

        for setting in settings:
            if settings in kwargs:
                post_body[snake_to_camel(settings)] = kwargs[setting]

        if self.organization.client.put(path, post_body):
            return True
        else:
            raise SnykError

    # https://snyk.docs.apiary.io/#reference/users/user-project-notification-settings/modify-project-notification-settings
    # https://snyk.docs.apiary.io/#reference/users/user-project-notification-settings/get-project-notification-settings
    def notification_settings(self):
        raise SnykNotImplementedError

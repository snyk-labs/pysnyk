import base64
from dataclasses import dataclass, field, InitVar
from typing import Optional, List, Dict, Any, Union

import requests
from mashumaro import DataClassJSONMixin  # type: ignore

from .errors import SnykError, SnykNotImplementedError
from .managers import Manager
from .utils import snake_to_camel


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
    def entitlements(self) -> Manager:
        return Manager.factory("Entitlement", self.client, self)

    # https://snyk.docs.apiary.io/#reference/users/user-organisation-notification-settings/modify-org-notification-settings
    # https://snyk.docs.apiary.io/#reference/users/user-organisation-notification-settings/get-org-notification-settings
    def notification_settings(self):
        raise SnykNotImplemented

    # https://snyk.docs.apiary.io/#reference/organisations/the-snyk-organisation-for-a-request/invite-users
    def invite(self, email: str, admin: bool = False):
        raise SnykNotImplementedError

    def _test(self, path, contents=None):
        if contents:
            # Check for a file-like object, allows us to support files
            # and strings in the same interface
            read = getattr(contents, "read", None)
            if callable(read):
                contents = contents.read()
            encoded = base64.b64encode(contents.encode()).decode()
            post_body = {
                "encoding": "base64",
                "files": {"target": {"contents": encoded}},
            }
            resp = self.client.post(path, post_body)
        else:
            resp = self.client.get(path)
        if resp:
            return IssueSet.from_dict(resp.json())
        else:
            raise SnykError

    # https://snyk.docs.apiary.io/#reference/test/maven/test-for-issues-in-a-public-package-by-group-id,-artifact-id-and-version
    def test_maven(
        self, package_group_id: str, package_artifact_id: str, version: str
    ) -> IssueSet:
        path = "test/maven/%s/%s/%s?org=%s" % (
            package_group_id,
            package_artifact_id,
            version,
            self.id,
        )
        return self._test(path)

    # https://snyk.docs.apiary.io/#reference/test/rubygems/test-for-issues-in-a-public-gem-by-name-and-version
    def test_rubygem(self, name: str, version: str) -> IssueSet:
        path = "test/rubygems/%s/%s?org=%s" % (name, version, self.id)
        return self._test(path)

    # https://snyk.docs.apiary.io/#reference/test/pip/test-for-issues-in-a-public-package-by-name-and-version
    def test_python(self, name: str, version: str) -> bool:
        path = "test/pip/%s/%s?org=%s" % (name, version, self.id)
        return self._test(path)

    # https://snyk.docs.apiary.io/#reference/test/npm/test-for-issues-in-a-public-package-by-name-and-version
    def test_npm(self, name: str, version: str) -> bool:
        path = "test/npm/%s/%s?org=%s" % (name, version, self.id)
        return self._test(path)

    # https://snyk.docs.apiary.io/#reference/test/pip/test-requirements.txt-file
    def test_pipfile(self, contents):
        path = "test/pip?org=%s" % self.id
        return self._test(path, contents)

    def test_gemfilelock(self, contents):
        path = "test/rubygems?org=%s" % self.id
        return self._test(path, contents)

    def test_packagejson(self, contents):
        path = "test/npm?org=%s" % self.id
        return self._test(path, contents)

    def test_gradlefile(self, contents):
        path = "test/gradle?org=%s" % self.id
        return self._test(path, contents)

    def test_sbt(self):
        path = "test/sbt?org=%s" % self.id
        return self._test(path, contents)

    def test_pom(self):
        path = "test/maven?org=%s" % self.id
        return self._test(path, contents)


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
        raise SnykError

    @property
    def settings(self) -> Manager:
        return Manager.factory("Setting", self.organization.client, self)

    # https://snyk.docs.apiary.io/#reference/projects/project-ignores/list-all-ignores
    @property
    def ignores(self) -> Manager:
        return Manager.factory("Ignore", self.organization.client, self)

    @property
    def jira_issues(self) -> Manager:
        return Manager.factory("JiraIssue", self.organization.client, self)

    # https://snyk.docs.apiary.io/#reference/dependencies/dependencies-by-organisation
    @property
    def dependencies(self) -> Manager:
        return Manager.factory(Dependency, self.organization.client, self)

    # https://snyk.docs.apiary.io/#reference/licenses/licenses-by-organisation
    @property
    def licenses(self) -> Manager:
        return Manager.factory(License, self.organization.client, self)

    @property
    def licenses(self) -> Manager:
        return Manager.factory(DependencyGraph, self.organization.client, self)

    # https://snyk.docs.apiary.io/#reference/projects/project-issues
    @property
    def issues(self) -> Manager:
        return Manager.factory(IssueSet, self.organization.client, self)

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

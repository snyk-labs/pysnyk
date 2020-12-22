import base64
from dataclasses import InitVar, dataclass, field
from typing import Any, Dict, List, Optional, Union

import requests
from mashumaro import DataClassJSONMixin  # type: ignore

from .errors import SnykError, SnykNotImplementedError
from .managers import Manager


@dataclass
class Vulnerability(DataClassJSONMixin):
    id: str
    url: str
    title: str
    description: str
    upgradePath: List[str]
    package: str
    version: str
    severity: str
    exploitMaturity: str
    isUpgradable: bool
    isPatchable: bool
    identifiers: Any
    semver: Any
    fromPackages: List[str] = field(default_factory=list)
    language: Optional[str] = None
    packageManager: Optional[str] = None
    publicationTime: Optional[str] = None
    priorityScore: Optional[int] = None
    disclosureTime: Optional[str] = None
    credit: Optional[List[Any]] = field(default_factory=list)
    CVSSv3: Optional[str] = None
    cvssScore: Optional[str] = None
    ignored: Optional[List[Any]] = field(default_factory=list)
    patched: Optional[List[Any]] = field(default_factory=list)


@dataclass
class LicenseIssue(DataClassJSONMixin):
    id: str
    url: str
    title: str
    package: str
    version: str
    severity: str
    fromPackages: List[str] = field(default_factory=list)
    # Although mentioned in the schema as required, currently not returned.
    isIgnored: Optional[bool] = None
    # Although mentioned in the schema as required, currently not returned.
    isPatched: Optional[bool] = None
    language: Optional[str] = None
    priorityScore: Optional[int] = None
    packageManager: Optional[str] = None
    ignored: Optional[List[Any]] = field(default_factory=list)
    patched: Optional[List[Any]] = field(default_factory=list)


@dataclass
class Issue(DataClassJSONMixin):
    vulnerabilities: List[Vulnerability]
    licenses: List[LicenseIssue]


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
    def dependencies(self) -> Manager:
        return Manager.factory(Dependency, self.client, self)

    @property
    def entitlements(self) -> Manager:
        return Manager.factory("Entitlement", self.client, self)

    @property
    def integrations(self) -> Manager:
        return Manager.factory(Integration, self.client, self)

    """
    Imports need integrations, but exposing a high-level API that
    can find the integration from the URL of the thing you want
    to import should make things simpler. This is currently only
    supported for GitHub as an example. If this works nicely then
    extending the list of integrations, adding support for branches
    and files, and better errors, would be required.
    """

    def import_project(self, url, files: Optional[List[str]] = None) -> bool:
        try:
            components = url.split("/")
            service = components[0]
            if service == "github.com":
                owner = components[1]
                name = components[2]
                parts = name.split("@")
                branch = "master"
                if len(parts) == 2:
                    name = parts[0]
                    branch = parts[1]
            elif service == "docker.io":
                name = "/".join(components[1:])
            else:
                raise SnykNotImplementedError

        except ValueError:
            raise SnykError
        try:
            integrations = {"github.com": "github", "docker.io": "docker-hub"}
            integration_name = integrations[service]
        except KeyError:
            raise SnykError
        try:
            if service == "docker.io":
                return self.integrations.filter(name=integration_name)[0].import_image(
                    name
                )
            else:
                integration = self.integrations.filter(name=integration_name)[0]

                if files:
                    return integration.import_git(owner, name, branch, files)
                else:
                    return integration.import_git(owner, name, branch)

        except KeyError:
            raise SnykError

    # https://snyk.docs.apiary.io/#reference/users/user-organisation-notification-settings/modify-org-notification-settings
    # https://snyk.docs.apiary.io/#reference/users/user-organisation-notification-settings/get-org-notification-settings
    def notification_settings(self):
        raise SnykNotImplemented  # pragma: no cover

    # https://snyk.docs.apiary.io/#reference/organisations/the-snyk-organisation-for-a-request/invite-users
    def invite(self, email: str, admin: bool = False) -> bool:
        path = "org/%s/invite" % self.id
        payload = {"email": email, "isAdmin": admin}
        return bool(self.client.post(path, payload))

    def _test(self, path, contents=None, additional=None):
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

            # Some test methods carry a second file, often a lock file
            if additional:
                read = getattr(additional, "read", None)
                if callable(read):
                    additional = additional.read()
                encoded = base64.b64encode(additional.encode()).decode()
                post_body["files"]["additional"] = {"contents": encoded}

            resp = self.client.post(path, post_body)
        else:
            resp = self.client.get(path)
        return IssueSet.from_dict(resp.json())

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

    def test_rubygem(self, name: str, version: str) -> IssueSet:
        path = "test/rubygems/%s/%s?org=%s" % (name, version, self.id)
        return self._test(path)

    def test_python(self, name: str, version: str) -> bool:
        path = "test/pip/%s/%s?org=%s" % (name, version, self.id)
        return self._test(path)

    def test_npm(self, name: str, version: str) -> bool:
        path = "test/npm/%s/%s?org=%s" % (name, version, self.id)
        return self._test(path)

    def test_pipfile(self, contents):
        path = "test/pip?org=%s" % self.id
        return self._test(path, contents)

    def test_gemfilelock(self, contents):
        path = "test/rubygems?org=%s" % self.id
        return self._test(path, contents)

    def test_packagejson(self, contents, lock=None):
        path = "test/npm?org=%s" % self.id
        return self._test(path, contents, lock)

    def test_gradlefile(self, contents):
        path = "test/gradle?org=%s" % self.id
        return self._test(path, contents)

    def test_sbt(self, contents):
        path = "test/sbt?org=%s" % self.id
        return self._test(path, contents)

    def test_pom(self, contents):
        path = "test/maven?org=%s" % self.id
        return self._test(path, contents)

    def test_composer(self, contents, lock):
        path = "test/composer?org=%s" % self.id
        return self._test(path, contents, lock)

    def test_yarn(self, contents, lock):
        path = "test/yarn?org=%s" % self.id
        return self._test(path, contents, lock)


@dataclass
class Integration(DataClassJSONMixin):
    name: str
    id: str
    organization: Optional[Organization] = None

    @property
    def settings(self):
        if not self.organization:
            raise SnykError
        return Manager.factory("IntegrationSetting", self.organization.client, self)

    def _import(self, payload) -> bool:
        if not self.organization:
            raise SnykError
        path = "org/%s/integrations/%s/import" % (self.organization.id, self.id)
        return bool(self.organization.client.post(path, payload))

    def import_git(
        self, owner: str, name: str, branch: str = "master", files: List[str] = []
    ):
        return self._import(
            {
                "target": {"owner": owner, "name": name, "branch": branch},
                "files": [{"path": x} for x in files],
            }
        )

    def import_image(self, name: str):
        if ":" not in name:
            name = "%s:latest" % name
        return self._import({"target": {"name": name}})

    def import_gitlab(self, id: str, branch: str = "master", files: List[str] = []):
        return self._import(
            {
                "target": {"id": id, "branch": branch},
                "files": [{"path": x} for x in files],
            }
        )

    def import_bitbucket(
        self, project_key: str, name: str, repo_slug: str, files: List[str] = []
    ):
        return self._import(
            {
                "target": {
                    "projectKey": project_key,
                    "name": name,
                    "repoSlug": repo_slug,
                },
                "files": [{"path": x} for x in files],
            }
        )

    def import_heroku(self, app_id: str, slug_id: str, files: List[str] = []):
        return self._import(
            {
                "target": {"appId": app_id, "slugId": slug_id},
                "files": [{"path": x} for x in files],
            }
        )

    def import_lambda(self, function_id: str, files: List[str] = []):
        return self._import(
            {
                "target": {"functionId": function_id},
                "files": [{"path": x} for x in files],
            }
        )

    def import_cloudfoundry(self, app_id: str, files: List[str] = []):
        return self._import(
            {"target": {"appId": app_id}, "files": [{"path": x} for x in files]}
        )


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
    severity: Optional[str] = None


@dataclass
class Member(DataClassJSONMixin):
    id: str
    username: str
    name: str
    email: str
    role: str

    # https://snyk.docs.apiary.io/#reference/organisations/manage-roles-in-organisation/update-a-member-in-the-organisation
    def update_role(self, role: str):
        raise SnykNotImplementedError  # pragma: no cover

    # https://snyk.docs.apiary.io/#reference/organisations/manage-roles-in-organisation/remove-a-member-from-the-organisation
    def delete(self):
        raise SnykNotImplementedError  # pragma: no cover


@dataclass
class IssueCounts(DataClassJSONMixin):
    low: int
    high: int
    medium: int


@dataclass
class DependencyGraphPackageInfo(DataClassJSONMixin):
    name: str
    version: Optional[str] = None


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
    licenses: List[DependencyLicense]
    projects: List[DependencyProject]
    latestVersion: Optional[str] = None
    latestVersionPublishedDate: Optional[str] = None
    firstPublishedDate: Optional[str] = None
    isDeprecated: Optional[bool] = None
    type: Optional[str] = None
    deprecatedVersions: Optional[List[Any]] = field(default_factory=list)
    dependenciesWithIssues: Optional[List[Any]] = field(default_factory=list)


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
    browseUrl: str
    isMonitored: bool
    issueCountsBySeverity: IssueCounts
    imageTag: Optional[str] = None
    imageId: Optional[str] = None
    imageBaseImage: Optional[str] = None
    imagePlatform: Optional[str] = None
    imageCluster: Optional[str] = None
    hostname: Optional[str] = None
    remoteRepoUrl: Optional[str] = None
    branch: Optional[str] = None
    _tags: Optional[List[Any]] = field(default_factory=list)
    _attributes: Optional[Dict[Any,Any]] = field(default_factory=dict)

    def delete(self) -> bool:
        path = "org/%s/project/%s" % (self.organization.id, self.id)
        return bool(self.organization.client.delete(path))

    @property
    def settings(self) -> Manager:
        return Manager.factory("Setting", self.organization.client, self)

    @property
    def ignores(self) -> Manager:
        return Manager.factory("Ignore", self.organization.client, self)

    @property
    def jira_issues(self) -> Manager:
        return Manager.factory("JiraIssue", self.organization.client, self)

    @property
    def dependencies(self) -> Manager:
        return Manager.factory(Dependency, self.organization.client, self)

    @property
    def licenses(self) -> Manager:
        return Manager.factory(License, self.organization.client, self)

    @property
    def dependency_graph(self) -> DependencyGraph:
        return Manager.factory(DependencyGraph, self.organization.client, self).all()

    @property
    def issueset(self) -> Manager:
        return Manager.factory(IssueSet, self.organization.client, self)

    @property
    def vulnerabilities(self) -> List[Vulnerability]:
        return self.issueset.all().issues.vulnerabilities

    @property
    def tags(self) -> Manager:
        return Manager.factory("Tag", self.organization.client, self)

    @property
    def attributes(self) -> Manager:
        return Manager.factory("Attribute", self.organization.client, self)

    # https://snyk.docs.apiary.io/#reference/users/user-project-notification-settings/modify-project-notification-settings
    # https://snyk.docs.apiary.io/#reference/users/user-project-notification-settings/get-project-notification-settings
    def notification_settings(self):
        raise SnykNotImplementedError  # pragma: no cover

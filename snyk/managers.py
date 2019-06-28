import abc
from typing import List, Any, Dict

from .errors import SnykError, SnykNotFoundError, SnykNotImplementedError


class Manager(abc.ABC):
    def __init__(self, klass, client, instance=None):
        self.klass = klass
        self.client = client
        self.instance = instance

    @abc.abstractmethod
    def all(self):
        pass  # pragma: no cover

    def get(self, id: str):
        try:
            return next(x for x in self.all() if x.id == id)
        except StopIteration:
            raise SnykNotFoundError

    def first(self):
        try:
            return self.all()[0]
        except IndexError:
            raise SnykNotFoundError

    def filter(self, **kwargs: Any):
        data = self.all()
        if kwargs:
            for key, value in kwargs.items():
                data = [x for x in data if getattr(x, key) == value]
        return data

    @staticmethod
    def factory(klass, client, instance=None):
        try:
            if isinstance(klass, str):
                key = klass
            else:
                key = klass.__name__
            manager = {
                "Project": ProjectManager,
                "Organization": OrganizationManager,
                "Member": MemberManager,
                "License": LicenseManager,
                "Dependency": DependencyManager,
                "Entitlement": EntitlementManager,
                "Setting": SettingManager,
                "Ignore": IgnoreManager,
                "JiraIssue": JiraIssueManager,
                "DependencyGraph": DependencyGraphManager,
                "Issue": IssueManager,
            }[key]
            return manager(klass, client, instance)
        except KeyError:
            raise SnykError


class DictManager(Manager):
    @abc.abstractmethod
    def all(self) -> Dict[str, Any]:
        pass

    def get(self, id: str):
        try:
            self.all()[id]
        except KeyError:
            raise SnykNotFoundError

    def filter(self, **kwargs: Any):
        raise SnykNotImplementedError

    def first(self):
        try:
            next(iter(self.all().items()))
        except StopIteration:
            raise SnykNotFoundError


class SingletonManager(Manager):
    @abc.abstractmethod
    def all(self) -> Any:
        pass

    def first(self):
        raise SnykNotImplementedError

    def get(self, id: str):
        raise SnykNotImplementedError

    def filter(self, **kwargs: Any):
        raise SnykNotImplementedError


class OrganizationManager(Manager):
    def all(self):
        resp = self.client.get("orgs")
        orgs = []
        if "orgs" in resp.json():
            for org_data in resp.json()["orgs"]:
                orgs.append(self.klass.from_dict(org_data))
        for org in orgs:
            org.client = self.client
        return orgs


class ProjectManager(Manager):
    def all(self):
        projects = []
        if self.instance:
            path = "org/%s/projects" % self.instance.id
            resp = self.client.get(path)
            if "projects" in resp.json():
                for project_data in resp.json()["projects"]:
                    project_data["organization"] = self.instance.to_dict()
                    projects.append(self.klass.from_dict(project_data))
            for x in projects:
                x.organization = self.instance
        else:
            for org in self.client.organizations.all():
                projects.extend(org.projects.all())
        return projects


class MemberManager(Manager):
    def all(self):
        path = "org/%s/members" % self.instance.id
        resp = self.client.get(path)
        members = []
        for member_data in resp.json():
            members.append(self.klass.from_dict(member_data))
        return members


class LicenseManager(Manager):
    def all(self):
        if hasattr(self.instance, "organization"):
            path = "org/%s/licenses" % self.instance.organization.id
            post_body = {"filters": {"projects": [self.instance.id]}}
        else:
            path = "org/%s/licenses" % self.instance.id
            post_body: Dict[str, Dict[str, List[str]]] = {"filters": {}}

        resp = self.client.post(path, post_body)
        license_data = resp.json()
        licenses = []
        if "results" in license_data:
            for license in license_data["results"]:
                licenses.append(self.klass.from_dict(license))
        return licenses


class DependencyManager(Manager):
    def all(self, page: int = 1):
        results_per_page = 50
        path = "org/%s/dependencies?sortBy=dependency&order=asc&page=%s&perPage=%s" % (
            self.instance.organization.id,
            page,
            results_per_page,
        )

        post_body = {"filters": {"projects": [self.instance.id]}}

        resp = self.client.post(path, post_body)
        dependency_data = resp.json()

        total = dependency_data[
            "total"
        ]  # contains the total number of results (for pagination use)
        results = dependency_data["results"]

        if total > (page * results_per_page):
            next_results = self.all(page + 1)
            results.extend(next_results)
            return results

        dependencies = []
        for dependency_data in results:
            dependencies.append(self.klass.from_dict(dependency_data))
        return dependencies


class EntitlementManager(DictManager):
    def all(self) -> Dict[str, bool]:
        path = "org/%s/entitlements" % self.instance.id
        resp = self.client.get(path)
        return resp.json()


class SettingManager(DictManager):
    def all(self) -> Dict[str, Any]:
        path = "org/%s/project/%s/settings" % (
            self.instance.organization.id,
            self.instance.id,
        )
        resp = self.client.get(path)
        return resp.json()


class IgnoreManager(DictManager):
    def all(self) -> Dict[str, List[object]]:
        path = "org/%s/project/%s/ignores" % (
            self.instance.organization.id,
            self.instance.id,
        )
        resp = self.client.get(path)
        return resp.json()


class JiraIssueManager(DictManager):
    def all(self) -> Dict[str, List[object]]:
        path = "org/%s/project/%s/jira-issues" % (
            self.instance.organization.id,
            self.instance.id,
        )
        resp = self.client.get(path)
        return resp.json()


class DependencyGraphManager(SingletonManager):
    def all(self) -> Any:
        path = "org/%s/project/%s/dep-graph" % (
            self.instance.organization.id,
            self.instance.id,
        )
        resp = self.client.get(path)
        dependency_data = resp.json()
        return self.klass.from_dict(dependency_data)


class IssueManager(SingletonManager):
    def all(self) -> Any:
        path = "org/%s/project/%s/issues" % (
            self.instance.organization.id,
            self.instance.id,
        )
        post_body = {
            "filters": {
                "severities": ["high", "medium", "low"],
                "types": ["vuln", "license"],
                "ignored": False,
                "patched": False,
            }
        }
        resp = self.client.post(path, post_body)
        return self.klass.from_dict(resp.json())

    def filter(self, **kwargs: Any):
        path = "org/%s/project/%s/issues" % (
            self.instance.organization.id,
            self.instance.id,
        )
        filters = {}
        for filter_name in ["severity"]:
            if kwargs.get(filter_name):
                filters[filter_name] = kwargs[filter_name]
        post_body = {"filters": filters}
        resp = self.client.post(path, post_body)
        return self.klass.from_dict(resp.json())

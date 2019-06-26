import inspect
from typing import List, Any

from .errors import SnykError, SnykNotFoundError


class Manager(object):
    def __init__(self, klass, client, instance=None):
        self.klass = klass
        self.client = client
        self.instance = instance

    def all(self):
        return []

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
            manager = {
                "Project": ProjectManager,
                "Organization": OrganizationManager,
                "Member": MemberManager,
                "License": LicenseManager,
                "Dependency": DependencyManager,
            }[klass.__name__]
            return manager(klass, client, instance)
        except KeyError:
            raise SnykError


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


def DependencyManager(Manager):
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

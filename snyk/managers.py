import abc
from typing import Any, Dict, List

from .errors import SnykError, SnykNotFoundError, SnykNotImplementedError
from .utils import snake_to_camel


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

    def _filter_by_kwargs(self, data, **kwargs: Any):
        if kwargs:
            for key, value in kwargs.items():
                data = [x for x in data if getattr(x, key) == value]
        return data

    def filter(self, **kwargs: Any):
        return self._filter_by_kwargs(self.all(), **kwargs)

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
                "IssueSet": IssueSetManager,
                "Integration": IntegrationManager,
                "IntegrationSetting": IntegrationSettingManager,
                "Tag": TagManager,
                "Attribute": AttributeManager,
            }[key]
            return manager(klass, client, instance)
        except KeyError:
            raise SnykError


class DictManager(Manager):
    @abc.abstractmethod
    def all(self) -> Dict[str, Any]:
        pass  # pragma: no cover

    def get(self, id: str):
        try:
            return self.all()[id]
        except KeyError:
            raise SnykNotFoundError

    def filter(self, **kwargs: Any):
        raise SnykNotImplementedError

    def first(self):
        try:
            return next(iter(self.all().items()))
        except StopIteration:
            raise SnykNotFoundError


class SingletonManager(Manager):
    @abc.abstractmethod
    def all(self) -> Any:
        pass  # pragma: no cover

    def first(self):
        raise SnykNotImplementedError  # pragma: no cover

    def get(self, id: str):
        raise SnykNotImplementedError  # pragma: no cover

    def filter(self, **kwargs: Any):
        raise SnykNotImplementedError  # pragma: no cover


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


class TagManager(Manager):
    def all(self):
        return self.instance._tags

    def add(self, key, value) -> bool:
        tag = {"key": key, "value": value}
        path = "org/%s/project/%s/tags" % (
            self.instance.organization.id,
            self.instance.id,
        )
        return bool(self.client.post(path, tag))

    def delete(self, key, value) -> bool:
        tag = {"key": key, "value": value}
        path = "org/%s/project/%s/tags/remove" % (
            self.instance.organization.id,
            self.instance.id,
        )
        return bool(self.client.post(path, tag))


class AttributeManager(Manager):
    def all(self):
        return self.instance._attributes.copy()

    def criticality(self):
        return self.all()["criticality"]

    def environment(self):
        return self.all()["environment"]

    def lifecycle(self):
        return self.all()["lifecycle"]

    def set(self, criticality: str = None, environment: str = None, lifecycle: str =None) -> bool:
        attributes = self.all()
        if criticality:
            attributes["criticality"] = [criticality]

        if environment:
            attributes["environment"] = [environment]

        if lifecycle:
            attributes["lifecycle"] = [lifecycle]

        path = "org/%s/project/%s/attributes" % (
            self.instance.organization.id,
            self.instance.id,
        )
        return bool(self.client.post(path, attributes))

    # TODO: These returns a 404, is it possible that the endpoint only works toward the shotname? Ie backend-g95?
    # def add(self, attribute, value) -> bool:
    #     data = {"attribute": attribute, "value": value}
    #     path = "org/%s/project/%s/attribute/add" % (
    #         self.instance.organization.id,
    #         self.instance.id,
    #     )
    #     return bool(self.client.post(path, data))
    #
    # def delete(self, attribute, value) -> bool:
    #     data = {"attribute": attribute, "value": value}
    #     path = "org/%s/project/%s/attribute/remove" % (
    #         self.instance.organization.id,
    #         self.instance.id,
    #     )
    #     return bool(self.client.post(path, data))


class ProjectManager(Manager):
    def _query(self, tags: List[Dict[str, str]] = []):
        projects = []
        if self.instance:
            path = "org/%s/projects" % self.instance.id
            if tags:
                for tag in tags:
                    if "key" not in tag or "value" not in tag or len(tag.keys()) != 2:
                        raise SnykError("Each tag must contain only a key and a value")
                data = {"filters": {"tags": {"includes": tags}}}
                resp = self.client.post(path, data)
            else:
                resp = self.client.get(path)
            if "projects" in resp.json():
                for project_data in resp.json()["projects"]:
                    project_data["organization"] = self.instance.to_dict()
                    # We move tags to _tags as a cache, to avoid the need for additional requests
                    # when working with tags. We want tags to be the manager
                    try:
                        project_data["_tags"] = project_data["tags"]
                        del project_data["tags"]
                    except KeyError:
                        pass

                    try:
                        project_data["_attributes"] = project_data["attributes"].copy()
                        del project_data["attributes"]
                    except KeyError:
                        pass

                    projects.append(self.klass.from_dict(project_data))
            for x in projects:
                x.organization = self.instance
        else:
            for org in self.client.organizations.all():
                projects.extend(org.projects.all())
        return projects

    def all(self):
        return self._query()

    def filter(self, tags: List[Dict[str, str]] = [], **kwargs: Any):
        if tags:
            return self._filter_by_kwargs(self._query(tags), **kwargs)
        else:
            return super().filter(**kwargs)

    def get(self, id: str):
        if self.instance:
            path = "org/%s/project/%s" % (self.instance.id, id)
            resp = self.client.get(path)
            project_data = resp.json()
            project_data["organization"] = self.instance.to_dict()
            project_klass = self.klass.from_dict(project_data)
            project_klass.organization = self.instance
            return project_klass
        else:
            return super().get(id)


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
        if hasattr(self.instance, "organization"):
            org_id = self.instance.organization.id
            post_body = {"filters": {"projects": [self.instance.id]}}
        else:
            org_id = self.instance.id
            post_body = {"filters": {}}

        path = "org/%s/dependencies?sortBy=dependency&order=asc&page=%s&perPage=%s" % (
            org_id,
            page,
            results_per_page,
        )

        resp = self.client.post(path, post_body)
        dependency_data = resp.json()

        total = dependency_data[
            "total"
        ]  # contains the total number of results (for pagination use)

        results = [self.klass.from_dict(item) for item in dependency_data["results"]]

        if total > (page * results_per_page):
            next_results = self.all(page + 1)
            results.extend(next_results)

        return results


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

    def update(self, **kwargs: bool) -> bool:
        path = "org/%s/project/%s/settings" % (
            self.instance.organization.id,
            self.instance.id,
        )
        post_body = {}

        settings = [
            "pull_request_test_enabled",
            "pull_request_fail_on_vuln",
            "pull_request_fail_only_for_high_severity",
        ]

        for setting in settings:
            if setting in kwargs:
                post_body[snake_to_camel(setting)] = kwargs[setting]

        return bool(self.client.put(path, post_body))


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

    def create(self, issue_id: str, fields: Any) -> Dict[str, str]:
        path = "org/%s/project/%s/issue/%s/jira-issue" % (
            self.instance.organization.id,
            self.instance.id,
            issue_id,
        )
        post_body = {"fields": fields}
        resp = self.client.post(path, post_body)
        response_data = resp.json()
        # The response we get is not following the schema as specified by the api
        # https://snyk.docs.apiary.io/#reference/projects/project-jira-issues-/create-jira-issue
        if (
            issue_id in response_data
            and len(response_data[issue_id]) > 0
            and "jiraIssue" in response_data[issue_id][0]
        ):
            return response_data[issue_id][0]["jiraIssue"]
        raise SnykError


class IntegrationManager(Manager):
    def all(self):
        path = "org/%s/integrations" % self.instance.id
        resp = self.client.get(path)
        integrations = []
        integrations_data = [{"name": x, "id": resp.json()[x]} for x in resp.json()]
        for data in integrations_data:
            integrations.append(self.klass.from_dict(data))
        for integration in integrations:
            integration.organization = self.instance
        return integrations


class IntegrationSettingManager(DictManager):
    def all(self):
        path = "org/%s/integrations/%s/settings" % (
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
        if "depGraph" in dependency_data:
            return self.klass.from_dict(dependency_data["depGraph"])
        raise SnykError


class IssueSetManager(SingletonManager):
    def _convert_reserved_words(self, data):
        for key in ["vulnerabilities", "licenses"]:
            if "issues" in data and key in data["issues"]:
                for i, vuln in enumerate(data["issues"][key]):
                    if "from" in vuln:
                        data["issues"][key][i]["fromPackages"] = data["issues"][key][
                            i
                        ].pop("from")
        return data

    def all(self) -> Any:
        return self.filter()

    def filter(self, **kwargs: Any):
        path = "org/%s/project/%s/issues" % (
            self.instance.organization.id,
            self.instance.id,
        )
        filters = {
            "severities": ["high", "medium", "low"],
            "types": ["vuln", "license"],
            "ignored": False,
            "patched": False,
        }
        for filter_name in filters.keys():
            if kwargs.get(filter_name):
                filters[filter_name] = kwargs[filter_name]
        post_body = {"filters": filters}
        resp = self.client.post(path, post_body)
        return self.klass.from_dict(self._convert_reserved_words(resp.json()))

import abc
import logging
import json
from typing import Any, Dict, List
from requests.compat import urljoin

from deprecation import deprecated  # type: ignore

from .errors import SnykError, SnykNotFoundError, SnykNotImplementedError, SnykHTTPError
from .utils import snake_to_camel

logger = logging.getLogger(__name__)

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
                "Project":            ProjectManager,
                "Organization":       OrganizationManager,
                "Member":             MemberManager,
                "License":            LicenseManager,
                "Dependency":         DependencyManager,
                "Entitlement":        EntitlementManager,
                "Setting":            SettingManager,
                "Ignore":             IgnoreManager,
                "JiraIssue":          JiraIssueManager,
                "DependencyGraph":    DependencyGraphManager,
                "IssueSet":           IssueSetManager,
                "IssueSetAggregated": IssueSetAggregatedManager,
                "Integration":        IntegrationManager,
                "IntegrationSetting": IntegrationSettingManager,
                "Tag":                TagManager,
                "IssuePaths":         IssuePathsManager,
                "OrganizationGroup":  OrganizationGroupManager,
                "User":               UserManager,
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
        params = {'limit': self.client.params['limit']}
        resp = self.client.get_rest_pages("/orgs", params)
        
        orgs = []
        if len(resp) > 0:

            groups = self.client.groups.all()

            for org in resp:

                try:
                    group = next(x for x in groups if x.id == org['attributes']['group_id']).to_dict()
                except StopIteration:
                    group = None

                # Map org data to model variables
                org_template = {
                    'name':  org['attributes']['name'],
                    'id': org['id'],
                    'slug': org['attributes']['slug'],
                    'url': urljoin(self.client.web_url, '/org/{}'.format(org['attributes']['slug'])),
                    'personal': org['attributes']['is_personal'],
                    'group': group,
                    'client': self.client
                }
                
                orgs.append(self.klass.from_dict(org_template))

        return orgs

    def get(self, id: str):
        try:
            org = self.client.get_rest_page("/orgs/{}".format(id))

            org_template = {
                    'name':  org['attributes']['name'],
                    'id': org['id'],
                    'slug': org['attributes']['slug'],
                    'url': urljoin(self.client.web_url, '/org/{}'.format(org['attributes']['slug'])),
                    'personal': org['attributes']['is_personal'],
                    'group': self.client.groups.get(org['attributes']['group_id']).to_dict() if 'group_id' in org['attributes'].keys() else None,
                    'client': self.client
                }
        except SnykHTTPError as e:
            logging.error(e.error)
            raise e
        except Exception as e:
            logging.error(e)
            raise e

        return self.klass.from_dict(org_template)

class OrganizationGroupManager(Manager):
    def all(self):
        params = {'limit': self.client.params['limit']}
        resp = self.client.get_rest_pages("/groups", params)

        groups = []
        if len(resp) > 0:
            for group in resp:
                groups.append(self.klass.from_dict({'name': group['attributes']['name'], 'id': group['id']}))

        return groups

    def first(self):
        raise SnykNotImplementedError  # pragma: no cover
    
    def get(self, id: str):
        try:
            resp = self.client.get_rest_page("/groups/{}".format(id))
        except SnykHTTPError as e:
            if e.error[0]['detail'] == "Group Not Found":
                logging.error("Group Not Found")
                raise SnykNotFoundError from None
            elif e.error[0]['detail'] == 'must match format "uuid"':
                logging.error("ID must match format 'uuid'")
                raise e
            else:
                raise e
        except Exception as e:
            raise e

        return self.klass(resp['attributes']['name'],resp['id'])


    def filter(self, **kwargs: Any):
       raise SnykNotImplementedError  # pragma: no cover


class TagManager(Manager):
    def all(self):
        return self.instance._tags

    def add(self, key, value) -> bool:

        path = "orgs/%s/projects/%s" % (
            self.instance.organization.id,
            self.instance.id,
        )
        
        # Retain previous tags
        tags = self.instance._tags
        tags.append({'key':key, 'value':value})

        # Build the request body
        body = {
            "data": { 
            "attributes":{
                "tags":tags
            },
            "relationships":{}, 
            "id":self.instance.id, 
            "type": "project"
            }
        }

        params = {'user_id': self.instance.organization.client.users.self.id}
        headers = {'content-type': 'application/vnd.api+json'}
        return bool(self.client.patch(path=path, body=body, params=params, headers=headers))

    def delete(self, key, value) -> bool:
        tag = {"key": key, "value": value}
        path = "org/%s/project/%s/tags/remove" % (
            self.instance.organization.id,
            self.instance.id,
        )
        return bool(self.client.post(path, tag))

class UserManager(Manager):
    
    def all(self) -> Any:
        pass  # pragma: no cover
    
    def first(self):
        raise SnykNotImplementedError  # pragma: no cover

    def get(self, id: str):
        raise SnykNotImplementedError  # pragma: no cover

    def filter(self, **kwargs: Any):
        raise SnykNotImplementedError  # pragma: no cover
      
    @property
    def self(self):
        user = self.client.get_rest_page("/self")
        user_data = {'id': user['id']}
        fields = ['name','username','email']
        for field in fields:
            if field in user['attributes']:
                user_data[field] = user['attributes'][field]
        return self.klass.from_dict(user_data)
    
# TODO: change implementation here to call REST Projects and other V1 APIs to fill in the gaps as per
# migration guide https://docs.google.com/document/d/1e-CnYRYxZXBRCRFW8YZ8tfKkv5zLSg2tEHPiLrvO8Oc
# Since the implementation uses filtering by tags, use an older API version that has this available https://apidocs.snyk.io/?version=2022-07-08%7Ebeta#get-/orgs/-org_id-/projects
# See annotations on the class snyk/models.py#L451-L452 for what data needs to be fetched from elsewhere or constructed
class ProjectManager(Manager):
    #def _query(self, tags: List[Dict[str, str]] = []):
    def _query(self, params: dict = {}):
        projects = []
        if self.instance:
            if 'limit' not in params.keys():
                params['limit'] = self.client.params['limit']
                
            path = "orgs/%s/projects" % self.instance.id
            resp = self.client.get_rest_pages(path, params)

            for project in resp:
                attributes = project['attributes']

                project_data = {
                    'name':            attributes['name'],
                    'id':              project['id'],
                    'created':         attributes['created'],
                    'origin':          attributes['origin'],
                    'type':            attributes['type'],
                    'readOnly':        attributes['read_only'],
                    'testFrequency':   attributes['settings']['recurring_tests']['frequency'],
                    'browseUrl':       urljoin(self.instance.url,'/project/{}'.format(id)),
                    'isMonitored':     attributes['status'] if attributes['status'] == 'active' else False,
                    'targetReference': attributes['target_reference'],
                    'organization':    self.instance.to_dict(),
                    '_tags':           attributes['tags'] if 'tags' in attributes.keys() else [],
                    'attributes':      {'criticality': attributes['business_criticality'], 
                                        'environment': attributes['environment'], 
                                        'lifecycle':   attributes['lifecycle']},
                }

                project_klass = self.klass.from_dict(project_data)

                projects.append(project_klass)
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
            path = "orgs/%s/projects/%s" % (self.instance.id, id)
            resp = self.client.get_rest_page(path)
            attributes = resp['attributes']
            
            project_data = {
                'name':            attributes['name'],
                'id':              resp['id'],
                'created':         attributes['created'],
                'origin':          attributes['origin'],
                'type':            attributes['type'],
                'readOnly':        attributes['read_only'],
                'testFrequency':   attributes['settings']['recurring_tests']['frequency'],
                'browseUrl':       urljoin(self.instance.url,'/project/{}'.format(id)),
                'isMonitored':     attributes['status'] if attributes['status'] == 'active' else False,
                'targetReference': attributes['target_reference'],
                'organization':    self.instance.to_dict(),
                '_tags':           attributes['tags'] if 'tags' in attributes.keys() else [],
                'attributes':      {'criticality': attributes['business_criticality'], 
                                    'environment': attributes['environment'], 
                                    'lifecycle':   attributes['lifecycle']},
            }

            project_klass = self.klass.from_dict(project_data)
            
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
        results_per_page = 1000
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
            "auto_dep_upgrade_enabled",
            "auto_dep_upgrade_ignored_dependencies",
            "auto_dep_upgrade_min_age",
            "auto_dep_upgrade_limit",
            "pull_request_fail_on_any_vulns",
            "pull_request_fail_only_for_high_severity",
            "pull_request_test_enabled",
            "pull_request_assignment",
            "pull_request_inheritance",
            "pull_request_fail_only_for_issues_with_fix",
            "auto_remediation_prs",
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


@deprecated("API has been removed, use IssueSetAggregatedManager instead")
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
            "severities": ["critical", "high", "medium", "low"],
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


class IssueSetAggregatedManager(SingletonManager):
    def all(self) -> Any:
        return self.filter()

    def filter(self, **kwargs: Any):
        path = "org/%s/project/%s/aggregated-issues" % (
            self.instance.organization.id,
            self.instance.id,
        )
        default_filters = {
            "severities": ["critical", "high", "medium", "low"],
            "exploitMaturity": [
                "mature",
                "proof-of-concept",
                "no-known-exploit",
                "no-data",
            ],
            "types": ["vuln", "license"],
            "priority": {"score": {"min": 0, "max": 1000}},
        }

        post_body = {"filters": default_filters}

        all_filters = list(default_filters.keys()) + ["ignored", "patched"]
        for filter_name in all_filters:
            if filter_name in kwargs.keys():
                post_body["filters"][filter_name] = kwargs[filter_name]

        for optional_field in ["includeDescription", "includeIntroducedThrough"]:
            if optional_field in kwargs.keys():
                post_body[optional_field] = kwargs[optional_field]

        resp = self.client.post(path, post_body)
        return self.klass.from_dict(resp.json())


class IssuePathsManager(SingletonManager):
    def all(self):
        path = "org/%s/project/%s/issue/%s/paths" % (
            self.instance.organization_id,
            self.instance.project_id,
            self.instance.id,
        )
        resp = self.client.get(path)
        return self.klass.from_dict(resp.json())

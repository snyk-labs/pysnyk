import abc
import logging
import json
from typing import Any, Dict, List
from requests.compat import urljoin
from copy import deepcopy

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
                "Project":               ProjectManager,
                "Organization":          OrganizationManager,
                "Member":                MemberManager,
                "License":               LicenseManager,
                "Dependency":            DependencyManager,
                "Entitlement":           EntitlementManager,
                "Setting":               SettingManager,
                "Ignore":                IgnoreManager,
                "JiraIssue":             JiraIssueManager,
                "DependencyGraph":       DependencyGraphManager,
                "IssueSet":              IssueSetManager,
                "IssueSetAggregated":    IssueSetAggregatedManager2,
                "Integration":           IntegrationManager,
                "IntegrationSetting":    IntegrationSettingManager,
                "Tag":                   TagManager,
                "IssuePaths":            IssuePathsManager,
                "OrganizationGroup":     OrganizationGroupManager,
                "OrganizationGroupTags": OrganizationGroupTagManager,
                "User":                  UserManager,
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
        params = {'limit': self.client.limit}
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

class OrganizationGroupTagManager(Manager):
    def all(self):
        # Version 1 endpoint
        self.client.api_url = self.client.API_URL_V1

        resp = self.client.get(f'/group/{self.instance.id}/tags?perPage=50000&page=1')

        # Reset to REST endpoint
        self.client.api_url = self.client.API_URL
        
        return resp.json()['tags']

    def delete(self,key: str, value: str, force: bool=False) -> bool:
        # Version 1 endpoint
        self.client.api_url = self.client.API_URL_V1
        
        body = {'key':   key,
                'value': value,
                'force': force}
        
        resp = self.client.post(f'/group/{self.instance.id}/tags/delete', body)

        # Reset to REST endpoint
        self.client.api_url = self.client.API_URL

        if resp.status_code == 200:
            return True
        else:
            return False

class OrganizationGroupManager(Manager):
    def all(self):
        params = {'limit': self.client.limit}
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

        return self.klass(resp['attributes']['name'],resp['id'],self.client)


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
        tag = {"key": key, "value": value}
        tags = self.instance._tags
        tags.append(tag)

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

        resp = self.client.patch(path=path, body=body, params=params, headers=headers).json()

        # Check to make sure the new tag was created
        if tag in resp['data']['attributes']['tags']:
            return True

        return False

    def delete(self, key, value) -> bool:
        path = "orgs/%s/projects/%s" % (
            self.instance.organization.id,
            self.instance.id,
        )

        tag = {"key": key, "value": value}
        tags = [ x for x in self.instance._tags if x != tag ]

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

        resp = self.client.patch(path=path, body=body, params=params, headers=headers).json()

        # Check to make sure the tag was deleted
        if tag in resp['data']['attributes']['tags']:
            return False

        return True

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
    def _map_rest_data_to_project_model(self, data: dict = {}):
        """Takes the data field from a rest API query for the /orgs/{org_id}/projects/{project_id} query and maps it to the Project model

        :param data: dictionary data field from a rest API call to /orgs/{org_id}/projects/{project_id}

        :return: Project model"""

        attr = data['attributes']

        # Mandetory flags
        project_data = {
            'name':            attr['name'],
            'id':              data['id'],
            'created':         attr['created'],
            'origin':          attr['origin'],
            'type':            attr['type'],
            'readOnly':        attr['read_only'],
            'testFrequency':   attr['settings']['recurring_tests']['frequency'],
            'browseUrl':       f"{self.instance.url}/project/{data['id']}",
            'isMonitored':     attr['status'] if attr['status'] == 'active' else False,
            'targetReference': attr['target_reference'],
            'organization':    self.instance.to_dict(),
            'attributes':      {'criticality': attr['business_criticality'], 
                                'environment': attr['environment'], 
                                'lifecycle':   attr['lifecycle']},
        }
        #            '_tags':           attr['tags'] if 'tags' in attr.keys() else [],

        # Optional flags
        for key in data.keys():
            if 'attributes' == key:
                for attribute in data['attributes']:
                    if 'tags' == attribute:
                        project_data['_tags'] = attr['tags']

            if 'meta' == key:
                if 'latest_dependency_total' in data['meta'].keys():
                    total = data['meta']['latest_dependency_total']['total']
                    if total:
                        project_data['totalDependencies'] = total
                    else:
                        project_data['totalDependencies'] = 0
                if 'latest_issue_counts' in data['meta'].keys():
                    project_data['issueCountsBySeverity'] = {
                        'critical': int(data['meta']['latest_issue_counts']['critical']),
                        'high': int(data['meta']['latest_issue_counts']['high']),
                        'medium': int(data['meta']['latest_issue_counts']['medium']),
                        'low': int(data['meta']['latest_issue_counts']['low']),
                    }

        return self.klass.from_dict(project_data)

    def filter(self, **kwargs: Any):
        """This functions allows you to filter using all of the filters available on https://apidocs.snyk.io/experimental?version=2023-07-28%7Eexperimental#tag--Projects
        Then returns the project dictionaries in a list

        The list of parameters below are a list of of available filters from version=2023-07-28~experimental as of 7/31/2023
        
        :param target_id: List of strings (target IDs)    
            Return projects that belong to the provided targets
        :param meta_count: string - Allowed: "only"        
            Only return the collection count
        :param ids: List of strings (Project IDs)   
            Return projects that match the provided IDs
        :param names: List of strings (Project names) 
            Return projects that match the provided names
        :param origins: List of strings (origins)       
            Return projects that match the provided origins
        :param types: List of strings (project types) 
            Return projects that match the provided types
        :param expand: string - Allowed: "target"      
            Expand relationships
        :param latest_issue_counts: bool              
            Include a summary count for the issues found in the most recent scan of this project
        :param latest_dependency_total: bool
            Include the total number of dependencies found in the most recent scan of this project
        :param cli_monitored_before: date-time - Example: 2021-05-29T09:50:54.014Z       
            Filter projects uploaded and monitored before this date (encoded value) 
        :param cli_monitored_after: date-time  - Example: 2021-05-29T09:50:54.014Z
            Filter projects uploaded and monitored after this date (encoded value)
        :param importing_user_public_id: List of strings   
            Return projects that match the provided importing user public ids.
        :param tags: List of strings (tags) - List of dict() - Example: [{'key':'test_key', 'value':'test_value'}]
            Return projects that match all the provided tags
        :param business_criticality: List of strings - Allowed: critical ┃ high ┃ medium ┃ low
            Return projects that match all the provided business_criticality value
        :param environment: List of strings - Allowed: frontend ┃ backend ┃ internal ┃ external ┃ mobile ┃ saas ┃ onprem ┃ hosted ┃ distributed
            Return projects that match all the provided environment values
        :param lifecycle: List of strings - Allowed: production ┃ development ┃ sandbox
            Return projects that match all the provided lifecycle values
        :param version: string - The requested version of the endpoint to process the request
        :param starting_after: string - Examples: v1.eyJpZCI6IjEwMDAifQo=
            Return the page of results immediately after this cursor
        :param ending_before: string - Examples: v1.eyJpZCI6IjExMDAifQo=
            Return the page of results immediately before this cursor
        :param limit: int - Default: 10 (Min: 10, Max: 100, only multiples of 10 allowed)
            Number of results to return per page

        :return: returns a list of dictionaries. One dictionary for each project included in the query.
        """

        filters = {
            'meta.latest_issue_counts': True,
            'meta.latest_dependency_total': True,
        }

        filters_list = [
            "target_id",
            "meta_count",
            "ids",
            "names",
            "origins",
            "types",
            "expand: string - Allowed",
            "latest_issue_counts",
            "latest_dependency_total",
            "cli_monitored_before",
            "cli_monitored_after",
            "importing_user_public_id",
            "tags",
            "business_criticality",
            "environment",
            "lifecycle",
            "version",
            "starting_after",
            "ending_before",
            "limit",
        ]
        
        filters_list.extend(list(filters.keys()))

        # Set new filters
        for filter_name in kwargs.keys():
            if filter_name in filters_list:
                # map variable name to api parameter name
                if filter_name in ["latest_issue_counts","latest_dependency_total"] :
                    filters[f"meta.{filter_name}"] = kwargs[filter_name]
                else:
                    filters[filter_name] = kwargs[filter_name]

        #TODO: Add validation for every parameter to make sure
        # They're each formatted correctly.

        if 'limit' not in filters.keys():
            filters['limit'] = self.client.limit
                
        path = "orgs/%s/projects" % self.instance.id
        
        resp = self.client.get_rest_pages(path, filters)

        return resp

    def query(self, **kwargs: Any):
        """Utility to query data from the api and return a list of project data models"""
        if self.instance:
            projects = []
            resp = self.filter(**kwargs)
            for project in resp:
                projects.append(self._map_rest_data_to_project_model(project))
            return projects
        else:
            return super().get(**kwargs)

    def get(self, id: str):
        """legacy get method for backward compatibility"""
        
        if self.instance:
            resp = self.filter(ids=[id])
            return self._map_rest_data_to_project_model(resp[0])
        else:
            return super().get(id)

    def all(self):
        projects = []
        if self.instance:
            resp = self.filter()
            for project in resp:
                model = self._map_rest_data_to_project_model(project)
                projects.append(model)
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
        # Version 1 endpoint
        self.client.api_url = self.client.API_URL_V1

        path = "org/%s/project/%s/ignores" % (
            self.instance.organization.id,
            self.instance.id,
        )
        resp = self.client.get(path)

        # Reset to REST endpoint
        self.client.api_url = self.client.API_URL
        return resp.json()



class JiraIssueManager(DictManager):
    def all(self) -> Dict[str, List[object]]:
        # Version 1 endpoint
        self.client.api_url = self.client.API_URL_V1

        path = "org/%s/project/%s/jira-issues" % (
            self.instance.organization.id,
            self.instance.id,
        )
        resp = self.client.get(path)

        # Reset to REST endpoint
        self.client.api_url = self.client.API_URL
        
        return resp.json()

    def create(self, issue_id: str, fields: Any) -> Dict[str, str]:
        # Version 1 endpoint
        self.client.api_url = self.client.API_URL_V1

        path = "org/%s/project/%s/issue/%s/jira-issue" % (
            self.instance.organization.id,
            self.instance.id,
            issue_id,
        )
        post_body = {"fields": fields}
        resp = self.client.post(path, post_body)
        response_data = resp.json()

        # Reset to REST endpoint
        self.client.api_url = self.client.API_URL
        
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

    def all(self) -> Any:
        self._query()


class IssueSetAggregatedManager2(SingletonManager):
    """
    TODO: Update the Issue model to match the latest changes to API
    def _map_rest_data_to_issue_model(self, data: dict = {}):
        '''
        Lets map what we can, then set the rest to optional
        Things to map:

        # Mapped
        id: str
        issueType: str
        isIgnored: bool

        # Not Mapped
        pkgName: str
        pkgVersions: List[str]
        isPatched: bool
        fixInfo: FixInfo
        introducedThrough: Optional[List[Any]] = None
        ignoreReasons: Optional[List[Any]] = None
        # Not mentioned in schema but returned
        # https://snyk.docs.apiary.io/#reference/projects/aggregated-project-issues/list-all-aggregated-issues
        priorityScore: Optional[int] = None
        priority: Optional[Any] = None

        issueData: IssueData
            # issueData fields to map
            ## Mapped
            id: str
            title: str
            severity: str
            url: str

            ## Unmapped
            exploitMaturity: str
            description: Optional[str] = None
            identifiers: Optional[Any] = None
            credit: Optional[List[str]] = None
            semver: Optional[Any] = None
            publicationTime: Optional[str] = None
            disclosureTime: Optional[str] = None
            CVSSv3: Optional[str] = None
            cvssScore: Optional[str] = None
            language: Optional[str] = None
            patches: Optional[Any] = None
            nearestFixedInVersion: Optional[str] = None
            ignoreReasons: Optional[List[Any]] = None

        '''

        # Map the required items
        attr = data['attributes']
        issue_data = {
            'id': attr['key'], # This appears to be what Snyk is using for the id and not the actual ID for "package_vulnerability" type issues
            'issueType': attr['type'],
            'title': attr['title'],
            'description': "", # Need to get details from somewhere else
            'issueData': {
                'id': attr['key']
                'title': attr['title']
                'severity': attr['effective_severity_level']
                exploitMaturity: str
                description: Optional[str] = None
                identifiers: Optional[Any] = None
                credit: Optional[List[str]] = None
                semver: Optional[Any] = None
                publicationTime: Optional[str] = None
                disclosureTime: Optional[str] = None
                CVSSv3: Optional[str] = None
                cvssScore: Optional[str] = None
                language: Optional[str] = None
                patches: Optional[Any] = None
                nearestFixedInVersion: Optional[str] = None
                ignoreReasons: Optional[List[Any]] = None
            },
            'isIgnored': attr['ignored'],

        }

        # Calling object is a Project
        if hasattr(self.instance, 'organization'):
            # Generate URL
            issue_data['issueData']['url'] = f"{self.instance.browseUrl}#issue-{attr['key']}"

        # Calling object is an Organization
        else:
            issue_data['issueData']['url'] = f"{self.instance.url}/project/{data['relationships']['scan_item']['id']}#issue-{attr['key']}"
    """
    def filter(self, **kwargs: Any):

        filters = {}
        if 'limit' not in filters.keys():
            filters['limit'] = self.client.limit
        
        # Calling object is a Project
        if hasattr(self.instance, 'organization'):
            filters['scan_item.id'] = self.instance.id
            filters['scan_item.type'] = 'project'

            path = f"orgs/{self.instance.organization.id}/issues"

        # Calling object is an Organization
        else:
            path = f"orgs/{self.instance.id}/issues"
        
        resp = self.client.get_rest_pages(path, filters)

        return resp

    def all(self):
        return self.filter()
        

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

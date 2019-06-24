from typing import Any, List, Dict, Optional, Union

import requests

from .models import Organization, Project
from .errors import SnykError, SnykOrganizationNotFound, SnykProjectNotFound


class SnykClient(object):
    API_URL = "https://snyk.io/api/v1"

    def __init__(self, token: str, url: Optional[str] = None):
        self.api_token = token
        self.api_url = url or self.API_URL
        self.api_headers = {"Authorization": "token %s" % self.api_token}
        self.api_post_headers = self.api_headers
        self.api_post_headers["Content-Type"] = "application/json"

    def post(self, path: str, body: Any) -> requests.Response:
        url = "%s/%s" % (self.api_url, path)
        resp = requests.post(url, json=body, headers=self.api_post_headers)
        if not resp:
            raise SnykError(resp)
        return resp

    def put(self, path: str, body: Any) -> requests.Response:
        url = "%s/%s" % (self.api_url, path)
        resp = requests.put(url, json=body, headers=self.api_post_headers)
        if not resp:
            raise SnykError(resp)
        return resp

    def get(self, path: str) -> requests.Response:
        url = "%s/%s" % (self.api_url, path)
        resp = requests.get(url, headers=self.api_headers)
        if not resp:
            raise SnykError(resp)
        return resp

    def delete(self, path: str) -> requests.Response:
        url = "%s/%s" % (self.api_url, path)
        resp = requests.delete(url, headers=self.api_headers)
        if not resp:
            raise SnykError(resp)
        return resp

    @property
    def organizations(self) -> List[Organization]:
        resp = self.get("orgs")
        orgs = []
        if "orgs" in resp.json():
            for org_data in resp.json()["orgs"]:
                orgs.append(Organization.from_dict(org_data))
        for org in orgs:
            org.client = self
        return orgs

    def organization(self, id) -> Organization:
        try:
            resp = self.get("orgs/%s" % id)
            if "orgs" in resp.json():
                for org_data in resp.json()["orgs"]:
                    org = Organization.from_dict(org_data)
                    org.client = self
                    return org
            raise SnykOrganizationNotFound
        except SnykError:
            raise SnykOrganizationNotFound

    @property
    def projects(self) -> List[Project]:
        projects = []
        for org in self.organizations:
            projects.extend(org.projects)
        return projects

    def project(self, id) -> Union[Project, None]:
        for org in self.organizations:
            try:
                return org.project(id)
            except SnykProjectNotFound:
                pass
        raise SnykProjectNotFound

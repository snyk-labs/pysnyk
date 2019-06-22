from typing import Any, List, Dict, Optional

import requests

from .models import Organization
from .errors import SnykError


class SnykClient(object):
    API_URL = "https://snyk.io/api/v1/"

    def __init__(self, token: str, url: Optional[str] = None):
        self.api_token = token
        self.api_url = url or self.API_URL
        self.api_headers = {"Authorization": "token %s" % self.api_token}
        self.api_post_headers = self.api_headers
        self.api_post_headers["Content-Type"] = "application/json"

    def _requests_do_post_api_return_http_response(
        self, path: str, obj_json_post_body: Any
***REMOVED*** -> requests.Response:
        api_url = "%s/%s" % (self.api_url, path)
        resp = requests.post(
            api_url, json=obj_json_post_body, headers=self.api_post_headers
    ***REMOVED***
        if resp.status_code != requests.codes.ok:
            raise SnykError(resp.json())
        return resp

    def _requests_do_put_api_return_http_response(
        self, path: str, obj_json_post_body: Any
***REMOVED*** -> requests.Response:
        api_url = "%s/%s" % (self.api_url, path)
        resp = requests.put(
            api_url, json=obj_json_post_body, headers=self.api_post_headers
    ***REMOVED***
        if resp.status_code != requests.codes.ok:
            raise SnykError(resp.json())
        return resp

    def _requests_do_get_return_http_response(self, path: str) -> requests.Response:
        api_url = "%s/%s" % (self.api_url, path)
        resp = requests.get(api_url, headers=self.api_headers)
        if resp.status_code != requests.codes.ok:
            raise SnykError(resp.json())
        return resp

    def _requests_do_delete_return_http_response(self, path: str) -> requests.Response:
        api_url = "%s/%s" % (self.api_url, path)
        resp = requests.delete(api_url, headers=self.api_headers)
        if resp.status_code != requests.codes.ok:
            raise SnykError(resp.json())
        return resp

    # https://snyk.docs.apiary.io/#reference/0/list-members-in-a-group/list-all-members-in-a-group
    def groups_members(self, group_id: str) -> Any:
        path = "org/%s/members" % group_id
        resp = self._requests_do_get_return_http_response(path)
        obj_json_response_content = resp.json()
        return obj_json_response_content

    def organizations(self) -> List[Organization]:
        resp = self._requests_do_get_return_http_response("orgs")
        orgs = []
        if "orgs" in resp.json():
            for org_data in resp.json()["orgs"]:
                orgs.append(Organization.from_dict(org_data))
        for org in orgs:
            org.client = self
        return orgs

    def integrations_import(
        self,
        org_id: str,
        integration_id: str,
        github_org: str,
        repo_name: str,
        manifest_files: List[str],
***REMOVED*** -> requests.Response:
        full_api_url = "%sorg/%s/integrations/%s/import" % (
            self.api_url,
            org_id,
            integration_id,
    ***REMOVED***

        post_body: Dict[str, Any] = {
            "target": {"owner": github_org, "name": repo_name, "branch": "master"}
        }

        if manifest_files is not None and len(manifest_files) > 0:
            files = []
            for f in manifest_files:
                f_obj = {"path": f}
                files.append(f_obj)

            post_body["files"] = files

        http_response = self._requests_do_post_api_return_http_response(
            full_api_url, post_body
    ***REMOVED***
        return http_response

import logging
import urllib.parse
from typing import Any, List, Optional

import requests
from retry.api import retry_call

from .__version__ import __version__
from .errors import SnykHTTPError, SnykNotImplementedError
from .managers import Manager
from .models import Organization, Project
from .utils import cleanup_path

logger = logging.getLogger(__name__)


class SnykClient(object):
    API_URL = "https://snyk.io/api/v1"
    USER_AGENT = "pysnyk/%s" % __version__

    def __init__(
        self,
        token: str,
        url: Optional[str] = None,
        user_agent: Optional[str] = USER_AGENT,
        debug: bool = False,
        tries: int = 1,
        delay: int = 1,
        backoff: int = 2,
        verify: bool = True,
        version: Optional[str] = None,
    ):
        self.api_token = token
        self.api_url = url or self.API_URL
        self.api_headers = {
            "Authorization": "token %s" % self.api_token,
            "User-Agent": user_agent,
        }
        self.api_post_headers = self.api_headers
        self.api_post_headers["Content-Type"] = "application/json"
        self.tries = tries
        self.backoff = backoff
        self.delay = delay
        self.verify = verify
        self.version = version

        # Ensure we don't have a trailing /
        if self.api_url[-1] == "/":
            self.api_url = self.api_url.rstrip("/")

        if debug:
            logging.basicConfig(level=logging.DEBUG)

    def request(
        self,
        method,
        url: str,
        headers: object,
        params: object = None,
        json: object = None,
    ) -> requests.Response:

        if params and json:
            resp = method(
                url, headers=headers, params=params, json=json, verify=self.verify
            )
        elif params and not json:
            resp = method(url, headers=headers, params=params, verify=self.verify)
        elif json and not params:
            resp = method(url, headers=headers, json=json, verify=self.verify)
        else:
            resp = method(url, headers=headers, verify=self.verify)

        if not resp or resp.status_code >= requests.codes.server_error:
            logger.warning(f"Retrying: {resp.text}")
            raise SnykHTTPError(resp)
        return resp

    def post(self, path: str, body: Any, headers: dict = {}) -> requests.Response:
        url = f"{self.api_url}/{path}"
        logger.debug(f"POST: {url}")

        resp = retry_call(
            self.request,
            fargs=[requests.post, url],
            fkwargs={"json": body, "headers": {**self.api_post_headers, **headers}},
            tries=self.tries,
            delay=self.delay,
            backoff=self.backoff,
            exceptions=SnykHTTPError,
            logger=logger,
        )

        if not resp.ok:
            logger.error(resp.text)
            raise SnykHTTPError(resp)

        return resp

    def put(self, path: str, body: Any, headers: dict = {}) -> requests.Response:
        url = "%s/%s" % (self.api_url, path)
        logger.debug("PUT: %s" % url)

        resp = retry_call(
            self.request,
            fargs=[requests.put, url],
            fkwargs={"json": body, "headers": {**self.api_post_headers, **headers}},
            tries=self.tries,
            delay=self.delay,
            backoff=self.backoff,
            logger=logger,
        )
        if not resp.ok:
            logger.error(resp.text)
            raise SnykHTTPError(resp)

        return resp

    def get(
        self, path: str, params: dict = None, version: str = None
    ) -> requests.Response:
        """
        Rest (formerly v3) Compatible Snyk Client, assumes the presence of Version, either set in the client
        or called in this method means that we're talking to a rest API endpoint and will ensure the
        params are encoded properly with the version.

        Since certain endpoints can exist only in certain versions, being able to override the
        client version with each GET is necessary

        Returns a standard requests Response object
        """

        path = cleanup_path(path)

        url = f"{self.api_url}/{path}"

        if params or self.version:

            if not params:
                params = {}

            # we use the presence of version to determine if we are REST or not
            if "version" not in params.keys() and self.version:
                params["version"] = version or self.version

            # Python Bools are True/False, JS Bools are true/false
            # Snyk REST API is strictly case sensitive at the moment

            for k, v in params.items():
                if isinstance(v, bool):
                    params[k] = str(v).lower()

            debug_url = f"{url}&{urllib.parse.urlencode(params)}"
            fkwargs = {"headers": self.api_headers, "params": params}
        else:
            debug_url = url
            fkwargs = {"headers": self.api_headers}

        logger.debug(f"GET: {debug_url}")

        resp = retry_call(
            self.request,
            fargs=[requests.get, url],
            fkwargs=fkwargs,
            tries=self.tries,
            delay=self.delay,
            backoff=self.backoff,
            logger=logger,
        )
        if not resp.ok:
            logger.error(resp.text)
            raise SnykHTTPError(resp)

        return resp

    def delete(self, path: str) -> requests.Response:
        url = f"{self.api_url}/{path}"
        logger.debug(f"DELETE: {url}")

        resp = retry_call(
            self.request,
            fargs=[requests.delete, url],
            fkwargs={"headers": self.api_headers},
            tries=self.tries,
            delay=self.delay,
            backoff=self.backoff,
            logger=logger,
        )
        if not resp.ok:
            logger.error(resp.text)
            raise SnykHTTPError(resp)

        return resp

    def get_rest_pages(self, path: str, params: dict = {}) -> List:
        """
        Helper function to collect paginated responses from the rest API into a single
        list.

        This collects the "data" list from the first reponse and then appends the
        any further "data" lists if a next link is found in the links field.
        """

        # this is a raw primative but a higher level module might want something that does an
        # arbitrary path + origin=foo + limit=100 url construction instead before being sent here

        limit = params["limit"]

        data = list()

        page = self.get(path, params).json()

        data.extend(page["data"])

        while "next" in page["links"].keys():
            logger.debug(
                f"GET_REST_PAGES: Another link exists: {page['links']['next']}"
            )

            next_url = urllib.parse.urlsplit(page["links"]["next"])
            query = urllib.parse.parse_qs(next_url.query)

            for k, v in query.items():
                params[k] = v

            params["limit"] = limit

            page = self.get(next_url.path, params).json()

            data.extend(page["data"])

            logger.debug(
                f"GET_REST_PAGES: Added another {len(page['data'])} items to the response"
            )

        return data

    # alias for backwards compatibility where V3 was the old name
    get_v3_pages = get_rest_pages

    @property
    def organizations(self) -> Manager:
        return Manager.factory(Organization, self)

    @property
    def projects(self) -> Manager:
        return Manager.factory(Project, self)

    # https://snyk.docs.apiary.io/#reference/general/the-api-details/get-notification-settings
    # https://snyk.docs.apiary.io/#reference/users/user-notification-settings/modify-notification-settings
    def notification_settings(self):
        raise SnykNotImplementedError  # pragma: no cover

    # https://snyk.docs.apiary.io/#reference/groups/organisations-in-groups/create-a-new-organisation-in-the-group
    # https://snyk.docs.apiary.io/#reference/0/list-members-in-a-group/list-all-members-in-a-group
    # https://snyk.docs.apiary.io/#reference/0/members-in-an-organisation-of-a-group/add-a-member-to-an-organisation-from-another-organisation-in-the-group
    def groups(self):
        raise SnykNotImplementedError  # pragma: no cover

    # https://snyk.docs.apiary.io/#reference/reporting-api/issues/get-list-of-issues
    def issues(self):
        raise SnykNotImplementedError  # pragma: no cover

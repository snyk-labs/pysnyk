import logging
from typing import Any, Optional

import requests
from retry.api import retry_call  # type: ignore

from .__version__ import __version__
from .errors import SnykHTTPError, SnykNotImplementedError
from .managers import Manager
from .models import Organization, Project

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

    def request(self, method, url: str, headers: object, json={},) -> requests.Response:
        resp = method(url, json=json, headers=headers,)
        if not resp or resp.status_code >= requests.codes.server_error:
            raise SnykHTTPError(resp)
        return resp

    def post(self, path: str, body: Any) -> requests.Response:
        url = "%s/%s" % (self.api_url, path)
        logger.debug("POST: %s" % url)
        resp = retry_call(
            self.request,
            fargs=[requests.post, url],
            fkwargs={"json": body, "headers": self.api_post_headers},
            tries=self.tries,
            delay=self.delay,
            backoff=self.backoff,
            logger=logger,
        )
        if not resp:
            raise SnykHTTPError(resp)
        return resp

    def put(self, path: str, body: Any) -> requests.Response:
        url = "%s/%s" % (self.api_url, path)
        logger.debug("PUT: %s" % url)
        resp = retry_call(
            self.request,
            fargs=[requests.put, url],
            fkwargs={"json": body, "headers": self.api_post_headers},
            tries=self.tries,
            delay=self.delay,
            backoff=self.backoff,
            logger=logger,
        )
        if not resp:
            raise SnykHTTPError(resp)
        return resp

    def get(self, path: str) -> requests.Response:
        url = "%s/%s" % (self.api_url, path)
        logger.debug("GET: %s" % url)
        resp = retry_call(
            self.request,
            fargs=[requests.get, url],
            fkwargs={"headers": self.api_headers},
            tries=self.tries,
            delay=self.delay,
            backoff=self.backoff,
            logger=logger,
        )
        if not resp:
            raise SnykHTTPError(resp)
        return resp

    def delete(self, path: str) -> requests.Response:
        url = "%s/%s" % (self.api_url, path)
        logger.debug("DELETE: %s" % url)
        resp = retry_call(
            self.request,
            fargs=[requests.delete, url],
            fkwargs={"headers": self.api_headers},
            tries=self.tries,
            delay=self.delay,
            backoff=self.backoff,
            logger=logger,
        )
        if not resp:
            raise SnykHTTPError(resp)
        return resp

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

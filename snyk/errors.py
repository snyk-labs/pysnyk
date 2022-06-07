import json

import requests


class SnykError(Exception):
    pass


class SnykHTTPError(SnykError):
    def __init__(self, resp: requests.Response):
        if hasattr(resp, "json"):
            try:
                data = resp.json()
                self.code = data.get("code")
                self.message = data.get("message")
                self.error = data.get("error") or data.get("errors")
            except json.decoder.JSONDecodeError:
                self.code = resp.status_code


class SnykNotFoundError(SnykError):
    pass


class SnykOrganizationNotFoundError(SnykError):
    pass


class SnykNotImplementedError(SnykError):
    pass

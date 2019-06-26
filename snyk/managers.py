from typing import List, Any

from .models import Organization
from .errors import SnykError, SnykNotFoundError


class Manager(object):
    def __init__(self, client):
        self.client = client

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


class OrganizationManager(Manager):
    def all(self) -> List[Organization]:
        resp = self.client.get("orgs")
        orgs = []
        if "orgs" in resp.json():
            for org_data in resp.json()["orgs"]:
                orgs.append(Organization.from_dict(org_data))
        for org in orgs:
            org.client = self.client
        return orgs

from dataclasses import dataclass, field
from typing import Optional

from mashumaro import DataClassJSONMixin  # type: ignore


@dataclass
class Organization(DataClassJSONMixin):
    name: str
    id: str
    group: Optional[str] = None


@dataclass
class Member(DataClassJSONMixin):
    id: str
    username: str
    name: str
    email: str
    role: str


@dataclass
class IssueCounts(DataClassJSONMixin):
    low: int
    high: int
    medium: int


@dataclass
class Project(DataClassJSONMixin):
    name: str
    organization: Organization
    id: str
    created: str
    origin: str
    type: str
    readOnly: bool
    testFrequency: str
    totalDependencies: int
    imageTag: str
    lastTestedDate: str
    issueCountsBySeverity: IssueCounts
    imageId: Optional[str] = None

    def delete(self, client):
        path = "org/%s/project/%s" % (self.organization.id, self.id)
        return client._requests_do_delete_return_http_response(path)

"""

Snyk API client
~~~~~~~~~~~~~~~

Snyk provides an API for various parts of the service, including accessing
project vulnerabilities, managing settings and testing individual packages
or package manifests.

    >>> import snyk
    >>> client = snyk.SnykClient("<your-snyk-api-token>")
    >>> org = client.organizations.first()
    # Return a list of Snyk Project objects
    >>> org.projects.all()
    ...
    # Return vulnerability information for dependencies from a Pipfile
    >>> handle = open("Pipfile")
    >>> org.test_pipfile(handle)
    ...
"""

from .__version__ import __description__, __license__, __title__, __url__, __version__
from .client import SnykClient

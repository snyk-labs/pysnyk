import poetry_version  # type: ignore
from importlib_metadata import version  # type: ignore

__title__ = "snyk"
__description__ = "An API client for the Snyk API."
__url__ = "https://snyk.docs.apiary.io"
__license__ = "MIT"
try:
    __version__ = version("pysnyk")
except:
    __version__ = poetry_version.extract(source_file=__file__)

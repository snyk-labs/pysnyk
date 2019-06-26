class SnykError(Exception):
    pass


class SnykNotFoundError(SnykError):
    pass


class SnykOrganizationNotFound(SnykError):
    pass


class SnykProjectNotFound(SnykError):
    pass


class SnykNotImplemented(SnykError):
    pass

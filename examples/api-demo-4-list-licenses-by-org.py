***REMOVED***

***REMOVED***
from utils import get_token, get_default_token_path


***REMOVED***
***REMOVED***
***REMOVED***
***REMOVED***
***REMOVED***
***REMOVED***


***REMOVED***
***REMOVED***
***REMOVED***
***REMOVED***

show_dependencies = True
show_projects = True


client = SnykClient(snyk_token)
licenses = client.organizations.get(org_id).licenses.all()
print("\n\nNumber of licenses: %s" % len(licenses))
for license in licenses:
    print("\nLicense: %s" % (license.id))

    if show_dependencies:
        print("  Dependencies:")
        for dep in license.dependencies:
            print("   - %s: %s" % (dep.packageManager, dep.id))

    if show_projects:
        print("  Projects:")
        for proj in license.projects:
            print("   - %s" % proj.name)

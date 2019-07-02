***REMOVED***

***REMOVED***
from utils import get_token


***REMOVED***
***REMOVED***
***REMOVED***
        "--orgId", type=str, help="The Snyk Organisation Id", required=True
***REMOVED***
***REMOVED***
        "--projectId", type=str, help="The project ID in Snyk", required=True
***REMOVED***
***REMOVED***


snyk_token = get_token("snyk-api-token")
***REMOVED***
***REMOVED***
project_id = args.projectId


client = SnykClient(snyk_token)
dependencies = (
    client.organizations.get(org_id).projects.get(project_id).dependencies.all()
)

for dep in dependencies:
    print("%s@%s" % (dep.name, dep.version))

    licenses = dep.licenses
    if len(licenses) > 0:
        print("  Licenses:")
        for l in licenses:
            print("   - %s | %s" % (l.license, l.id))

    deps_with_issues = dep.dependenciesWithIssues
    if len(deps_with_issues) > 0:
        print("  Deps with Issues:")
        for d in deps_with_issues:
            print("   - %s" % d)

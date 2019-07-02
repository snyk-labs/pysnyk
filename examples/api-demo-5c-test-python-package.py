***REMOVED***

***REMOVED***
from utils import get_token


***REMOVED***
***REMOVED***
***REMOVED***
        "--orgId", type=str, help="The Snyk Organisation Id", required=True
***REMOVED***
***REMOVED***
        "--packageName", type=str, help="The Python package name", required=True
***REMOVED***
***REMOVED***
        "--packageVersion", type=str, help="The Python package version", required=True
***REMOVED***
***REMOVED***


snyk_token = get_token("snyk-api-token")
***REMOVED***
***REMOVED***
package_name = args.packageName
package_version = args.packageVersion

print("Testing package %s@%s\n" % (package_name, package_version))

client = SnykClient(snyk_token)
result = client.organizations.get(org_id).test_python(package_name, package_version)

all_vulnerability_issues = result.issues.vulnerabilities
all_license_issues = result.issues.licenses

print("Security Vulnerabilities:")
for v in all_vulnerability_issues:
    print(v)
    print(v.id)
    print("  %s" % v.title)
    print("  %s" % v.url)
    print("  %s@%s" % (v.package, v.version))
    print("  identifiers: %s" % v.identifiers["CVE"])
    print("  severity: %s" % v.severity)
    print("  language: %s" % v.language)
    print("  packageManager: %s" % v.packageManager)
    print("  isUpgradable: %s" % v.isUpgradable)
    print("  isPatchable: %s" % v.isPatchable)

print("\nLicense Issues:")
for l in all_license_issues:
    print(l)

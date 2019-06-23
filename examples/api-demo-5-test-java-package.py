***REMOVED***

from pysnyk import SnykClient
from utils import get_token


***REMOVED***
***REMOVED***
***REMOVED***
        "--orgId", type=str, help="The Snyk Organisation Id", required=True
***REMOVED***

***REMOVED***"--groupId", type=str, help="The maven package name")

***REMOVED***"--artifactId", type=str, help="The maven package name")

***REMOVED***"--packageVersion", type=str, help="The maven package name")

***REMOVED***
        "full_package_descriptor",
        nargs="?",
        metavar="groupId:artifactId@version",
        type=str,
        help="Full package to test.",
***REMOVED***

    args_list = parser.parse_args()

    if args_list.full_package_descriptor:
        try:
            args_list.groupId = args_list.full_package_descriptor.split(":")[0]

            args_list.artifactId = args_list.full_package_descriptor.split(":")[1]
            if "@" in args_list.artifactId:
                args_list.artifactId = args_list.artifactId.split("@")[0]

            args_list.packageVersion = args_list.full_package_descriptor.split("@")[1]
        except:
            parser.error(
                "Invalid full package description. Should be <groupId>:<packageId>@<version>"
        ***REMOVED***

        if not args_list.packageVersion:
            parser.error(
                "Invalid full package description. Should be <groupId>:<packageId>@<version>"
        ***REMOVED***
    else:
        if args_list.groupId is None:
            parser.error("You must specify --groupId")

        if args_list.artifactId is None:
            parser.error("You must specify --artifactId")

        if args_list.packageVersion is None:
            parser.error("You must specify --packageVersion")

    return args_list


snyk_token = get_token("snyk-api-token")
***REMOVED***

***REMOVED***
package_group_id = args.groupId
package_artifact_id = args.artifactId
package_version = args.packageVersion

***REMOVED***
json_res = client.snyk_test_maven(
    package_group_id, package_artifact_id, package_version, org_id
)

all_vulnerability_issues = json_res["issues"]["vulnerabilities"]
all_license_issues = json_res["issues"]["licenses"]

print("Security Vulnerabilities:")
for v in all_vulnerability_issues:
    print(v["id"])
    print("  %s" % v["title"])
    print("  %s" % v["url"])
    print("  %s@%s" % (v["package"], v["version"]))
    print("  identifiers: %s" % v["identifiers"]["CVE"])
    print("  severity: %s" % v["severity"])
    print("  language: %s" % v["language"])
    print("  packageManager: %s" % v["packageManager"])
    print("  isUpgradable: %s" % v["isUpgradable"])
    print("  isPatchable: %s" % v["isPatchable"])
    print()

print("\nLicense Issues:")
for l in all_license_issues:
    print(l)

high_vulns_list = [v for v in all_vulnerability_issues if v["severity"] == "high"]
medium_vulns_list = [v for v in all_vulnerability_issues if v["severity"] == "medium"]
low_vulns_list = [v for v in all_vulnerability_issues if v["severity"] == "low"]

print("\nSummary:")
print("%s vulnerabilities found:" % len(all_vulnerability_issues))
print("  %s high severity" % len(high_vulns_list))
print("  %s medium severity" % len(medium_vulns_list))
print("  %s low severity" % len(low_vulns_list))

print("\n%s licenses found" % len(all_license_issues))

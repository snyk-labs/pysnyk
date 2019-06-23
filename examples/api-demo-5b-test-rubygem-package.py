import argparse

from pysnyk import SnykClient
from utils import get_token


def parse_command_line_args():
    parser = argparse.ArgumentParser(description="Snyk API Examples")
    parser.add_argument(
        "--orgId", type=str, help="The Snyk Organisation Id", required=True
    )

    parser.add_argument(
        "--packageName", type=str, help="The RubyGem package name", required=True
    )

    parser.add_argument(
        "--packageVersion", type=str, help="The RubyGem package version", required=True
    )

    args_list = parser.parse_args()
    return args_list


snyk_token = get_token("snyk-api-token")
args = parse_command_line_args()
org_id = args.orgId
package_name = args.packageName
package_version = args.packageVersion

print("Testing package %s@%s\n" % (package_name, package_version))

client = SnykClient(token=snyk_token)
json_res = client.snyk_test_rubygem(package_name, package_version, org_id)

all_vulnerability_issues = json_res["issues"]["vulnerabilities"]
all_license_issues = json_res["issues"]["licenses"]

print("Security Vulnerabilities:")
for v in all_vulnerability_issues:
    print(v)
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

print("\nLicense Issues:")
for l in all_license_issues:
    print(l)

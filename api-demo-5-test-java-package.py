import json
import argparse

import SnykAPI


def print_json(json_obj):
    print(json.dumps(json_obj, indent=4))


def parse_command_line_args():
    parser = argparse.ArgumentParser(description="Snyk API Examples")
    parser.add_argument('--orgId', type=str,
                        help='The Snyk Organisation Id')

    parser.add_argument('--groupId', type=str,
                        help='The maven package name')

    parser.add_argument('--artifactId', type=str,
                        help='The maven package name')

    parser.add_argument('--packageVersion', type=str,
                        help='The maven package name')

    args_list = parser.parse_args()

    if args_list.orgId is None:
        parser.error('You must specify --orgId')

    if args_list.groupId is None:
        parser.error('You must specify --groupId')

    if args_list.artifactId is None:
        parser.error('You must specify --artifactId')

    if args_list.packageVersion is None:
        parser.error('You must specify --packageVersion')

    return args_list


args = parse_command_line_args()

org_id = args.orgId
package_group_id = args.groupId
package_artifact_id = args.artifactId
package_version = args.packageVersion

json_res = SnykAPI.snyk_test_maven(package_group_id, package_artifact_id, package_version, org_id)

all_vulnerability_issues = json_res['issues']['vulnerabilities']
all_license_issues = json_res['issues']['licenses']

print('Security Vulnerabilities:')
for v in all_vulnerability_issues:
    print(v)
    print(v['id'])
    print('  %s' % v['title'])
    print('  %s' % v['url'])
    print('  %s@%s' % (v['package'], v['version']))
    print('  identifiers: %s' % v['identifiers']['CVE'])
    print('  severity: %s' % v['severity'])
    print('  language: %s' % v['language'])
    print('  packageManager: %s' % v['packageManager'])
    print('  isUpgradable: %s' % v['isUpgradable'])
    print('  isPatchable: %s' % v['isPatchable'])

high_vulns_list = [v for v in all_vulnerability_issues if v['severity'] == 'high']
medium_vulns_list = [v for v in all_vulnerability_issues if v['severity'] == 'medium']
low_vulns_list = [v for v in all_vulnerability_issues if v['severity'] == 'low']

print('\n%s vulnerabilities found:' % len(all_vulnerability_issues))
print('  %s high severity' % len(high_vulns_list))
print('  %s medium severity' % len(medium_vulns_list))
print('  %s low severity' % len(low_vulns_list))

print('\nLicense Issues:')
for l in all_license_issues:
    print(l)

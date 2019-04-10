import json
***REMOVED***

import SnykAPI


def print_json(json_obj):
    print(json.dumps(json_obj, indent=4))


***REMOVED***
***REMOVED***
***REMOVED***'--orgId', type=str,
                        help='The Snyk Organisation Id')

***REMOVED***'--packageName', type=str,
                        help='The npm package name')

***REMOVED***'--packageVersion', type=str,
                        help='The npm package version')

    args_list = parser.parse_args()

    if args_list.orgId is None:
        parser.error('You must specify --orgId')

    if args_list.packageName is None:
        parser.error('You must specify --packageName')

    if args_list.packageVersion is None:
        parser.error('You must specify --packageVersion')

    return args_list


***REMOVED***
***REMOVED***
package_name = args.packageName
package_version = args.packageVersion

print('Testing package %s@%s\n' % (package_name, package_version))

json_res = SnykAPI.snyk_test_npm_package(package_name, package_version, org_id)

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

print('\nLicense Issues:')
for l in all_license_issues:
    print(l)



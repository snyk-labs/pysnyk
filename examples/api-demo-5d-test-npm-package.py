***REMOVED***

from pysnyk import SnykClient
from utils import get_token


***REMOVED***
***REMOVED***
***REMOVED***'--orgId', type=str,
                        help='The Snyk Organisation Id', required=True)

***REMOVED***'--packageName', type=str,
                        help='The npm package name', required=True)

***REMOVED***'--packageVersion', type=str,
                        help='The npm package version', required=True)

    args_list = parser.parse_args()
    return args_list


snyk_token = get_token('snyk-api-token')
***REMOVED***
***REMOVED***
package_name = args.packageName
package_version = args.packageVersion

print('Testing package %s@%s\n' % (package_name, package_version))

***REMOVED***
json_res = client.snyk_test_npm_package(package_name, package_version, org_id)

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

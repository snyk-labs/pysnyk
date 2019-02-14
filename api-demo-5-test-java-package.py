import json

import SnykAPI


def print_json(json_obj):
    print(json.dumps(json_obj, indent=4))


org_id = 'demo-applications'  # TODO: put in your org_id

package_group_id = 'org.apache.flex.blazeds'
package_artifact_id = 'blazeds'
package_version = '4.7.2'

json_res = SnykAPI.snyk_test_maven(package_group_id, package_artifact_id, package_version, org_id)

all_vulnerability_issues = json_res['issues']['vulnerabilities']
all_license_issues = json_res['issues']['licenses']

for v in all_vulnerability_issues:
    print(v)
    print(v['id'])
    print('  %s' % v['title'])
    print('  %s' % v['url'])
    print('  %s@%s' % (v['package'], v['version']))
    print('  severity: %s' % v['severity'])
    print('  language: %s' % v['language'])
    print('  packageManager: %s' % v['packageManager'])

    print('  isUpgradable: %s' % v['isUpgradable'])
    print('  isPatchable: %s' % v['isPatchable'])

for l in all_license_issues:
    print(l)



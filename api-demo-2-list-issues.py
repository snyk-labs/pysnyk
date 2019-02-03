import json

import SnykAPI


def print_json(json_obj):
    print(json.dumps(json_obj, indent=4))


org_id = ''
my_js_goof_project_id = ''


# List issues in a project
json_res = SnykAPI.snyk_projects_project_issues(org_id, my_js_goof_project_id)
print(json_res)
for v in json_res['issues']['vulnerabilities']:
    print('\n %s' %v['title'])
    print('  %s@%s' % (v['package'], v['version']))
    print('  Severity: %s' % v['severity'])

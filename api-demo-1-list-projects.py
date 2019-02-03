import json


import SnykAPI


def print_json(json_obj):
    print(json.dumps(json_obj, indent=4))


org_id = ''
my_js_goof_project_id = ''


# List projects in org
json_res = SnykAPI.snyk_projects_projects(org_id)
for proj in json_res['projects']:
    print('\nProject Name: %s' % proj['name'])
    print('  Issues Found:')
    print('      High  : %s' % proj['issueCountsBySeverity']['high'])
    print('      Medium: %s' % proj['issueCountsBySeverity']['medium'])
    print('      Low   : %s' % proj['issueCountsBySeverity']['low'])


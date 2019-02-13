import json

import SnykAPI


def print_json(json_obj):
    print(json.dumps(json_obj, indent=4))


org_id = ''  # TODO: put in your org_id
project_id = ''  # TODO: put in your project_id


request_payload = {
    "projects": [
        project_id
    ]
}

show_dependencies = True
show_projects = True


# List issues in a project
json_res = SnykAPI.snyk_licenses_list_all_licenses_by_org(org_id)
print('\n\nNumber of licenses: %s' % json_res['total'])
print(json_res)
for v in json_res['results']:
    print('\n%s' % (v['id']))

    if show_dependencies:
        dependencies = v['dependencies']
        print('  Dependencies:')
        for d in dependencies:
            print('   - %s: %s' % (d['packageManager'], d['id']))

    if show_projects:
        projects = v['projects']
        print('  Projects:')
        for p in projects:
            print('   - %s' % p['name'])

    # print('  %s@%s' % (v['package'], v['version']))
    # print('  Severity: %s' % v['severity'])


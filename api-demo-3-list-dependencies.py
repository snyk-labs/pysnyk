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


# List issues in a project
json_res = SnykAPI.snyk_dependencies_list_all_dependencies_by_project(org_id, project_id)

print(json_res)
for v in json_res['results']:
    print('\n%s: %s@%s' % (v['type'], v['name'], v['version']))

    licenses = v['licenses']
    if len(licenses) > 0:
        print('  Licenses:')
        for l in licenses:
            print('   - %s | %s' % (l['license'], l['id']))

    deps_with_issues = v['dependenciesWithIssues']
    if len(deps_with_issues) > 0:
        print('  Deps with Issues:')
        for d in deps_with_issues:
            print('   - %s' % d)

    # print('  %s@%s' % (v['package'], v['version']))
    # print('  Severity: %s' % v['severity'])
